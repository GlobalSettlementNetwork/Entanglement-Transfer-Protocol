"""
Cryptographic primitives for the Lattice Transfer Protocol.

PoC implementations of:
  - AEAD      — authenticated encryption (keystream + HMAC tag)
  - MLKEM     — ML-KEM key encapsulation (FIPS 203 simulation)
  - MLDSA     — ML-DSA digital signatures (FIPS 204 simulation)

Dual-lane hashing (canonical_hash, internal_hash, etc.) is provided by
the ``dual_lane`` subpackage and re-exported here for backward compatibility.

Production replacement:
  AEAD  → XChaCha20-Poly1305 (libsodium/NaCl)
  MLKEM → liboqs ML-KEM-768/1024 or FIPS 203 implementation
  MLDSA → liboqs ML-DSA-65/87 or FIPS 204 implementation
"""

from __future__ import annotations

import collections
import hmac as hmac_mod
import os
import struct
import warnings

# ---------------------------------------------------------------------------
# Re-export dual-lane architecture (backward compatibility)
# ---------------------------------------------------------------------------

from .dual_lane import (
    HashFunction,
    CryptoLane,
    SecurityProfile,
    COMPLIANCE_APPROVED as _COMPLIANCE_APPROVED,
    _blake3_available,
    _hash_digest,
    canonical_hash,
    canonical_hash_bytes,
    internal_hash,
    internal_hash_bytes,
    H,
    H_bytes,
    set_compliance_strict,
    get_compliance_strict,
)
from .dual_lane import hashing as _dl_hashing


# ---------------------------------------------------------------------------
# Real backend detection
# ---------------------------------------------------------------------------

# ML-KEM-768 (Level 3) fixed sizes — real backend only supports this parameter set.
# Level 5 (ML-KEM-1024) falls back to PoC until a 1024 backend is added.
_REAL_KEM_EK = 1184
_REAL_KEM_DK = 2400
_REAL_KEM_CT = 1088

_pqcrypto_kem_available = False
try:
    from pqcrypto.kem.ml_kem_768 import (
        generate_keypair as _kem_keygen,
        encrypt as _kem_encrypt,       # returns (ct, ss) — note order!
        decrypt as _kem_decrypt,
    )
    _pqcrypto_kem_available = True
except ImportError:
    pass

# ML-DSA-65 (Level 3) fixed sizes — same constraint as KEM.
_REAL_DSA_VK = 1952
_REAL_DSA_SK = 4032
_REAL_DSA_SIG = 3309

_pqcrypto_sign_available = False
try:
    from pqcrypto.sign.ml_dsa_65 import (
        generate_keypair as _dsa_keygen,
        sign as _dsa_sign,
        verify as _dsa_verify,          # raises on invalid, doesn't return bool
    )
    _pqcrypto_sign_available = True
except ImportError:
    pass

_pynacl_available = False
try:
    from nacl.bindings import (
        crypto_aead_xchacha20poly1305_ietf_encrypt as _nacl_encrypt,
        crypto_aead_xchacha20poly1305_ietf_decrypt as _nacl_decrypt,
    )
    _pynacl_available = True
except ImportError:
    pass


__all__ = [
    "SecurityProfile", "HashFunction", "CryptoLane",
    "canonical_hash", "canonical_hash_bytes",
    "internal_hash", "internal_hash_bytes",
    "H", "H_bytes", "AEAD", "MLKEM", "MLDSA",
    "get_security_profile", "set_security_profile",
    "set_crypto_provider", "get_crypto_provider",
    "set_compliance_strict", "get_compliance_strict",
    "_pqcrypto_kem_available", "_pqcrypto_sign_available", "_pynacl_available",
]


# ---------------------------------------------------------------------------
# Configurable crypto provider (FIPS 140-3 compliance)
# ---------------------------------------------------------------------------

# Global crypto provider override. When set to a FIPSCryptoProvider in FIPS
# mode, H() and H_bytes() delegate to SHA3-256, and AEAD delegates to
# AES-256-GCM. Default (None) uses the dual-lane primitives.
_crypto_provider = None


def set_crypto_provider(provider) -> None:
    """Set the global crypto provider (e.g., FIPSCryptoProvider for FIPS mode)."""
    global _crypto_provider
    _crypto_provider = provider


def get_crypto_provider():
    """Get the current crypto provider (None = default PoC primitives)."""
    return _crypto_provider


# Maximum entries in PoC simulation lookup tables before LRU eviction.
# Prevents unbounded memory growth in long-running processes.
_POC_TABLE_MAX = 10_000

if not (_pqcrypto_kem_available and _pqcrypto_sign_available):
    warnings.warn(
        "LTP is using PoC cryptographic simulations. "
        "Install pqcrypto for real ML-KEM-768/ML-DSA-65.",
        stacklevel=1,
    )


# ---------------------------------------------------------------------------
# SecurityProfile state management
# ---------------------------------------------------------------------------

# Module-level active profile (default: Level 3 / SHA3-256 + BLAKE3)
_active_profile: SecurityProfile = SecurityProfile.level3()


def get_security_profile() -> SecurityProfile:
    """Get the active security profile."""
    return _active_profile


def set_security_profile(profile: SecurityProfile) -> SecurityProfile:
    """
    Set the active security profile. Returns the previous profile.

    WARNING: Changing the profile mid-session will cause key size mismatches
    with existing keys. Only call this at initialization time.
    """
    global _active_profile
    previous = _active_profile
    _active_profile = profile
    # Update MLKEM/MLDSA class-level sizes to match
    MLKEM._sync_profile(profile)
    MLDSA._sync_profile(profile)
    return previous


# ---------------------------------------------------------------------------
# Patch dual_lane.hashing hooks to access state owned by this module
# ---------------------------------------------------------------------------

_dl_hashing._get_active_profile = get_security_profile
_dl_hashing._get_crypto_provider = get_crypto_provider


# ---------------------------------------------------------------------------
# AEAD: Authenticated Encryption with Associated Data
#
# PoC implementation using hash-derived keystream + XOR + HMAC tag.
# Uses the INTERNAL lane (not compliance-facing).
# Production: XChaCha20-Poly1305 via libsodium/NaCl.
# ---------------------------------------------------------------------------

class AEAD:
    """
    Authenticated encryption for shard-level and envelope-level encryption.

    Transport security for the materialization path (shard encryption, sealed
    lattice keys). NOT a canonical trust anchor — the canonical trust roots are
    commitment records, ML-DSA signatures, append-only log, and approval receipts.

    When pynacl is available, uses XChaCha20-Poly1305 (24-byte nonce, 16-byte tag).
    Otherwise falls back to PoC hash-derived keystream + HMAC tag.
    """

    NONCE_SIZE = 24 if _pynacl_available else 16
    TAG_SIZE = 16 if _pynacl_available else 32

    @classmethod
    def _tag_size(cls) -> int:
        """Actual tag size based on active backend."""
        if _pynacl_available:
            return 16  # Poly1305 tag
        return len(internal_hash_bytes(b"tag-size-probe"))

    @staticmethod
    def _keystream(key: bytes, nonce: bytes, length: int) -> bytes:
        """Generate deterministic keystream using internal lane hash (PoC only)."""
        stream = bytearray()
        counter = 0
        while len(stream) < length:
            block = key + nonce + struct.pack('>Q', counter)
            stream.extend(internal_hash_bytes(block))
            counter += 1
        return bytes(stream[:length])

    @staticmethod
    def _compute_tag(key: bytes, ciphertext: bytes, nonce: bytes, aad: bytes = b"") -> bytes:
        """Compute authentication tag using internal lane hash (PoC only)."""
        tag_key = internal_hash_bytes(key + b"aead-auth-tag-key")
        aad_len = struct.pack('>Q', len(aad))
        return internal_hash_bytes(tag_key + nonce + aad_len + aad + ciphertext)

    @classmethod
    def encrypt(cls, key: bytes, plaintext: bytes, nonce: bytes, aad: bytes = b"") -> bytes:
        """
        Encrypt plaintext → ciphertext || auth tag.

        Args:
            key: 32-byte symmetric key
            plaintext: data to encrypt
            nonce: NONCE_SIZE bytes, unique per (key, message) pair
            aad: associated data authenticated but not encrypted
        """
        if len(nonce) != cls.NONCE_SIZE:
            raise ValueError(f"Nonce must be {cls.NONCE_SIZE}B, got {len(nonce)}")

        if _pynacl_available:
            ct = _nacl_encrypt(plaintext, aad or None, nonce, key)
            if len(ct) != len(plaintext) + cls.TAG_SIZE:
                raise RuntimeError(
                    f"AEAD output size mismatch: {len(ct)} != {len(plaintext) + cls.TAG_SIZE}"
                )
            return ct

        # PoC fallback: hash-derived keystream + HMAC tag
        keystream = cls._keystream(key, nonce, len(plaintext))
        ciphertext = bytes(a ^ b for a, b in zip(plaintext, keystream))
        tag = cls._compute_tag(key, ciphertext, nonce, aad)
        return ciphertext + tag

    @classmethod
    def decrypt(cls, key: bytes, ciphertext_with_tag: bytes, nonce: bytes, aad: bytes = b"") -> bytes:
        """
        Verify tag, then decrypt → plaintext. Raises ValueError if tampered.

        IMPORTANT: Tag is verified BEFORE decryption (authenticate-then-decrypt).
        """
        if len(nonce) != cls.NONCE_SIZE:
            raise ValueError(f"Nonce must be {cls.NONCE_SIZE}B, got {len(nonce)}")

        if _pynacl_available:
            try:
                return _nacl_decrypt(ciphertext_with_tag, aad or None, nonce, key)
            except Exception:
                raise ValueError("AEAD authentication FAILED — data has been tampered with")

        # PoC fallback
        tag_size = cls._tag_size()
        if len(ciphertext_with_tag) < tag_size:
            raise ValueError("Ciphertext too short (missing authentication tag)")

        ciphertext = ciphertext_with_tag[:-tag_size]
        tag = ciphertext_with_tag[-tag_size:]

        expected_tag = cls._compute_tag(key, ciphertext, nonce, aad)
        if not hmac_mod.compare_digest(tag, expected_tag):
            raise ValueError("AEAD authentication FAILED — data has been tampered with")

        keystream = cls._keystream(key, nonce, len(ciphertext))
        return bytes(a ^ b for a, b in zip(ciphertext, keystream))


# ---------------------------------------------------------------------------
# ML-KEM (FIPS 203 / Kyber): Key Encapsulation Mechanism
#
# PoC SIMULATION: Uses canonical lane hash to simulate ML-KEM with
# correct key sizes per active SecurityProfile:
#   Level 3 (ML-KEM-768):  ek=1184, dk=2400, ct=1088, ss=32
#   Level 5 (ML-KEM-1024): ek=1568, dk=3168, ct=1568, ss=32
#
# Production: Replace with liboqs ML-KEM or FIPS 203 implementation.
# The PoC enforces size constraints and API semantics; the math is simulated.
# ---------------------------------------------------------------------------

class MLKEM:
    """
    ML-KEM Key Encapsulation Mechanism — PoC simulation.

    Uses the canonical hash lane (FIPS 203 simulation).

    Supports both ML-KEM-768 (Level 3) and ML-KEM-1024 (Level 5) via
    SecurityProfile. Key sizes are set by the active profile.

    Provides:
      - KeyGen() → (encapsulation_key, decapsulation_key)
      - Encaps(ek) → (shared_secret, ciphertext)
      - Decaps(dk, ciphertext) → shared_secret

    Security level: Determined by active SecurityProfile.
    """

    # Default Level 3 sizes (updated by _sync_profile)
    EK_SIZE = 1184   # Encapsulation key size (bytes)
    DK_SIZE = 2400   # Decapsulation key size (bytes)
    CT_SIZE = 1088   # Ciphertext size (bytes)
    SS_SIZE = 32     # Shared secret size (bytes)

    # PoC: maps dk_fingerprint → ek (populated by keygen, LRU-bounded)
    _PoC_dk_to_ek: collections.OrderedDict[str, bytes] = collections.OrderedDict()
    # PoC: maps (ek_fingerprint, ct_hash) → shared_secret (populated by encaps, LRU-bounded)
    _PoC_encaps_table: collections.OrderedDict[tuple[str, str], bytes] = collections.OrderedDict()

    @classmethod
    def _sync_profile(cls, profile: SecurityProfile) -> None:
        """Sync class-level sizes with the active security profile."""
        cls.EK_SIZE = profile.kem_ek_size
        cls.DK_SIZE = profile.kem_dk_size
        cls.CT_SIZE = profile.kem_ct_size
        cls.SS_SIZE = profile.kem_ss_size

    @classmethod
    def _use_real_backend(cls) -> bool:
        """Check if real pqcrypto backend matches the current profile's sizes."""
        return (_pqcrypto_kem_available
                and cls.EK_SIZE == _REAL_KEM_EK
                and cls.DK_SIZE == _REAL_KEM_DK)

    @classmethod
    def keygen(cls) -> tuple[bytes, bytes]:
        """
        Generate an ML-KEM keypair (768 or 1024 depending on profile).

        Returns: (encapsulation_key, decapsulation_key)
        The ek is public; dk MUST remain secret.
        """
        if cls._use_real_backend():
            ek, dk = _kem_keygen()
            if len(ek) != cls.EK_SIZE:
                raise RuntimeError(f"ML-KEM ek size mismatch: {len(ek)} != {cls.EK_SIZE}")
            if len(dk) != cls.DK_SIZE:
                raise RuntimeError(f"ML-KEM dk size mismatch: {len(dk)} != {cls.DK_SIZE}")
            return ek, dk

        # PoC fallback: hash-derived key simulation
        seed = os.urandom(64)
        hash_size = len(canonical_hash_bytes(b"size-probe"))

        dk_material = bytearray()
        for i in range(0, cls.DK_SIZE, hash_size):
            dk_material.extend(canonical_hash_bytes(seed + struct.pack('>I', i) + b"mlkem-dk"))
        dk = bytes(dk_material[:cls.DK_SIZE])

        ek_material = bytearray()
        for i in range(0, cls.EK_SIZE, hash_size):
            ek_material.extend(canonical_hash_bytes(seed + struct.pack('>I', i) + b"mlkem-ek"))
        ek = bytes(ek_material[:cls.EK_SIZE])

        # PoC: store dk→ek binding for decapsulation lookup (LRU-bounded)
        # Only populated when using PoC fallback — real backend doesn't need it.
        dk_fp = canonical_hash(dk[:32])
        cls._PoC_dk_to_ek[dk_fp] = ek
        if len(cls._PoC_dk_to_ek) > _POC_TABLE_MAX:
            cls._PoC_dk_to_ek.popitem(last=False)

        return ek, dk

    @classmethod
    def encaps(cls, ek: bytes) -> tuple[bytes, bytes]:
        """
        Encapsulate: generate a shared secret and ciphertext.

        Args:
            ek: Encapsulation key (public key of receiver)
        Returns:
            (shared_secret, ciphertext) — ss is 32 bytes, ct size per profile

        The ciphertext is sent to the receiver; only the holder of dk can
        recover the shared secret from it. Each call produces a FRESH
        (shared_secret, ciphertext) pair — this is the basis for forward secrecy.
        """
        if len(ek) != cls.EK_SIZE:
            raise ValueError(f"Invalid ek size: {len(ek)} (expected {cls.EK_SIZE})")

        if cls._use_real_backend():
            ct, ss = _kem_encrypt(ek)       # pqcrypto order: (ct, ss)
            if len(ct) != cls.CT_SIZE:
                raise RuntimeError(f"ML-KEM ct size mismatch: {len(ct)} != {cls.CT_SIZE}")
            if len(ss) != cls.SS_SIZE:
                raise RuntimeError(f"ML-KEM ss size mismatch: {len(ss)} != {cls.SS_SIZE}")
            return ss, ct                    # our order: (ss, ct)

        # PoC fallback: hash-derived encapsulation simulation
        ephemeral = os.urandom(32)
        ss_raw = canonical_hash_bytes(ek + ephemeral + b"mlkem-shared-secret")
        shared_secret = ss_raw[:32]  # Always 32-byte shared secret

        hash_size = len(ss_raw)
        ct_material = bytearray()
        for i in range(0, cls.CT_SIZE, hash_size):
            ct_material.extend(canonical_hash_bytes(ek + ephemeral + struct.pack('>I', i) + b"mlkem-ct"))
        ciphertext = bytes(ct_material[:cls.CT_SIZE])

        # PoC: store for decapsulation lookup (LRU-bounded)
        ek_fp = canonical_hash(ek)
        ct_hash = canonical_hash(ciphertext)
        cls._PoC_encaps_table[(ek_fp, ct_hash)] = shared_secret
        if len(cls._PoC_encaps_table) > _POC_TABLE_MAX:
            cls._PoC_encaps_table.popitem(last=False)

        return shared_secret, ciphertext

    @classmethod
    def decaps(cls, dk: bytes, ciphertext: bytes) -> bytes:
        """
        Decapsulate: recover shared secret from ciphertext using dk.

        Uses real ML-KEM lattice decryption when pqcrypto is available.
        Falls back to PoC lookup tables otherwise.
        """
        if len(dk) != cls.DK_SIZE:
            raise ValueError(f"Invalid dk size: {len(dk)} (expected {cls.DK_SIZE})")
        if len(ciphertext) != cls.CT_SIZE:
            raise ValueError(f"Invalid ct size: {len(ciphertext)} (expected {cls.CT_SIZE})")

        if cls._use_real_backend():
            ss = _kem_decrypt(dk, ciphertext)
            if len(ss) != cls.SS_SIZE:
                raise RuntimeError(f"ML-KEM ss size mismatch: {len(ss)} != {cls.SS_SIZE}")
            return ss

        # PoC: recover shared_secret via lookup tables (dk → ek → encaps table)
        # TIMING NOTE: Multiple dict.get() calls are NOT constant-time — they
        # leak information about whether keys/ciphertexts exist in the lookup
        # tables. This is an inherent limitation of the PoC hash-table simulation.
        # Production ML-KEM-768 (pqcrypto) uses constant-time lattice arithmetic
        # and the Fujisaki-Okamoto transform, which does not have this issue.
        # The PoC is for development/testing only and is never used when pqcrypto
        # is installed.
        dk_fp = canonical_hash(dk[:32])
        ek = cls._PoC_dk_to_ek.get(dk_fp)
        if ek is None:
            raise ValueError("Cannot decapsulate — unknown decapsulation key")
        ek_fp = canonical_hash(ek)
        ct_hash = canonical_hash(ciphertext)
        shared_secret = cls._PoC_encaps_table.get((ek_fp, ct_hash))
        if shared_secret is None:
            raise ValueError(
                "Cannot decapsulate — ciphertext not found "
                "(wrong key or corrupted ciphertext)"
            )
        return shared_secret

    @classmethod
    def reset_poc_state(cls) -> None:
        """Clear PoC simulation state. Call between tests for isolation."""
        cls._PoC_dk_to_ek.clear()
        cls._PoC_encaps_table.clear()


# ---------------------------------------------------------------------------
# ML-DSA (FIPS 204 / Dilithium): Digital Signatures
#
# PoC SIMULATION: Uses canonical lane hash to simulate ML-DSA with correct
# sizes per active SecurityProfile:
#   Level 3 (ML-DSA-65): vk=1952, sk=4032, sig=3309
#   Level 5 (ML-DSA-87): vk=2592, sk=4896, sig=4627
#
# Production: Replace with liboqs ML-DSA or FIPS 204 implementation.
# ---------------------------------------------------------------------------

class MLDSA:
    """
    ML-DSA Digital Signature Algorithm — PoC simulation.

    Uses the canonical hash lane (FIPS 204 simulation).

    Supports both ML-DSA-65 (Level 3) and ML-DSA-87 (Level 5) via
    SecurityProfile. Key/signature sizes are set by the active profile.

    Provides:
      - KeyGen() → (verification_key, signing_key)
      - Sign(sk, message) → signature
      - Verify(vk, message, signature) → bool

    Security level: Determined by active SecurityProfile.

    PoC simulation note:
      Signature verification uses a lookup table mapping
      (vk_fingerprint, message_hash) → expected_signature.
      keygen() stores the sk→vk binding; sign() stores the signature;
      verify() looks it up. Production replaces this with FIPS 204 math.
    """

    VK_SIZE = 1952   # Verification key (public) size
    SK_SIZE = 4032   # Signing key (private) size
    SIG_SIZE = 3309  # Signature size

    @classmethod
    def _sync_profile(cls, profile: SecurityProfile) -> None:
        """Sync class-level sizes with the active security profile."""
        cls.VK_SIZE = profile.dsa_vk_size
        cls.SK_SIZE = profile.dsa_sk_size
        cls.SIG_SIZE = profile.dsa_sig_size

    # PoC: maps sk_fingerprint → vk_fingerprint (populated by keygen, LRU-bounded)
    _PoC_sk_to_vk: collections.OrderedDict[str, str] = collections.OrderedDict()
    # PoC: maps (vk_fingerprint, message_hash) → signature (populated by sign, LRU-bounded)
    _PoC_sig_table: collections.OrderedDict[tuple[str, str], bytes] = collections.OrderedDict()

    @classmethod
    def _use_real_backend(cls) -> bool:
        """Check if real pqcrypto backend matches the current profile's sizes."""
        return (_pqcrypto_sign_available
                and cls.VK_SIZE == _REAL_DSA_VK
                and cls.SK_SIZE == _REAL_DSA_SK)

    @classmethod
    def keygen(cls) -> tuple[bytes, bytes]:
        """
        Generate an ML-DSA keypair (65 or 87 depending on profile).

        Returns: (verification_key, signing_key)
        """
        if cls._use_real_backend():
            vk, sk = _dsa_keygen()
            if len(vk) != cls.VK_SIZE:
                raise RuntimeError(f"ML-DSA vk size mismatch: {len(vk)} != {cls.VK_SIZE}")
            if len(sk) != cls.SK_SIZE:
                raise RuntimeError(f"ML-DSA sk size mismatch: {len(sk)} != {cls.SK_SIZE}")
            return vk, sk

        # PoC fallback: hash-derived key simulation
        seed = os.urandom(64)
        hash_size = len(canonical_hash_bytes(b"size-probe"))

        sk_material = bytearray()
        for i in range(0, cls.SK_SIZE, hash_size):
            sk_material.extend(canonical_hash_bytes(seed + struct.pack('>I', i) + b"mldsa-sk"))
        sk = bytes(sk_material[:cls.SK_SIZE])

        vk_material = bytearray()
        for i in range(0, cls.VK_SIZE, hash_size):
            vk_material.extend(canonical_hash_bytes(seed + struct.pack('>I', i) + b"mldsa-vk"))
        vk = bytes(vk_material[:cls.VK_SIZE])

        # PoC: store sk→vk binding for signature verification (LRU-bounded)
        sk_fp = canonical_hash(sk[:32])
        vk_fp = canonical_hash(vk)
        cls._PoC_sk_to_vk[sk_fp] = vk_fp
        if len(cls._PoC_sk_to_vk) > _POC_TABLE_MAX:
            cls._PoC_sk_to_vk.popitem(last=False)

        return vk, sk

    @classmethod
    def sign(cls, sk: bytes, message: bytes) -> bytes:
        """
        Sign a message with sk.

        Returns: signature (size depends on active profile)
        """
        if len(sk) != cls.SK_SIZE:
            raise ValueError(f"Invalid sk size: {len(sk)} (expected {cls.SK_SIZE})")

        if cls._use_real_backend():
            sig = _dsa_sign(sk, message)
            if len(sig) != cls.SIG_SIZE:
                raise RuntimeError(f"ML-DSA sig size mismatch: {len(sig)} != {cls.SIG_SIZE}")
            return sig

        # PoC fallback: hash-derived signature simulation
        raw_sig = canonical_hash_bytes(sk[:32] + message + b"mldsa-signature")
        hash_size = len(raw_sig)
        sig_material = bytearray()
        for i in range(0, cls.SIG_SIZE, hash_size):
            sig_material.extend(canonical_hash_bytes(raw_sig + struct.pack('>I', i) + b"mldsa-expand"))
        signature = bytes(sig_material[:cls.SIG_SIZE])

        # PoC: store for verification lookup (LRU-bounded)
        sk_fp = canonical_hash(sk[:32])
        vk_fp = cls._PoC_sk_to_vk.get(sk_fp)
        if vk_fp is not None:
            msg_hash = canonical_hash(message)
            cls._PoC_sig_table[(vk_fp, msg_hash)] = signature
            if len(cls._PoC_sig_table) > _POC_TABLE_MAX:
                cls._PoC_sig_table.popitem(last=False)

        return signature

    @classmethod
    def verify(cls, vk: bytes, message: bytes, signature: bytes) -> bool:
        """
        Verify a signature against vk and message.

        Returns: True if valid, False if forgery/tamper detected.
        """
        if len(vk) != cls.VK_SIZE:
            raise ValueError(f"Invalid vk size: {len(vk)} (expected {cls.VK_SIZE})")
        if len(signature) != cls.SIG_SIZE:
            return False

        if cls._use_real_backend():
            # pqcrypto.sign.ml_dsa_65.verify returns True/False.
            return bool(_dsa_verify(vk, message, signature))

        # PoC fallback: lookup table verification
        # TIMING NOTE: dict.get() is NOT constant-time — it leaks whether the
        # (vk, message) pair exists in the table via timing. This is an inherent
        # limitation of the PoC simulation. Production ML-DSA-65 (pqcrypto)
        # uses constant-time lattice arithmetic and does not have this issue.
        # When PoC is used (development/testing only), this timing leak is
        # acceptable because the PoC is not used for security-critical operations.
        vk_fp = canonical_hash(vk)
        msg_hash = canonical_hash(message)
        expected = cls._PoC_sig_table.get((vk_fp, msg_hash))
        if expected is None:
            # Perform a dummy comparison to reduce timing signal from early return.
            # This doesn't fully eliminate the leak (dict.get is still variable-time)
            # but narrows the observable timing difference.
            hmac_mod.compare_digest(b"\x00" * cls.SIG_SIZE, signature)
            return False
        return hmac_mod.compare_digest(expected, signature)

    @classmethod
    def reset_poc_state(cls) -> None:
        """Clear PoC simulation state. Call between tests for isolation."""
        cls._PoC_sk_to_vk.clear()
        cls._PoC_sig_table.clear()
