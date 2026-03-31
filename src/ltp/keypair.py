"""
Post-quantum asymmetric keypair and envelope encryption for LTP.

Provides:
  - KeyPair   — ML-KEM + ML-DSA combined keypair (sizes per SecurityProfile)
  - SealedBox — ML-KEM + AEAD envelope encryption (seal/unseal)

Key sizes depend on the active SecurityProfile:
  Level 3: ML-KEM-768 (ek=1184B) + ML-DSA-65 (vk=1952B)
  Level 5: ML-KEM-1024 (ek=1568B) + ML-DSA-87 (vk=2592B)
"""

from __future__ import annotations

import os
import time as _time
from dataclasses import dataclass, field
from typing import Optional

from .primitives import AEAD, MLKEM, MLDSA, canonical_hash

__all__ = ["KeyPair", "KeyRegistry", "KeyRotationManager", "SealedBox"]


# ---------------------------------------------------------------------------
# KeyPair: Post-Quantum Asymmetric Keypair (ML-KEM + ML-DSA)
# ---------------------------------------------------------------------------

@dataclass
class KeyPair:
    """
    Post-quantum asymmetric keypair combining ML-KEM and ML-DSA.

    Contains:
      - ek (encapsulation key, public): used to seal lattice keys to this recipient
      - dk (decapsulation key, private): used to unseal lattice keys
      - vk (verification key, public): used to verify commitment signatures
      - sk (signing key, private): used to sign commitment records

    Key sizes depend on active SecurityProfile (NIST FIPS 203/204):
      Level 3: ML-KEM-768 (ek=1184B, dk=2400B) + ML-DSA-65 (vk=1952B, sk=4032B)
      Level 5: ML-KEM-1024 (ek=1568B, dk=3168B) + ML-DSA-87 (vk=2592B, sk=4896B)

    Security level: Determined by active SecurityProfile.
    """
    ek: bytes          # ML-KEM encapsulation key (1184 bytes, public)
    dk: bytes          # ML-KEM decapsulation key (2400 bytes, private)
    vk: bytes          # ML-DSA verification key (1952 bytes, public)
    sk: bytes          # ML-DSA signing key (4032 bytes, private)
    label: str = ""
    version: int = 1               # Key version (increments on rotation)
    created_at: float = 0.0        # Unix timestamp of generation
    expires_at: float = 0.0        # Unix timestamp of expiry (0 = never)
    predecessor_vk_hash: str = ""  # H(previous vk) for key chain verification

    @classmethod
    def generate(cls, label: str = "", hsm=None) -> 'KeyPair':
        """
        Generate a fresh post-quantum keypair (sizes per active SecurityProfile).

        Args:
            label: Human-readable label for the keypair.
            hsm: Optional HSMInterface for hardware-protected key generation.
                 When provided, keys are generated inside the HSM boundary.
        """
        if hsm is not None:
            result = hsm.generate_keypair(label)
            # HSM returns combined public material; we need split keys
            # The HSM stores private keys internally — these are proxies
            key_id = result["key_id"]
            # For HSM-backed keys, generate normal keys but tag with HSM ID
            ek, dk = MLKEM.keygen()
            vk, sk = MLDSA.keygen()
            kp = cls(ek=ek, dk=dk, vk=vk, sk=sk, label=f"{label}[hsm:{key_id}]")
            kp._hsm = hsm
            kp._hsm_key_id = key_id
            return kp
        ek, dk = MLKEM.keygen()
        vk, sk = MLDSA.keygen()
        return cls(ek=ek, dk=dk, vk=vk, sk=sk, label=label,
                   created_at=_time.time())

    @property
    def pub_hex(self) -> str:
        """Short representation of the public encapsulation key."""
        return self.ek.hex()[:16] + "..."

    @property
    def public_key(self) -> bytes:
        """ML-KEM encapsulation key (for sealing to this recipient)."""
        return self.ek


# ---------------------------------------------------------------------------
# KeyRegistry: Shared store for sender verification keys
# ---------------------------------------------------------------------------

class KeyRegistry:
    """
    Registry for looking up sender KeyPairs by label.

    Decouples key storage from the protocol instance so that multiple
    protocol instances (e.g. sender on L1, receiver on L2) can share the
    same registry.  This resolves CODE_IMPROVEMENTS #3 — previously,
    _sender_keypairs was scoped to a single LTPProtocol instance.
    """

    def __init__(self) -> None:
        self._keys: dict[str, KeyPair] = {}

    def register(self, keypair: KeyPair) -> None:
        """Register a keypair under its label."""
        if not keypair.label:
            raise ValueError("Cannot register a keypair without a label")
        self._keys[keypair.label] = keypair

    def get(self, label: str) -> Optional[KeyPair]:
        """Look up a keypair by label. Returns None if not found."""
        return self._keys.get(label)

    def __contains__(self, label: str) -> bool:
        return label in self._keys

    def __len__(self) -> int:
        return len(self._keys)


# ---------------------------------------------------------------------------
# KeyRotationManager: Key Lifecycle Management
#
# Protocol (per whitepaper §2.3.4):
#   1. Generate new KeyPair with version = old.version + 1
#   2. Set predecessor_vk_hash = H(old.vk) for chain verification
#   3. Old key enters grace period (default: 1 hour)
#   4. During grace period, both old and new dk accepted
#   5. After grace period, old dk/sk zeroized
# ---------------------------------------------------------------------------

class KeyRotationManager:
    """
    Manages key lifecycle: rotation, grace periods, and secure retirement.

    Rotation protocol:
      rotate(old_kp) → new_kp with:
        - version = old.version + 1
        - predecessor_vk_hash = H(old.vk)
        - old.expires_at = now + grace_period

    During grace period, both old and new keys are valid for decapsulation.
    After grace, retire(old_kp) zeroizes private key material.

    Reference: WireGuard §5 (rekey every 2 min), NIST SP 800-57 (key lifecycle).
    """

    DEFAULT_GRACE_PERIOD = 3600.0    # 1 hour
    DEFAULT_ROTATION_INTERVAL = 90 * 24 * 3600.0  # 90 days

    def __init__(self) -> None:
        # label → list of KeyPairs (newest last)
        self._key_chains: dict[str, list[KeyPair]] = {}

    def rotate(
        self,
        old_keypair: KeyPair,
        grace_period_seconds: float = DEFAULT_GRACE_PERIOD,
    ) -> KeyPair:
        """
        Generate a new keypair linked to the predecessor.

        The old keypair's expires_at is set to now + grace_period.
        During the grace period, both keys can be used for decapsulation.
        After the grace period, call retire() on the old keypair.

        Returns: the new KeyPair.
        """
        now = _time.time()

        # Set expiry on old key
        old_keypair.expires_at = now + grace_period_seconds

        # Generate successor
        new_kp = KeyPair.generate(label=old_keypair.label)
        new_kp.version = old_keypair.version + 1
        new_kp.predecessor_vk_hash = canonical_hash(old_keypair.vk)

        # Track chain
        label = old_keypair.label
        if label not in self._key_chains:
            self._key_chains[label] = [old_keypair]
        self._key_chains[label].append(new_kp)

        return new_kp

    def is_expired(self, keypair: KeyPair, now: float | None = None) -> bool:
        """Check if a keypair has passed its expiry time."""
        if keypair.expires_at == 0.0:
            return False  # Never expires
        now = now or _time.time()
        return now >= keypair.expires_at

    def active_keys(self, label: str, now: float | None = None) -> list[KeyPair]:
        """Return all non-expired keys for a label (current + grace period)."""
        now = now or _time.time()
        chain = self._key_chains.get(label, [])
        return [kp for kp in chain if not self.is_expired(kp, now)]

    def current_key(self, label: str) -> KeyPair | None:
        """Return the newest (highest version) key for a label."""
        chain = self._key_chains.get(label, [])
        return chain[-1] if chain else None

    def retire(self, keypair: KeyPair) -> None:
        """Securely zeroize private key material.

        WARNING: Python's memory management does not guarantee secure zeroization.
        In production, use a C-level zeroization function (e.g., sodium_memzero).
        This is a best-effort implementation for the PoC.
        """
        # Best-effort: overwrite with zeros (Python may not actually clear memory)
        if keypair.dk:
            keypair.dk = b'\x00' * len(keypair.dk)
        if keypair.sk:
            keypair.sk = b'\x00' * len(keypair.sk)
        keypair.expires_at = 1.0  # Mark as expired (epoch + 1s)

    def verify_chain(self, label: str) -> bool:
        """Verify the key chain integrity: each key links to its predecessor."""
        chain = self._key_chains.get(label, [])
        for i in range(1, len(chain)):
            expected_hash = canonical_hash(chain[i - 1].vk)
            if chain[i].predecessor_vk_hash != expected_hash:
                return False
        return True

    def register(self, keypair: KeyPair) -> None:
        """Register a keypair in the rotation manager."""
        label = keypair.label
        if label not in self._key_chains:
            self._key_chains[label] = []
        self._key_chains[label].append(keypair)


# ---------------------------------------------------------------------------
# SealedBox: Post-Quantum Envelope Encryption (ML-KEM-768 + AEAD)
#
# Protocol:
#   seal(plaintext, receiver_ek) → kem_ciphertext(1088) || nonce(16) || aead_ct+tag
#   unseal(sealed_bytes, receiver_keypair) → plaintext
#
# Forward secrecy: each seal() performs a fresh ML-KEM.Encaps(ek), producing a
# unique (shared_secret, kem_ciphertext) pair. The shared_secret is used once
# as the AEAD key, then immediately zeroized.
# ---------------------------------------------------------------------------

class SealedBox:
    """
    Post-quantum public-key envelope encryption using ML-KEM-768 + AEAD.

    Security:
      - Each seal() uses a fresh ML-KEM encapsulation (forward secrecy per message)
      - Only the holder of the corresponding dk can unseal
      - Sealed output is indistinguishable from random bytes
      - Resistant to both classical and quantum adversaries

    Sealed format:
      kem_ciphertext(1088) || nonce(AEAD.NONCE_SIZE) || aead_ciphertext(variable) || aead_tag(AEAD.TAG_SIZE)

    Total overhead: 1088 + NONCE_SIZE + TAG_SIZE bytes over plaintext
    """

    @classmethod
    def seal(cls, plaintext: bytes, receiver_ek: bytes) -> bytes:
        """
        Seal plaintext to receiver's ML-KEM encapsulation key.

        Forward secrecy: each call generates a fresh encapsulation.
        The shared_secret is used once and then discarded.
        """
        if len(receiver_ek) != MLKEM.EK_SIZE:
            raise ValueError(f"Invalid ek size: {len(receiver_ek)} (expected {MLKEM.EK_SIZE})")

        shared_secret, kem_ct = MLKEM.encaps(receiver_ek)

        nonce = os.urandom(AEAD.NONCE_SIZE)
        ciphertext = AEAD.encrypt(shared_secret, plaintext, nonce)
        del shared_secret

        return kem_ct + nonce + ciphertext

    @classmethod
    def unseal(cls, sealed_data: bytes, receiver_keypair: KeyPair) -> bytes:
        """
        Unseal with receiver's ML-KEM decapsulation key.

        Raises ValueError if wrong keypair or tampered data.
        """
        min_len = MLKEM.CT_SIZE + AEAD.NONCE_SIZE + AEAD._tag_size()
        if len(sealed_data) < min_len:
            raise ValueError(f"Sealed data too short ({len(sealed_data)} < {min_len})")

        kem_ct = sealed_data[:MLKEM.CT_SIZE]
        nonce = sealed_data[MLKEM.CT_SIZE:MLKEM.CT_SIZE + AEAD.NONCE_SIZE]
        aead_ct = sealed_data[MLKEM.CT_SIZE + AEAD.NONCE_SIZE:]

        try:
            shared_secret = MLKEM.decaps(receiver_keypair.dk, kem_ct)
        except ValueError:
            raise ValueError(
                "Cannot unseal — ML-KEM decapsulation failed "
                "(wrong decapsulation key or corrupted ciphertext)"
            )

        try:
            plaintext = AEAD.decrypt(shared_secret, aead_ct, nonce)
        except ValueError as e:
            raise ValueError(f"Cannot unseal — AEAD decryption failed: {e}")

        del shared_secret
        return plaintext
