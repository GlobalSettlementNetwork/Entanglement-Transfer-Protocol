"""
LTP Protocol orchestrator — the three-phase transfer protocol.

Provides:
  - LTPProtocol — COMMIT / LATTICE / MATERIALIZE phases

Post-quantum security model (Option C + ML-KEM + ML-DSA):
  COMMIT:      encrypt shards with CEK → distribute ciphertext → ML-DSA sign record
  LATTICE:     seal minimal key (entity_id + CEK + ref) via ML-KEM to receiver
  MATERIALIZE: ML-KEM unseal → derive locations → fetch ciphertext → decrypt → decode
"""

from __future__ import annotations

import json
import struct
import time
from typing import Optional

from .commitment import CommitmentNetwork, CommitmentRecord
from .entity import Entity
from .erasure import ErasureCoder
from .keypair import KeyPair
from .lattice import LatticeKey
from .primitives import H, MLKEM, MLDSA
from .shards import ShardEncryptor

__all__ = ["LTPProtocol"]


class LTPProtocol:
    """
    Lattice Transfer Protocol — main protocol orchestrator.

    Post-quantum security model (Option C):
      COMMIT:      encrypt shards → distribute → ML-DSA-65 sign commitment record
      LATTICE:     seal minimal key via ML-KEM-768 to receiver
      MATERIALIZE: unseal → verify → fetch → decrypt → decode → verify EntityID
    """

    def __init__(self, network: CommitmentNetwork) -> None:
        self.network = network
        self.default_n = 8
        self.default_k = 4
        self._entity_sizes: dict[str, int] = {}
        self._sender_keypairs: dict[str, KeyPair] = {}

    # --- PHASE 1: COMMIT ---

    def commit(
        self,
        entity: Entity,
        sender_keypair: KeyPair,
        n: int = None,
        k: int = None,
    ) -> tuple[str, CommitmentRecord, bytes]:
        """
        PHASE 1: COMMIT

        1. Compute EntityID = H(content || shape || timestamp || sender_vk)
        2. Erasure encode → n plaintext shards
        3. Generate random CEK; encrypt each shard (AEAD)
        4. Distribute encrypted shards to commitment nodes
        5. Write minimal commitment record (Merkle root only, NO shard_ids)
        6. Sign record with sender's ML-DSA-65 key

        Returns: (entity_id, commitment_record, cek)
        """
        n = n or self.default_n
        k = k or self.default_k

        sender_id = sender_keypair.label
        self._sender_keypairs[sender_id] = sender_keypair

        timestamp = time.time()
        entity_id = entity.compute_id(sender_keypair.vk, timestamp)
        shape_hash = H(entity.shape.encode())
        self._entity_sizes[entity_id] = len(entity.content)

        print(f"  [COMMIT] Entity ID: {entity_id[:16]}...")
        print(f"  [COMMIT] Content size: {len(entity.content):,} bytes")

        plaintext_shards = ErasureCoder.encode(entity.content, n, k)
        print(f"  [COMMIT] Erasure encoded → {n} shards (k={k} for reconstruction)")
        print(f"  [COMMIT] Plaintext shard size: {len(plaintext_shards[0]):,} bytes each")

        # SECURITY: Each entity MUST have a unique CEK (see whitepaper §2.1.1).
        cek = ShardEncryptor.generate_cek()
        print(f"  [COMMIT] CEK generated: {cek.hex()[:16]}... (256-bit CSPRNG)")

        encrypted_shards = [
            ShardEncryptor.encrypt_shard(cek, entity_id, shard, i)
            for i, shard in enumerate(plaintext_shards)
        ]

        overhead = len(encrypted_shards[0]) - len(plaintext_shards[0])
        print(
            f"  [COMMIT] Shards encrypted (AEAD): {len(encrypted_shards[0]):,} bytes "
            f"each (+{overhead}B auth tag)"
        )

        shard_map_root = self.network.distribute_encrypted_shards(entity_id, encrypted_shards)
        print(f"  [COMMIT] Encrypted shards → {len(self.network.nodes)} commitment nodes")
        print(f"  [COMMIT]   Nodes store CIPHERTEXT ONLY (cannot read content)")

        content_hash = H(entity.content)
        record = CommitmentRecord(
            entity_id=entity_id,
            sender_id=sender_id,
            shard_map_root=shard_map_root,
            content_hash=content_hash,
            encoding_params={
                "n": n,
                "k": k,
                "algorithm": "reed-solomon-gf256",
                "gf_poly": "0x11d",
                "eval": "vandermonde-powers-of-0x02",
            },
            shape=entity.shape,
            shape_hash=shape_hash,
            timestamp=timestamp,
        )

        record.sign(sender_keypair.sk)
        sig_size = len(record.signature)

        commitment_ref = self.network.log.append(record)
        print(f"  [COMMIT] Record written to log (ref: {commitment_ref[:16]}...)")
        print(f"  [COMMIT]   Log contains: entity_id, Merkle root, encoding params")
        print(f"  [COMMIT]   Log does NOT contain: shard_ids, shard content, CEK")
        print(f"  [COMMIT]   ML-DSA-65 signature: {sig_size:,} bytes (quantum-resistant)")

        return entity_id, record, cek

    # --- PHASE 2: LATTICE ---

    def lattice(
        self,
        entity_id: str,
        record: CommitmentRecord,
        cek: bytes,
        receiver_keypair: KeyPair,
        access_policy: dict = None,
    ) -> bytes:
        """
        PHASE 2: LATTICE

        Create a minimal lattice key and seal it to the receiver via ML-KEM.

        Inner payload (~160 bytes):
          entity_id (64B hex) + CEK (64B hex) + commitment_ref (64B hex) + policy

        Sealed output (~1300 bytes):
          kem_ciphertext(1088) + nonce(16) + encrypted_payload + aead_tag(32)

        Forward secrecy: each seal() generates a fresh ML-KEM encapsulation.

        Returns: sealed lattice key (opaque bytes)
        """
        commitment_ref = H(json.dumps(record.to_dict(), sort_keys=True).encode())

        key = LatticeKey(
            entity_id=entity_id,
            cek=cek,
            commitment_ref=commitment_ref,
            access_policy=access_policy or {"type": "unrestricted"},
        )

        inner_size = key.plaintext_size
        sealed = key.seal(receiver_keypair.ek)
        entity_size = self._entity_sizes.get(entity_id, 0)

        print(f"  [LATTICE] Receiver: {receiver_keypair.label} ({receiver_keypair.pub_hex})")
        print(f"  [LATTICE] Inner payload: {inner_size} bytes")
        print(f"  [LATTICE]   Contains: entity_id + CEK + commitment_ref + policy")
        print(f"  [LATTICE]   REMOVED: shard_ids, encoding_params, sender_id")
        print(f"  [LATTICE] Sealed via ML-KEM-768: {len(sealed):,} bytes")
        print(f"  [LATTICE]   kem_ciphertext: {MLKEM.CT_SIZE} bytes (fresh encapsulation)")
        print(f"  [LATTICE]   nonce: 16 bytes | aead_tag: 32 bytes")
        print(f"  [LATTICE]   Forward secrecy: shared_secret zeroized after AEAD encrypt")
        if entity_size > 0:
            print(
                f"  [LATTICE] Entity: {entity_size:,}B → Key: {len(sealed):,}B "
                f"({entity_size / len(sealed):.1f}x ratio)"
            )

        return sealed

    # --- PHASE 3: MATERIALIZE ---

    def materialize(
        self, sealed_key: bytes, receiver_keypair: KeyPair
    ) -> Optional[bytes]:
        """
        PHASE 3: MATERIALIZE

        1. Unseal lattice key with receiver's private key
        2. Fetch commitment record from log
        3. Verify commitment reference (hash match vs sealed ref)
        4. Verify ML-DSA-65 signature on commitment record
        5. Read encoding params (n, k) from record
        6. Derive shard locations from entity_id (no shard_ids needed)
        7. Fetch k-of-n encrypted shards; decrypt with CEK
        8. Erasure decode → original entity content
        9. Verify full EntityID: H(content || shape || ts || sender_vk)

        Returns: entity content bytes, or None on failure.
        """
        label = receiver_keypair.label
        print(f"  [MATERIALIZE] Receiver '{label}' beginning materialization...")
        print(f"  [MATERIALIZE] Sealed key size: {len(sealed_key)} bytes")

        # Step 1: Unseal the lattice key
        try:
            key = LatticeKey.unseal(sealed_key, receiver_keypair)
        except ValueError as e:
            print(f"  [MATERIALIZE] ✗ UNSEAL FAILED: {e}")
            return None

        print(f"  [MATERIALIZE] ✓ Key unsealed with private key")
        print(f"  [MATERIALIZE]   Entity ID: {key.entity_id[:16]}...")
        print(f"  [MATERIALIZE]   CEK recovered: {key.cek.hex()[:16]}...")

        # Step 2: Fetch commitment record
        record = self.network.log.fetch(key.entity_id)
        if record is None:
            print(f"  [MATERIALIZE] ✗ Commitment not found for {key.entity_id[:16]}...")
            return None
        print(f"  [MATERIALIZE] ✓ Commitment record found in log")

        # Step 3: Verify commitment reference
        record_ref = H(json.dumps(record.to_dict(), sort_keys=True).encode())
        if record_ref != key.commitment_ref:
            print(f"  [MATERIALIZE] ✗ Commitment reference MISMATCH (tampered?)")
            return None
        print(f"  [MATERIALIZE] ✓ Commitment reference verified")

        # Step 4: Verify ML-DSA-65 signature
        sender_kp = self._sender_keypairs.get(record.sender_id)
        if sender_kp is None:
            print(f"  [MATERIALIZE] ✗ Sender '{record.sender_id}' not found in registry")
            return None
        if not record.verify_signature(sender_kp.vk):
            print(f"  [MATERIALIZE] ✗ ML-DSA signature INVALID — commitment record rejected")
            return None
        print(f"  [MATERIALIZE] ✓ ML-DSA-65 signature verified (sender '{record.sender_id}')")

        # Step 5: Read encoding params from record
        n = record.encoding_params["n"]
        k = record.encoding_params["k"]
        print(f"  [MATERIALIZE] Encoding: n={n}, k={k} (from commitment record)")

        # Step 6: Fetch all n shards (so AEAD can reject bad ones; erasure fills gaps)
        print(f"  [MATERIALIZE] Deriving shard locations from entity_id + index...")
        print(f"  [MATERIALIZE] Fetching up to {n} encrypted shards (need {k} valid)...")

        encrypted_shards = self.network.fetch_encrypted_shards(key.entity_id, n, n)

        if len(encrypted_shards) < k:
            print(f"  [MATERIALIZE] ✗ Only fetched {len(encrypted_shards)}/{k} shards")
            return None
        print(f"  [MATERIALIZE] ✓ Fetched {len(encrypted_shards)} encrypted shards")

        # Step 7: Decrypt each shard with CEK (AEAD rejects tampered shards)
        plaintext_shards: dict[int, bytes] = {}
        for i, enc_shard in encrypted_shards.items():
            try:
                plaintext_shards[i] = ShardEncryptor.decrypt_shard(
                    key.cek, key.entity_id, enc_shard, i
                )
            except ValueError as e:
                print(
                    f"  [MATERIALIZE] ⚠ Shard {i}: AEAD authentication FAILED — {e} (skipping)"
                )

        tampered_count = len(encrypted_shards) - len(plaintext_shards)
        if len(plaintext_shards) < k:
            print(
                f"  [MATERIALIZE] ✗ Only {len(plaintext_shards)}/{k} shards decrypted "
                f"({tampered_count} rejected by AEAD)"
            )
            return None
        print(f"  [MATERIALIZE] ✓ {len(plaintext_shards)} shards decrypted with CEK")
        if tampered_count > 0:
            print(
                f"  [MATERIALIZE]   ⚠ {tampered_count} shard(s) REJECTED by AEAD tag verification"
            )
        else:
            print(f"  [MATERIALIZE]   AEAD tags verified — no shard tampering detected")

        # Step 8: Erasure decode
        entity_content = ErasureCoder.decode(plaintext_shards, n, k)
        print(f"  [MATERIALIZE] ✓ Entity reconstructed ({len(entity_content):,} bytes)")

        # Step 9: Verify full EntityID (end-to-end content integrity, whitepaper §2.3.1)
        # Defends against commitment record substitution attacks.
        expected_entity_id = H(
            entity_content
            + record.shape.encode()
            + struct.pack('>d', record.timestamp)
            + sender_kp.vk
        )
        if expected_entity_id != key.entity_id:
            print(f"  [MATERIALIZE] ✗ EntityID MISMATCH — reconstructed content differs!")
            print(f"  [MATERIALIZE]   Expected: {key.entity_id[:16]}...")
            print(f"  [MATERIALIZE]   Got:      {expected_entity_id[:16]}...")
            print(f"  [MATERIALIZE]   Entity is REJECTED (immutability violation attempt)")
            return None
        print(
            f"  [MATERIALIZE] ✓ EntityID verified: "
            f"H(content‖shape‖ts‖vk) = {expected_entity_id[:16]}..."
        )
        print(f"  [MATERIALIZE] ✓ MATERIALIZATION COMPLETE")

        return entity_content
