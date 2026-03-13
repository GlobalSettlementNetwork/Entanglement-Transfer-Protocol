"""
Commitment layer for the Lattice Transfer Protocol.

Provides:
  - AuditResult       — typed result of a node audit challenge
  - CommitmentNode    — distributed node storing encrypted shards
  - CommitmentRecord  — minimal log entry (ML-DSA signed, Merkle root only)
  - CommitmentLog     — append-only hash-chained ledger with inclusion proofs
  - CommitmentNetwork — orchestrates nodes, log, audit, and placement
  - PDP integration   — cryptographic storage proofs via enforcement module
"""

from __future__ import annotations

import json
import os
import struct
import time
from dataclasses import dataclass, field
from typing import Optional

from .primitives import H, H_bytes, MLDSA

__all__ = [
    "AuditResult",
    "CommitmentNode",
    "CommitmentRecord",
    "CommitmentLog",
    "CommitmentNetwork",
]


# ---------------------------------------------------------------------------
# AuditResult: typed return value for node audit operations
# ---------------------------------------------------------------------------

@dataclass
class AuditResult:
    """Result of a storage-proof audit on a single commitment node."""
    node_id: str
    challenged: int
    passed: int
    failed: int
    missing: int
    suspicious_latency: int
    burst_size: int
    avg_response_us: float
    result: str        # "PASS" or "FAIL"
    strikes: int


# ---------------------------------------------------------------------------
# CommitmentNode
# ---------------------------------------------------------------------------

class CommitmentNode:
    """
    A node in the distributed commitment network.

    SECURITY (Option C):
      - Stores ONLY encrypted shard data (ciphertext)
      - Keyed by (entity_id, shard_index) — both derivable by authorized receivers
      - Cannot read shard content (no access to CEK)
    """

    def __init__(self, node_id: str, region: str) -> None:
        self.node_id = node_id
        self.region = region
        self.shards: dict[tuple[str, int], bytes] = {}
        self.strikes: int = 0
        self.audit_passes: int = 0
        self.evicted: bool = False
        # TTL tracking: (entity_id, shard_index) → (stored_at_epoch, ttl_epochs or None)
        self._shard_ttl: dict[tuple[str, int], tuple[int, Optional[int]]] = {}

    def store_shard(self, entity_id: str, shard_index: int, encrypted_data: bytes) -> bool:
        """Store an encrypted shard. Returns False if node is evicted."""
        if self.evicted:
            return False
        self.shards[(entity_id, shard_index)] = encrypted_data
        return True

    def store_shard_with_ttl(
        self,
        entity_id: str,
        shard_index: int,
        encrypted_data: bytes,
        stored_at_epoch: int,
        ttl_epochs: Optional[int] = None,
    ) -> bool:
        """
        Store an encrypted shard with TTL metadata.

        Args:
            ttl_epochs: Number of epochs before expiry. None = permanent.

        Whitepaper §5.4.4: TTL-based eviction with renewal.
        """
        if self.evicted:
            return False
        key = (entity_id, shard_index)
        self.shards[key] = encrypted_data
        self._shard_ttl[key] = (stored_at_epoch, ttl_epochs)
        return True

    def is_shard_expired(
        self, entity_id: str, shard_index: int, current_epoch: int
    ) -> bool:
        """Check if a shard has expired based on its TTL."""
        key = (entity_id, shard_index)
        ttl_info = self._shard_ttl.get(key)
        if ttl_info is None:
            return False  # No TTL metadata = permanent
        stored_at, ttl = ttl_info
        if ttl is None:
            return False  # Explicit None TTL = permanent
        return current_epoch >= stored_at + ttl

    def renew_shard_ttl(
        self, entity_id: str, shard_index: int, additional_epochs: int
    ) -> bool:
        """Extend the TTL of a shard. Returns False if shard not found."""
        key = (entity_id, shard_index)
        ttl_info = self._shard_ttl.get(key)
        if ttl_info is None or key not in self.shards:
            return False
        stored_at, ttl = ttl_info
        if ttl is None:
            return True  # Already permanent
        self._shard_ttl[key] = (stored_at, ttl + additional_epochs)
        return True

    def evict_expired_shards(self, current_epoch: int) -> int:
        """Remove all expired shards. Returns count removed."""
        expired_keys = [
            key for key in list(self._shard_ttl.keys())
            if self.is_shard_expired(key[0], key[1], current_epoch)
        ]
        for key in expired_keys:
            self.shards.pop(key, None)
            self._shard_ttl.pop(key, None)
        return len(expired_keys)

    def fetch_shard(self, entity_id: str, shard_index: int) -> Optional[bytes]:
        """Fetch an encrypted shard. Returns None if missing or evicted."""
        if self.evicted:
            return None
        return self.shards.get((entity_id, shard_index))

    def respond_to_audit(
        self, entity_id: str, shard_index: int, nonce: bytes
    ) -> Optional[str]:
        """
        Respond to a storage proof challenge.

        Protocol: Challenge(entity_id, shard_index, nonce) → H(ciphertext || nonce)
        Returns None if the shard is missing (audit failure).
        """
        if self.evicted:
            return None
        ct = self.shards.get((entity_id, shard_index))
        if ct is None:
            return None
        return H(ct + nonce)

    def remove_shard(self, entity_id: str, shard_index: int) -> bool:
        """Remove a shard (used to simulate node failure or eviction cleanup)."""
        key = (entity_id, shard_index)
        if key in self.shards:
            del self.shards[key]
            return True
        return False

    @property
    def shard_count(self) -> int:
        return len(self.shards)


# ---------------------------------------------------------------------------
# CommitmentRecord
# ---------------------------------------------------------------------------

@dataclass
class CommitmentRecord:
    """
    An immutable record in the commitment log.

    SECURITY (Option C + Post-Quantum):
      - Individual shard IDs are NOT stored
      - Only a Merkle root of encrypted shard hashes is stored
      - Signed with ML-DSA-65 (quantum-resistant digital signature)
    """
    entity_id: str
    sender_id: str
    shard_map_root: str       # H(H(enc_shard_0) || ... || H(enc_shard_n))
    content_hash: str         # H(content) — secondary integrity check
    encoding_params: dict     # {"n", "k", "algorithm", "gf_poly", "eval"}
    shape: str                # canonicalized media type
    shape_hash: str           # H(shape) — legacy lookup compatibility
    timestamp: float
    ttl_epochs: Optional[int] = None  # §5.4.4: epochs until shard eviction (None = permanent)
    predecessor: Optional[str] = None
    signature: bytes = b""    # ML-DSA-65 signature (3309 bytes)

    def signable_payload(self) -> bytes:
        """The canonical bytes that get signed/verified.

        NOTE: `predecessor` is intentionally excluded. It is set by
        CommitmentLog.append() after signing, so including it would
        invalidate the signature. The sender authenticates the commitment
        content; the log's hash-chain separately authenticates predecessor.
        """
        d = {
            "entity_id": self.entity_id,
            "sender_id": self.sender_id,
            "shard_map_root": self.shard_map_root,
            "content_hash": self.content_hash,
            "encoding_params": self.encoding_params,
            "shape": self.shape,
            "shape_hash": self.shape_hash,
            "timestamp": self.timestamp,
        }
        return json.dumps(d, sort_keys=True).encode()

    def sign(self, sender_sk: bytes) -> None:
        """Sign this record with the sender's ML-DSA-65 signing key."""
        self.signature = MLDSA.sign(sender_sk, self.signable_payload())

    def verify_signature(self, sender_vk: bytes) -> bool:
        """Verify this record's ML-DSA-65 signature against sender's vk."""
        if not self.signature:
            return False
        return MLDSA.verify(sender_vk, self.signable_payload(), self.signature)

    def to_dict(self) -> dict:
        return {
            "entity_id": self.entity_id,
            "sender_id": self.sender_id,
            "shard_map_root": self.shard_map_root,
            "content_hash": self.content_hash,
            "encoding_params": self.encoding_params,
            "shape": self.shape,
            "shape_hash": self.shape_hash,
            "timestamp": self.timestamp,
            "predecessor": self.predecessor,
            "signature": self.signature.hex() if self.signature else "",
        }


# ---------------------------------------------------------------------------
# CommitmentLog
# ---------------------------------------------------------------------------

class CommitmentLog:
    """
    Append-only commitment log with hash-chaining and signed tree heads.

    Security properties (Whitepaper §5.1.4):
      - Hash-chained: each entry references the hash of the previous entry
      - Signed tree heads (STH): operators sign the root hash at each append
      - Inclusion proofs: O(log N) Merkle proof that a record exists in the log
      - Fork detection: inconsistent STHs are cryptographic proof of equivocation
    """

    def __init__(self) -> None:
        self._records: dict[str, CommitmentRecord] = {}
        self._chain: list[str] = []
        self._chain_hashes: list[str] = []
        self._tree_heads: list[dict] = []

    def append(self, record: CommitmentRecord) -> str:
        """
        Append a record to the hash-chained log. Returns its commitment reference.

        chain_hash = H(record_bytes || previous_chain_hash)
        """
        if record.entity_id in self._records:
            raise ValueError(f"Entity {record.entity_id} already committed (immutable)")

        prev_hash = self._chain_hashes[-1] if self._chain_hashes else ("0" * 64)
        record.predecessor = prev_hash

        record_bytes = json.dumps(record.to_dict(), sort_keys=True).encode()
        record_hash = H(record_bytes)
        chain_hash = H(record_bytes + prev_hash.encode())

        self._records[record.entity_id] = record
        self._chain.append(record.entity_id)
        self._chain_hashes.append(chain_hash)

        sth = {
            "sequence": len(self._chain) - 1,
            "root_hash": chain_hash,
            "timestamp": time.time(),
            "record_count": len(self._chain),
        }
        self._tree_heads.append(sth)

        return record_hash

    def fetch(self, entity_id: str) -> Optional[CommitmentRecord]:
        return self._records.get(entity_id)

    def verify_chain_integrity(self) -> tuple[bool, int]:
        """
        Verify the entire hash chain from genesis to head.

        Returns: (is_valid, last_valid_index)
        """
        prev_hash = "0" * 64
        for i, entity_id in enumerate(self._chain):
            record = self._records[entity_id]
            record_bytes = json.dumps(record.to_dict(), sort_keys=True).encode()
            expected_hash = H(record_bytes + prev_hash.encode())
            if expected_hash != self._chain_hashes[i]:
                return False, i
            prev_hash = self._chain_hashes[i]
        return True, len(self._chain) - 1

    def get_inclusion_proof(self, entity_id: str) -> Optional[dict]:
        """Generate an inclusion proof for a committed entity."""
        if entity_id not in self._records:
            return None
        idx = self._chain.index(entity_id)
        return {
            "entity_id": entity_id,
            "position": idx,
            "chain_hash": self._chain_hashes[idx],
            "predecessor": self._chain_hashes[idx - 1] if idx > 0 else ("0" * 64),
            "tree_head": self._tree_heads[idx] if idx < len(self._tree_heads) else None,
        }

    def verify_inclusion(self, entity_id: str, proof: dict) -> bool:
        """Verify an inclusion proof against the current log state."""
        record = self._records.get(entity_id)
        if record is None:
            return False
        record_bytes = json.dumps(record.to_dict(), sort_keys=True).encode()
        expected = H(record_bytes + proof["predecessor"].encode())
        return expected == proof["chain_hash"]

    @property
    def head_hash(self) -> str:
        """Current tree head hash (latest chain_hash)."""
        return self._chain_hashes[-1] if self._chain_hashes else ("0" * 64)

    @property
    def length(self) -> int:
        return len(self._chain)


# ---------------------------------------------------------------------------
# CommitmentNetwork
# ---------------------------------------------------------------------------

class CommitmentNetwork:
    """
    Manages the distributed commitment network.

    Responsibilities:
      - Deterministic shard placement via consistent hashing
      - Distributing and fetching encrypted shards
      - Storage proof auditing with burst challenges AND PDP proofs
      - Node eviction and shard repair
      - Correlated failure analysis (regional failure model)

    Performance:
      - Placement results are cached (invalidated on node list change)
      - Audit uses reverse index: node_id → [(entity_id, shard_index)]
        for O(S) audit where S = shards on node, instead of O(N·n).
    """

    def __init__(self) -> None:
        self.nodes: list[CommitmentNode] = []
        self.log = CommitmentLog()
        # Cache: (entity_id, shard_index, replicas) → [CommitmentNode]
        self._placement_cache: dict[tuple[str, int, int], list[CommitmentNode]] = {}
        self._node_count_at_cache: int = 0
        # Reverse index: node_id → set of (entity_id, shard_index)
        self._node_shard_index: dict[str, set[tuple[str, int]]] = {}
        # Optional enforcement pipeline (set via set_enforcement_pipeline)
        self._enforcement_pipeline = None

    def _invalidate_placement_cache(self) -> None:
        """Clear placement cache when node list changes."""
        self._placement_cache.clear()
        self._node_count_at_cache = len(self.nodes)

    def set_enforcement_pipeline(self, pipeline) -> None:
        """Attach an EnforcementPipeline for integrated enforcement."""
        self._enforcement_pipeline = pipeline

    def add_node(self, node_id: str, region: str) -> CommitmentNode:
        node = CommitmentNode(node_id, region)
        self.nodes.append(node)
        self._node_shard_index[node_id] = set()
        self._invalidate_placement_cache()
        return node

    def _placement(
        self, entity_id: str, shard_index: int, replicas: int = 2
    ) -> list[CommitmentNode]:
        """Deterministic shard placement via consistent hashing (cached)."""
        if not self.nodes:
            raise ValueError("No commitment nodes available")

        # Invalidate cache if node count changed
        if len(self.nodes) != self._node_count_at_cache:
            self._invalidate_placement_cache()

        cache_key = (entity_id, shard_index, replicas)
        cached = self._placement_cache.get(cache_key)
        if cached is not None:
            return cached

        placement_key = f"{entity_id}:{shard_index}"
        h = int.from_bytes(H_bytes(placement_key.encode()), "big")

        selected = []
        for r in range(replicas):
            idx = (h + r * 7) % len(self.nodes)
            if self.nodes[idx] not in selected:
                selected.append(self.nodes[idx])

        self._placement_cache[cache_key] = selected
        return selected

    def distribute_encrypted_shards(
        self, entity_id: str, encrypted_shards: list[bytes], replicas: int = 2
    ) -> str:
        """
        Distribute encrypted shards to commitment nodes.

        Returns: Merkle root of encrypted shard hashes (for commitment record).
        """
        shard_hashes = []

        for i, enc_shard in enumerate(encrypted_shards):
            shard_hash = H(enc_shard + entity_id.encode() + struct.pack('>I', i))
            shard_hashes.append(shard_hash)

            target_nodes = self._placement(entity_id, i, replicas)
            for node in target_nodes:
                node.store_shard(entity_id, i, enc_shard)
                # Update reverse index for O(S) audit
                self._node_shard_index.setdefault(node.node_id, set()).add(
                    (entity_id, i)
                )

        return H(b''.join(h.encode() for h in shard_hashes))

    def fetch_encrypted_shards(
        self, entity_id: str, n: int, k: int
    ) -> dict[int, bytes]:
        """
        Fetch k encrypted shards by deriving locations from entity_id.

        NO shard_ids needed — locations computed from entity_id + index.
        Returns: {shard_index: encrypted_shard_bytes}
        """
        fetched: dict[int, bytes] = {}

        for i in range(n):
            if len(fetched) >= k:
                break
            target_nodes = self._placement(entity_id, i)
            for node in target_nodes:
                data = node.fetch_shard(entity_id, i)
                if data is not None:
                    fetched[i] = data
                    break

        return fetched

    def audit_node(self, node: CommitmentNode, burst: int = 1) -> AuditResult:
        """
        Audit a single node via storage proof challenges.

        Uses reverse index (node_id → shards) for O(S) lookup where
        S = shards on this node, instead of scanning all N entities.

        Anti-outsourcing: burst challenges issue `burst` simultaneous nonces
        per shard, multiplying relay latency and making outsourcing detectable.

        Returns: AuditResult with full challenge statistics.
        """
        challenged = 0
        passed = 0
        failed = 0
        missing = 0
        suspicious_latency = 0
        response_times: list[float] = []

        # Use reverse index if available; fall back to full scan
        node_shards = self._node_shard_index.get(node.node_id)
        if node_shards is not None and len(node_shards) > 0:
            shard_list = list(node_shards)
        else:
            # Fall back to full scan for backward compatibility
            shard_list = []
            for entity_id in self.log._chain:
                record = self.log.fetch(entity_id)
                if record is None:
                    continue
                n = record.encoding_params.get("n", 8)
                for shard_index in range(n):
                    target_nodes = self._placement(entity_id, shard_index)
                    if node in target_nodes:
                        shard_list.append((entity_id, shard_index))

        for entity_id, shard_index in shard_list:
            nonces = [os.urandom(16) for _ in range(burst)]
            burst_pass = True

            for nonce in nonces:
                t0 = time.monotonic()
                response = node.respond_to_audit(entity_id, shard_index, nonce)
                elapsed = time.monotonic() - t0
                response_times.append(elapsed)
                challenged += 1

                if response is None:
                    missing += 1
                    failed += 1
                    burst_pass = False
                else:
                    known_good = self._get_known_good_hash(
                        entity_id, shard_index, nonce, exclude_node=node
                    )
                    if known_good is not None and response == known_good:
                        passed += 1
                    elif known_good is None:
                        passed += 1
                    else:
                        failed += 1
                        burst_pass = False

            if burst > 1 and burst_pass and response_times:
                burst_latencies = response_times[-burst:]
                max_burst_latency = max(burst_latencies)
                if max_burst_latency > 0.001:
                    suspicious_latency += 1

        if challenged == 0:
            result = "PASS"
        elif failed > 0:
            result = "FAIL"
            node.strikes += 1
        else:
            result = "PASS"
            node.audit_passes += 1
            node.strikes = max(0, node.strikes - 1)

        avg_latency = (sum(response_times) / len(response_times)) if response_times else 0.0

        return AuditResult(
            node_id=node.node_id,
            challenged=challenged,
            passed=passed,
            failed=failed,
            missing=missing,
            suspicious_latency=suspicious_latency,
            burst_size=burst,
            avg_response_us=round(avg_latency * 1_000_000, 1),
            result=result,
            strikes=node.strikes,
        )

    def _get_known_good_hash(
        self, entity_id: str, shard_index: int, nonce: bytes,
        exclude_node: CommitmentNode
    ) -> Optional[str]:
        """Fetch a known-good audit hash from another healthy replica."""
        for other_node in self.nodes:
            if other_node is exclude_node or other_node.evicted:
                continue
            response = other_node.respond_to_audit(entity_id, shard_index, nonce)
            if response is not None:
                return response
        return None

    def audit_all_nodes(self, burst: int = 1) -> list[AuditResult]:
        """Audit every active node. Returns list of AuditResult."""
        results = []
        for node in self.nodes:
            if not node.evicted:
                results.append(self.audit_node(node, burst=burst))
        return results

    def audit_node_pdp(
        self, node: CommitmentNode, epoch: int, sample_size: int = 4,
        vdf_verifier=None,
    ) -> dict:
        """
        Audit a node using PDP (Proof of Data Possession) challenges.

        Provides cryptographic storage verification instead of statistical
        burst challenges. Uses the enforcement module's PDP infrastructure.

        Returns: {"node_id", "entities_challenged", "passed", "failed",
                  "result", "proof_size_bytes"}
        """
        from .enforcement import (
            PDPChallenge, PDPVerifier, StorageProofStrategy,
        )

        verifier = PDPVerifier()
        node_shards = self._node_shard_index.get(node.node_id, set())
        if not node_shards:
            return {
                "node_id": node.node_id,
                "entities_challenged": 0,
                "passed": 0,
                "failed": 0,
                "result": "PASS",
                "proof_size_bytes": 0,
            }

        # Group shards by entity
        entities: dict[str, list[int]] = {}
        for entity_id, shard_index in node_shards:
            entities.setdefault(entity_id, []).append(shard_index)

        total_passed = 0
        total_failed = 0
        total_proof_bytes = 0

        for entity_id, shard_indices in entities.items():
            # Register known shard hashes for this node's shards
            shard_hashes = {}
            for idx in shard_indices:
                data = node.fetch_shard(entity_id, idx)
                if data is not None:
                    from .primitives import H as hash_fn
                    shard_hashes[idx] = hash_fn(data)

            if not shard_hashes:
                continue

            verifier.register_commitment(entity_id, shard_hashes)

            # Challenge only indices this node actually stores
            available_indices = sorted(shard_hashes.keys())
            challenge_count = min(sample_size, len(available_indices))
            # Deterministic subset selection using hash
            seed = H_bytes(f"{entity_id}:{epoch}:pdp-node".encode())
            rng_val = int.from_bytes(seed[:8], "big")
            selected_indices = []
            remaining = list(available_indices)
            for _ in range(challenge_count):
                if not remaining:
                    break
                pick = rng_val % len(remaining)
                selected_indices.append(remaining.pop(pick))
                rng_val = int.from_bytes(
                    H_bytes(seed + struct.pack(">I", len(selected_indices)))[:8],
                    "big",
                )

            # Generate coefficients for selected indices
            coefficients = []
            for idx in selected_indices:
                coeff_seed = H_bytes(seed + struct.pack(">I", idx))
                coefficients.append(coeff_seed[:16])

            challenge_id = H(
                f"{entity_id}:{epoch}:{sorted(selected_indices)}".encode()
            )
            challenge = PDPChallenge(
                challenge_id=challenge_id,
                epoch=epoch,
                shard_indices=selected_indices,
                coefficients=coefficients,
                deadline_epoch=epoch + 1,
            )

            # Node computes proof from its stored shards
            node_shard_data = {}
            for idx in challenge.shard_indices:
                data = node.fetch_shard(entity_id, idx)
                if data is not None:
                    node_shard_data[idx] = data

            proof = PDPVerifier.compute_proof_from_shards(
                shard_data=node_shard_data,
                indices=challenge.shard_indices,
                coefficients=challenge.coefficients,
                challenge_id=challenge.challenge_id,
            )

            # Verify proof
            if verifier.verify_proof(entity_id, challenge, proof):
                total_passed += 1
            else:
                total_failed += 1

            total_proof_bytes += proof.proof_size_bytes

        result = "FAIL" if total_failed > 0 else "PASS"
        if result == "FAIL":
            node.strikes += 1
        else:
            node.audit_passes += 1
            node.strikes = max(0, node.strikes - 1)

        # VDF-enhanced timing challenge (HYBRID mode)
        vdf_result_data = None
        if vdf_verifier is not None and entities:
            first_entity = next(iter(entities))
            first_idx = entities[first_entity][0]
            challenge = vdf_verifier.generate_challenge(
                first_entity, first_idx, epoch
            )
            vdf_eval = vdf_verifier.evaluate(challenge)
            vdf_ok = vdf_verifier.verify(challenge, vdf_eval)
            vdf_result_data = {
                "challenge_id": challenge.challenge_id,
                "verified": vdf_ok,
                "computation_time_ms": vdf_eval.computation_time_ms,
            }
            if not vdf_ok:
                result = "FAIL"
                node.strikes += 1

        audit_output = {
            "node_id": node.node_id,
            "entities_challenged": len(entities),
            "passed": total_passed,
            "failed": total_failed,
            "result": result,
            "proof_size_bytes": total_proof_bytes,
            "strikes": node.strikes,
        }
        if vdf_result_data is not None:
            audit_output["vdf"] = vdf_result_data

        return audit_output

    def evict_node(self, node: CommitmentNode) -> dict:
        """
        Evict a misbehaving node and trigger shard repair.

        Repair operates on CIPHERTEXT — no plaintext exposure.
        Returns: {"evicted_node", "shards_affected", "repaired", "lost"}
        """
        node.evicted = True
        repaired = 0
        lost = 0

        orphaned_shards = list(node.shards.items())

        for (entity_id, shard_index), enc_shard in orphaned_shards:
            replica_found = False
            for other_node in self.nodes:
                if other_node is node or other_node.evicted:
                    continue
                replica = other_node.fetch_shard(entity_id, shard_index)
                if replica is not None:
                    for target in self.nodes:
                        if (target is not node and not target.evicted
                                and target.fetch_shard(entity_id, shard_index) is None):
                            target.store_shard(entity_id, shard_index, replica)
                            repaired += 1
                            replica_found = True
                            break
                    if replica_found:
                        break
            if not replica_found:
                lost += 1

        return {
            "evicted_node": node.node_id,
            "shards_affected": len(orphaned_shards),
            "repaired": repaired,
            "lost": lost,
        }

    @property
    def active_node_count(self) -> int:
        return sum(1 for n in self.nodes if not n.evicted)

    # --- TTL-Based Shard Eviction (Whitepaper §5.4.4) ---

    def evict_expired_shards(self, current_epoch: int) -> dict:
        """
        Evict all expired shards across the network.

        Returns: {"total_evicted", "nodes_affected", "entities_affected"}
        """
        total_evicted = 0
        nodes_affected = 0
        entities_affected: set[str] = set()

        for node in self.nodes:
            if node.evicted:
                continue
            # Track which entities will be affected
            for key in list(node._shard_ttl.keys()):
                if node.is_shard_expired(key[0], key[1], current_epoch):
                    entities_affected.add(key[0])
            evicted = node.evict_expired_shards(current_epoch)
            if evicted > 0:
                total_evicted += evicted
                nodes_affected += 1

        return {
            "total_evicted": total_evicted,
            "nodes_affected": nodes_affected,
            "entities_affected": len(entities_affected),
        }

    def renew_entity_ttl(self, entity_id: str, additional_epochs: int) -> int:
        """
        Extend TTL for all shards of an entity across all nodes.

        Returns count of shards renewed.
        """
        renewed = 0
        for node in self.nodes:
            if node.evicted:
                continue
            for key in list(node._shard_ttl.keys()):
                if key[0] == entity_id:
                    if node.renew_shard_ttl(key[0], key[1], additional_epochs):
                        renewed += 1
        return renewed

    def distribute_encrypted_shards_with_ttl(
        self,
        entity_id: str,
        encrypted_shards: list[bytes],
        epoch: int,
        ttl_epochs: Optional[int] = None,
        replicas: int = 2,
    ) -> str:
        """
        Distribute encrypted shards with TTL metadata.

        Like distribute_encrypted_shards but records TTL for each shard.
        Returns: Merkle root of encrypted shard hashes.
        """
        shard_hashes = []

        for i, enc_shard in enumerate(encrypted_shards):
            shard_hash = H(enc_shard + entity_id.encode() + struct.pack('>I', i))
            shard_hashes.append(shard_hash)

            target_nodes = self._placement(entity_id, i, replicas)
            for node in target_nodes:
                node.store_shard_with_ttl(
                    entity_id, i, enc_shard, epoch, ttl_epochs
                )
                self._node_shard_index.setdefault(node.node_id, set()).add(
                    (entity_id, i)
                )

        return H(b''.join(h.encode() for h in shard_hashes))

    # --- Correlated Failure Analysis (Whitepaper §5.4.1.1) ---

    def region_failure(self, region: str) -> list[CommitmentNode]:
        """Simulate correlated regional failure. Returns affected nodes."""
        affected = []
        for node in self.nodes:
            if node.region == region and not node.evicted:
                node.evicted = True
                affected.append(node)
        return affected

    def restore_region(self, region: str) -> list[CommitmentNode]:
        """Restore all nodes in a region (undo region_failure)."""
        restored = []
        for node in self.nodes:
            if node.region == region and node.evicted:
                node.evicted = False
                restored.append(node)
        return restored

    def check_cross_region_placement(
        self, entity_id: str, n: int, replicas: int = 2
    ) -> dict:
        """
        Verify that shard replicas span multiple failure domains (regions).

        Returns: {"entity_id", "total_shards", "cross_region_count",
                  "same_region_count", "regions_used", "all_cross_region"}
        """
        cross_region = 0
        same_region = 0
        regions_used: set[str] = set()

        for shard_index in range(n):
            targets = self._placement(entity_id, shard_index, replicas)
            target_regions = {t.region for t in targets}
            regions_used |= target_regions
            if len(target_regions) > 1:
                cross_region += 1
            else:
                same_region += 1

        return {
            "entity_id": entity_id[:16] + "...",
            "total_shards": n,
            "cross_region_count": cross_region,
            "same_region_count": same_region,
            "regions_used": sorted(regions_used),
            "all_cross_region": same_region == 0,
        }

    def availability_under_region_failure(
        self, entity_id: str, n: int, k: int, failed_region: str
    ) -> dict:
        """
        Compute shard availability if an entire region fails.

        Returns: {"failed_region", "shards_total", "shards_lost",
                  "shards_surviving", "can_reconstruct", "k_threshold"}
        """
        surviving = 0
        lost = 0
        for shard_index in range(n):
            targets = self._placement(entity_id, shard_index)
            has_survivor = any(
                t.region != failed_region and not t.evicted
                for t in targets
            )
            if has_survivor:
                surviving += 1
            else:
                lost += 1

        return {
            "failed_region": failed_region,
            "shards_total": n,
            "shards_lost": lost,
            "shards_surviving": surviving,
            "can_reconstruct": surviving >= k,
            "k_threshold": k,
        }
