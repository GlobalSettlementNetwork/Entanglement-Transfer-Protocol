"""
Tests for CommitmentRecord, CommitmentLog, CommitmentNetwork, and audit protocol.
"""

import os
import pytest

from src.ltp.commitment import (
    AuditResult,
    CommitmentLog,
    CommitmentNetwork,
    CommitmentNode,
    CommitmentRecord,
)
from src.ltp.entity import Entity
from src.ltp.keypair import KeyPair
from src.ltp.primitives import H


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_record(keypair: KeyPair) -> CommitmentRecord:
    entity_id = H(os.urandom(32))
    record = CommitmentRecord(
        entity_id=entity_id,
        sender_id=keypair.label,
        shard_map_root=H(b"root"),
        content_hash=H(b"content"),
        encoding_params={"n": 8, "k": 4, "algorithm": "reed-solomon-gf256",
                         "gf_poly": "0x11d", "eval": "vandermonde-powers-of-0x02"},
        shape="text/plain",
        shape_hash=H(b"text/plain"),
        timestamp=1740000000.0,
    )
    record.sign(keypair.sk)
    return record


# ---------------------------------------------------------------------------
# CommitmentRecord
# ---------------------------------------------------------------------------

class TestCommitmentRecord:
    def test_sign_and_verify(self):
        kp = KeyPair.generate("alice")
        record = _make_record(kp)
        assert record.verify_signature(kp.vk) is True

    def test_wrong_vk_fails(self):
        kp1 = KeyPair.generate("alice")
        kp2 = KeyPair.generate("bob")
        record = _make_record(kp1)
        assert record.verify_signature(kp2.vk) is False

    def test_tamper_content_hash_breaks_sig(self):
        kp = KeyPair.generate("alice")
        record = _make_record(kp)
        record.content_hash = H(b"different content")
        assert record.verify_signature(kp.vk) is False

    def test_tamper_entity_id_breaks_sig(self):
        kp = KeyPair.generate("alice")
        record = _make_record(kp)
        record.entity_id = H(b"fake entity")
        assert record.verify_signature(kp.vk) is False

    def test_predecessor_excluded_from_signable_payload(self):
        """Setting predecessor after signing must NOT invalidate the signature."""
        kp = KeyPair.generate("alice")
        record = _make_record(kp)
        assert record.verify_signature(kp.vk)  # valid before predecessor set
        record.predecessor = "0" * 64
        assert record.verify_signature(kp.vk)  # still valid after predecessor set

    def test_empty_signature_fails(self):
        kp = KeyPair.generate("alice")
        record = _make_record(kp)
        record.signature = b""
        assert record.verify_signature(kp.vk) is False

    def test_to_dict_round_trip(self):
        kp = KeyPair.generate("alice")
        record = _make_record(kp)
        d = record.to_dict()
        assert d["entity_id"] == record.entity_id
        assert d["sender_id"] == record.sender_id
        assert "shape" in d


# ---------------------------------------------------------------------------
# CommitmentLog
# ---------------------------------------------------------------------------

class TestCommitmentLog:
    def test_append_and_fetch(self):
        log = CommitmentLog()
        kp = KeyPair.generate("sender")
        record = _make_record(kp)
        log.append(record)
        assert log.fetch(record.entity_id) is record

    def test_append_returns_hash(self):
        log = CommitmentLog()
        kp = KeyPair.generate("sender")
        record = _make_record(kp)
        ref = log.append(record)
        assert ref.startswith("blake2b:")

    def test_duplicate_append_raises(self):
        log = CommitmentLog()
        kp = KeyPair.generate("sender")
        record = _make_record(kp)
        log.append(record)
        with pytest.raises(ValueError, match="already committed"):
            log.append(record)

    def test_chain_integrity_empty(self):
        log = CommitmentLog()
        ok, _ = log.verify_chain_integrity()
        assert ok is True

    def test_chain_integrity_multiple_records(self):
        log = CommitmentLog()
        kp = KeyPair.generate("sender")
        for _ in range(5):
            record = _make_record(kp)
            log.append(record)
        ok, idx = log.verify_chain_integrity()
        assert ok is True

    def test_tamper_breaks_chain(self):
        log = CommitmentLog()
        kp = KeyPair.generate("sender")
        records = []
        for _ in range(3):
            r = _make_record(kp)
            log.append(r)
            records.append(r)

        # Tamper with first record
        original_hash = records[0].content_hash
        prefix, hex_part = original_hash.split(":", 1)
        records[0].content_hash = prefix + ":" + hex(int(hex_part, 16) ^ 1)[2:].zfill(64)

        ok, break_idx = log.verify_chain_integrity()
        assert ok is False
        assert break_idx == 0

        # Restore
        records[0].content_hash = original_hash
        ok, _ = log.verify_chain_integrity()
        assert ok is True

    def test_inclusion_proof_valid(self):
        log = CommitmentLog()
        kp = KeyPair.generate("sender")
        record = _make_record(kp)
        log.append(record)
        proof = log.get_inclusion_proof(record.entity_id)
        assert proof is not None
        assert log.verify_inclusion(record.entity_id, proof) is True

    def test_inclusion_proof_unknown_entity(self):
        log = CommitmentLog()
        assert log.get_inclusion_proof("unknown-entity-id") is None

    def test_head_hash_updates(self):
        log = CommitmentLog()
        initial = log.head_hash
        kp = KeyPair.generate("sender")
        log.append(_make_record(kp))
        assert log.head_hash != initial

    def test_length_property(self):
        log = CommitmentLog()
        kp = KeyPair.generate("sender")
        assert log.length == 0
        log.append(_make_record(kp))
        assert log.length == 1
        log.append(_make_record(kp))
        assert log.length == 2


# ---------------------------------------------------------------------------
# CommitmentNetwork — shard distribution and retrieval
# ---------------------------------------------------------------------------

class TestCommitmentNetwork:
    def test_add_node(self, network):
        assert len(network.nodes) == 6

    def test_distribute_and_fetch(self, network):
        entity_id = H(b"test-entity")
        shards = [os.urandom(64) for _ in range(8)]
        network.distribute_encrypted_shards(entity_id, shards)
        fetched = network.fetch_encrypted_shards(entity_id, 8, 4)
        assert len(fetched) >= 4

    def test_fetch_returns_at_most_requested(self, network):
        entity_id = H(b"fetch-limit-test")
        shards = [os.urandom(64) for _ in range(8)]
        network.distribute_encrypted_shards(entity_id, shards)
        fetched = network.fetch_encrypted_shards(entity_id, 8, 4)
        # fetch_encrypted_shards fetches up to the k argument
        assert len(fetched) <= 8

    def test_placement_deterministic(self, network):
        entity_id = H(b"stable-entity")
        p1 = network._placement(entity_id, 0)
        p2 = network._placement(entity_id, 0)
        assert [n.node_id for n in p1] == [n.node_id for n in p2]

    def test_evict_node(self, network, alice):
        """Evicting a node should trigger shard repair."""
        from src.ltp.protocol import LTPProtocol
        protocol = LTPProtocol(network)
        entity = Entity(content=b"repair test", shape="x-ltp/test")
        entity_id, record, cek = protocol.commit(entity, alice, n=8, k=4)

        target = network.nodes[0]
        result = network.evict_node(target)
        assert target.evicted is True
        assert result["evicted_node"] == target.node_id
        assert isinstance(result["repaired"], int)

    def test_active_node_count(self, network):
        assert network.active_node_count == 6
        network.nodes[0].evicted = True
        assert network.active_node_count == 5


# ---------------------------------------------------------------------------
# Audit protocol
# ---------------------------------------------------------------------------

class TestAuditProtocol:
    def test_audit_result_type(self, network, alice):
        from src.ltp.protocol import LTPProtocol
        protocol = LTPProtocol(network)
        entity = Entity(content=b"audit target", shape="x-ltp/test")
        protocol.commit(entity, alice, n=8, k=4)

        results = network.audit_all_nodes()
        assert all(isinstance(r, AuditResult) for r in results)

    def test_healthy_nodes_pass_audit(self, network, alice):
        from src.ltp.protocol import LTPProtocol
        protocol = LTPProtocol(network)
        entity = Entity(content=b"healthy test", shape="x-ltp/test")
        protocol.commit(entity, alice, n=8, k=4)

        results = network.audit_all_nodes()
        for r in results:
            assert r.result == "PASS"

    def test_degraded_node_fails_audit(self, network, alice):
        from src.ltp.protocol import LTPProtocol
        protocol = LTPProtocol(network)
        entity = Entity(content=b"degraded audit", shape="x-ltp/test")
        protocol.commit(entity, alice, n=8, k=4)

        # Forcibly delete shards from a node
        target = network.nodes[0]
        for key in list(target.shards.keys()):
            target.remove_shard(key[0], key[1])

        result = network.audit_node(target)
        assert result.result == "FAIL"
        assert result.failed > 0

    def test_burst_audit_produces_more_challenges(self, network, alice):
        from src.ltp.protocol import LTPProtocol
        protocol = LTPProtocol(network)
        entity = Entity(content=b"burst audit", shape="x-ltp/test")
        protocol.commit(entity, alice, n=8, k=4)

        result_burst1 = network.audit_node(network.nodes[0], burst=1)
        result_burst4 = network.audit_node(network.nodes[0], burst=4)
        # With burst=4, challenged count should be ~4× higher
        assert result_burst4.challenged >= result_burst1.challenged * 3

    def test_audit_result_fields(self, network, alice):
        from src.ltp.protocol import LTPProtocol
        protocol = LTPProtocol(network)
        entity = Entity(content=b"field test", shape="x-ltp/test")
        protocol.commit(entity, alice, n=8, k=4)

        r = network.audit_node(network.nodes[0])
        assert hasattr(r, "node_id")
        assert hasattr(r, "challenged")
        assert hasattr(r, "passed")
        assert hasattr(r, "failed")
        assert hasattr(r, "missing")
        assert hasattr(r, "result")
        assert hasattr(r, "strikes")
        assert hasattr(r, "avg_response_us")


# ---------------------------------------------------------------------------
# Correlated failure
# ---------------------------------------------------------------------------

class TestCorrelatedFailure:
    def test_region_failure_and_restore(self, network):
        affected = network.region_failure("US-East")
        assert all(n.evicted for n in affected)
        restored = network.restore_region("US-East")
        assert all(not n.evicted for n in restored)

    def test_availability_under_region_failure(self, network, alice):
        from src.ltp.protocol import LTPProtocol
        protocol = LTPProtocol(network)
        entity = Entity(content=b"regional failure test", shape="x-ltp/test")
        entity_id, record, _ = protocol.commit(entity, alice, n=8, k=4)

        regions = sorted(set(nd.region for nd in network.nodes))
        for region in regions:
            avail = network.availability_under_region_failure(entity_id, 8, 4, region)
            assert avail["can_reconstruct"] is True, \
                f"Entity cannot be reconstructed after {region} failure"

    def test_cross_region_placement(self, network, alice):
        from src.ltp.protocol import LTPProtocol
        protocol = LTPProtocol(network)
        entity = Entity(content=b"placement test", shape="x-ltp/test")
        entity_id, record, _ = protocol.commit(entity, alice, n=8, k=4)

        placement = network.check_cross_region_placement(entity_id, 8)
        assert "regions_used" in placement
        assert len(placement["regions_used"]) > 1
