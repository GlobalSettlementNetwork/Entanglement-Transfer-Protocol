"""
REST API Tests for CommitmentLogRestServer.

Tests all 6 RFC 6962-compatible endpoints.
"""

import json
import urllib.request
import urllib.error

import pytest

from src.ltp import KeyPair, Entity, CommitmentNetwork, LTPProtocol, reset_poc_state
from src.ltp.rest_server import CommitmentLogRestServer


@pytest.fixture
def server():
    """Start a REST server with a populated commitment log."""
    reset_poc_state()
    alice = KeyPair.generate("alice")
    network = CommitmentNetwork()
    for i in range(3):
        network.add_node(f"node-{i}", "us-east-1")
    protocol = LTPProtocol(network)

    # Commit 5 entities
    for i in range(5):
        entity = Entity(content=f"test-content-{i}".encode(), shape="text/plain")
        protocol.commit(entity, alice)

    srv = CommitmentLogRestServer(network.log, host="127.0.0.1", port=18962)
    srv.start()
    yield srv
    srv.stop()


def _get(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=5) as resp:
        return json.loads(resp.read())


class TestGetSTH:
    def test_returns_sth(self, server):
        data = _get(f"{server.url}/ct/v1/get-sth")
        assert "tree_size" in data
        assert data["tree_size"] == 5
        assert "root_hash" in data
        assert "sequence" in data

    def test_sth_has_signature(self, server):
        data = _get(f"{server.url}/ct/v1/get-sth")
        assert data["signature"] != ""
        assert data["operator_vk"] != ""


class TestGetEntries:
    def test_returns_range(self, server):
        data = _get(f"{server.url}/ct/v1/get-entries?start=0&end=3")
        assert len(data["entries"]) == 3
        assert data["start"] == 0
        assert data["end"] == 3

    def test_all_entries(self, server):
        data = _get(f"{server.url}/ct/v1/get-entries?start=0&end=5")
        assert len(data["entries"]) == 5

    def test_invalid_range(self, server):
        try:
            _get(f"{server.url}/ct/v1/get-entries?start=10&end=20")
            assert False, "Should have raised"
        except urllib.error.HTTPError as e:
            assert e.code == 400


class TestGetProof:
    def test_proof_for_entity(self, server):
        # Get first entity_id from entries
        entries = _get(f"{server.url}/ct/v1/get-entries?start=0&end=1")
        entity_id = entries["entries"][0]["entity_id"]

        proof = _get(f"{server.url}/ct/v1/get-proof-by-hash?entity_id={entity_id}")
        assert proof["entity_id"] == entity_id
        assert "position" in proof
        assert "root_hash" in proof

    def test_proof_missing_entity(self, server):
        try:
            _get(f"{server.url}/ct/v1/get-proof-by-hash?entity_id=nonexistent")
            assert False, "Should have raised"
        except urllib.error.HTTPError as e:
            assert e.code == 404

    def test_proof_missing_param(self, server):
        try:
            _get(f"{server.url}/ct/v1/get-proof-by-hash")
            assert False, "Should have raised"
        except urllib.error.HTTPError as e:
            assert e.code == 400


class TestGetConsistency:
    def test_consistency_proof(self, server):
        data = _get(f"{server.url}/ct/v1/get-sth-consistency?first=2&second=5")
        assert data["first"] == 2
        assert data["second"] == 5
        assert "consistency" in data

    def test_consistency_invalid_range(self, server):
        try:
            _get(f"{server.url}/ct/v1/get-sth-consistency?first=0&second=5")
            assert False, "Should have raised"
        except urllib.error.HTTPError as e:
            assert e.code == 400


class TestGetEntryAndProof:
    def test_entry_with_proof(self, server):
        entries = _get(f"{server.url}/ct/v1/get-entries?start=0&end=1")
        entity_id = entries["entries"][0]["entity_id"]

        data = _get(f"{server.url}/ct/v1/get-entry-and-proof?entity_id={entity_id}")
        assert "entry" in data
        assert "proof" in data
        assert data["entry"]["entity_id"] == entity_id

    def test_missing_entity(self, server):
        try:
            _get(f"{server.url}/ct/v1/get-entry-and-proof?entity_id=nonexistent")
            assert False, "Should have raised"
        except urllib.error.HTTPError as e:
            assert e.code == 404


class TestUnknownEndpoint:
    def test_404_on_unknown(self, server):
        try:
            _get(f"{server.url}/ct/v1/unknown")
            assert False, "Should have raised"
        except urllib.error.HTTPError as e:
            assert e.code == 404
