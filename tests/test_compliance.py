"""
Tests for the institutional compliance framework.

Covers: FIPS CryptoProvider, RBAC, GeoFencing, AuditLogger, KeyRotation,
        GDPR Deletion, SIEM Export, HSM Interface, ComplianceConfig.
"""

import json
import os
import pytest

from src.ltp.compliance import (
    AuditEvent,
    AuditEventType,
    ComplianceAuditLogger,
    ComplianceConfig,
    ComplianceFramework,
    ComplianceRole,
    CryptoProviderMode,
    DeletionProof,
    DeletionRequest,
    FIPSCryptoProvider,
    GDPRDeletionManager,
    GeoFencePolicy,
    HSMConfig,
    Jurisdiction,
    KeyRotationManager,
    KeyRotationPolicy,
    KeyVersion,
    Permission,
    RBACManager,
    RBACPolicy,
    SIEMExporter,
    SIEMFormat,
    SoftwareHSM,
)
from src.ltp.commitment import CommitmentNetwork
from src.ltp.primitives import set_crypto_provider, get_crypto_provider


# ============================================================================
# FIPS Crypto Provider
# ============================================================================

class TestFIPSCryptoProvider:
    """Tests for the FIPS 140-3 crypto provider."""

    def test_default_mode_uses_blake2b(self):
        provider = FIPSCryptoProvider(CryptoProviderMode.DEFAULT)
        h = provider.hash(b"test")
        assert h.startswith("blake2b:")
        assert not provider.is_fips_mode

    def test_default_mode_hash_bytes(self):
        provider = FIPSCryptoProvider(CryptoProviderMode.DEFAULT)
        raw = provider.hash_bytes(b"test")
        assert isinstance(raw, bytes)
        assert len(raw) == 32

    def test_default_mode_aead_roundtrip(self):
        provider = FIPSCryptoProvider(CryptoProviderMode.DEFAULT)
        key = os.urandom(32)
        nonce = os.urandom(16)
        plaintext = b"hello world"
        ct = provider.encrypt(key, plaintext, nonce)
        pt = provider.decrypt(key, ct, nonce)
        assert pt == plaintext

    def test_fips_mode_hash_uses_sha3(self):
        # FIPS mode should work even if OpenSSL FIPS isn't available
        # (it falls back to hashlib SHA3 which is always available)
        provider = FIPSCryptoProvider.__new__(FIPSCryptoProvider)
        provider.mode = CryptoProviderMode.FIPS
        provider._fips_available = True  # Skip check
        h = provider.hash(b"test")
        assert h.startswith("sha3-256:")

    def test_fips_mode_hash_bytes_sha3(self):
        provider = FIPSCryptoProvider.__new__(FIPSCryptoProvider)
        provider.mode = CryptoProviderMode.FIPS
        provider._fips_available = True
        raw = provider.hash_bytes(b"test")
        assert len(raw) == 32
        # Verify it's SHA3, not BLAKE2b
        import hashlib
        expected = hashlib.sha3_256(b"test").digest()
        assert raw == expected

    def test_algorithm_info_default(self):
        provider = FIPSCryptoProvider(CryptoProviderMode.DEFAULT)
        info = provider.algorithm_info()
        assert info["mode"] == "default (PoC)"
        assert "BLAKE2b" in info["hash"]

    def test_algorithm_info_fips(self):
        provider = FIPSCryptoProvider.__new__(FIPSCryptoProvider)
        provider.mode = CryptoProviderMode.FIPS
        provider._fips_available = True
        info = provider.algorithm_info()
        assert info["mode"] == "FIPS 140-3"
        assert "SHA3-256" in info["hash"]
        assert "AES-256-GCM" in info["aead"]

    def test_hybrid_mode_is_fips(self):
        provider = FIPSCryptoProvider.__new__(FIPSCryptoProvider)
        provider.mode = CryptoProviderMode.HYBRID
        provider._fips_available = True
        assert provider.is_fips_mode

    def test_set_crypto_provider_global(self):
        original = get_crypto_provider()
        try:
            provider = FIPSCryptoProvider(CryptoProviderMode.DEFAULT)
            set_crypto_provider(provider)
            assert get_crypto_provider() is provider
        finally:
            set_crypto_provider(original)


# ============================================================================
# RBAC
# ============================================================================

class TestRBAC:
    """Tests for Role-Based Access Control."""

    def test_create_policy_with_roles(self):
        mgr = RBACManager()
        policy = mgr.create_policy("alice", {ComplianceRole.SENDER})
        assert ComplianceRole.SENDER in policy.roles
        assert policy.identity_id == "alice"

    def test_sender_can_commit(self):
        mgr = RBACManager()
        mgr.create_policy("alice", {ComplianceRole.SENDER})
        assert mgr.check_permission("alice", Permission.ENTITY_COMMIT)

    def test_sender_cannot_slash(self):
        mgr = RBACManager()
        mgr.create_policy("alice", {ComplianceRole.SENDER})
        assert not mgr.check_permission("alice", Permission.SLASH_EXECUTE)

    def test_receiver_can_materialize(self):
        mgr = RBACManager()
        mgr.create_policy("bob", {ComplianceRole.RECEIVER})
        assert mgr.check_permission("bob", Permission.ENTITY_MATERIALIZE)

    def test_auditor_can_read_logs(self):
        mgr = RBACManager()
        mgr.create_policy("charlie", {ComplianceRole.AUDITOR})
        assert mgr.check_permission("charlie", Permission.AUDIT_LOG_READ)
        assert mgr.check_permission("charlie", Permission.AUDIT_LOG_EXPORT)

    def test_auditor_cannot_commit(self):
        mgr = RBACManager()
        mgr.create_policy("charlie", {ComplianceRole.AUDITOR})
        assert not mgr.check_permission("charlie", Permission.ENTITY_COMMIT)

    def test_compliance_officer_can_gdpr_delete(self):
        mgr = RBACManager()
        mgr.create_policy("dave", {ComplianceRole.COMPLIANCE_OFFICER})
        assert mgr.check_permission("dave", Permission.GDPR_DELETE)
        assert mgr.check_permission("dave", Permission.COMPLIANCE_REPORT)

    def test_admin_has_all_permissions(self):
        mgr = RBACManager()
        mgr.create_policy("root", {ComplianceRole.ADMIN})
        for perm in Permission:
            assert mgr.check_permission("root", perm), f"Admin missing {perm}"

    def test_unknown_identity_denied(self):
        mgr = RBACManager()
        assert not mgr.check_permission("unknown", Permission.ENTITY_COMMIT)

    def test_require_permission_raises(self):
        mgr = RBACManager()
        mgr.create_policy("alice", {ComplianceRole.SENDER})
        with pytest.raises(PermissionError):
            mgr.require_permission("alice", Permission.SLASH_EXECUTE)

    def test_policy_expiration(self):
        mgr = RBACManager()
        mgr.create_policy("temp", {ComplianceRole.SENDER}, epoch=0, expires_epoch=100)
        assert mgr.check_permission("temp", Permission.ENTITY_COMMIT, current_epoch=50)
        assert not mgr.check_permission("temp", Permission.ENTITY_COMMIT, current_epoch=101)

    def test_revoke_policy(self):
        mgr = RBACManager()
        mgr.create_policy("alice", {ComplianceRole.SENDER})
        assert mgr.check_permission("alice", Permission.ENTITY_COMMIT)
        mgr.revoke_policy("alice")
        assert not mgr.check_permission("alice", Permission.ENTITY_COMMIT)

    def test_denied_permissions_override(self):
        mgr = RBACManager()
        policy = mgr.create_policy("alice", {ComplianceRole.ADMIN})
        policy.denied_permissions.add(Permission.GDPR_DELETE)
        assert not mgr.check_permission("alice", Permission.GDPR_DELETE)
        # Other admin perms still work
        assert mgr.check_permission("alice", Permission.CONFIG_MODIFY)

    def test_list_identities_with_role(self):
        mgr = RBACManager()
        mgr.create_policy("a", {ComplianceRole.AUDITOR})
        mgr.create_policy("b", {ComplianceRole.AUDITOR})
        mgr.create_policy("c", {ComplianceRole.SENDER})
        auditors = mgr.list_identities_with_role(ComplianceRole.AUDITOR)
        assert set(auditors) == {"a", "b"}

    def test_rbac_with_audit_logger(self):
        logger = ComplianceAuditLogger()
        mgr = RBACManager()
        mgr.set_audit_logger(logger)
        mgr.create_policy("alice", {ComplianceRole.SENDER})
        assert logger.length >= 1


# ============================================================================
# Geo-Fencing
# ============================================================================

class TestGeoFencing:
    """Tests for jurisdiction-constrained shard placement."""

    def test_global_allows_all(self):
        policy = GeoFencePolicy()
        assert policy.is_region_allowed("us-east-1")
        assert policy.is_region_allowed("eu-west-1")
        assert policy.is_region_allowed("ap-southeast-1")

    def test_us_only_policy(self):
        policy = GeoFencePolicy(
            allowed_jurisdictions={Jurisdiction.US}
        )
        assert policy.is_region_allowed("us-east-1")
        assert policy.is_region_allowed("us-west-2")
        assert not policy.is_region_allowed("eu-west-1")
        assert not policy.is_region_allowed("ap-southeast-1")

    def test_eu_only_policy(self):
        policy = GeoFencePolicy(
            allowed_jurisdictions={Jurisdiction.EU}
        )
        assert not policy.is_region_allowed("us-east-1")
        assert policy.is_region_allowed("eu-west-1")
        assert policy.is_region_allowed("europe-west1")

    def test_exclusion_overrides_global(self):
        policy = GeoFencePolicy(
            allowed_jurisdictions={Jurisdiction.GLOBAL},
            excluded_jurisdictions={Jurisdiction.EU},
        )
        assert policy.is_region_allowed("us-east-1")
        assert not policy.is_region_allowed("eu-west-1")

    def test_govcloud_mapping(self):
        policy = GeoFencePolicy(
            allowed_jurisdictions={Jurisdiction.US_GOVCLOUD}
        )
        assert policy.is_region_allowed("us_gov-east-1")
        assert not policy.is_region_allowed("us-east-1")

    def test_filter_nodes(self):
        policy = GeoFencePolicy(
            allowed_jurisdictions={Jurisdiction.US}
        )
        network = CommitmentNetwork()
        n1 = network.add_node("n1", "us-east-1")
        n2 = network.add_node("n2", "eu-west-1")
        n3 = network.add_node("n3", "us-west-2")
        filtered = policy.filter_nodes(network.nodes)
        assert len(filtered) == 2
        assert n1 in filtered
        assert n3 in filtered
        assert n2 not in filtered

    def test_validate_placement(self):
        policy = GeoFencePolicy(
            allowed_jurisdictions={Jurisdiction.US}
        )
        network = CommitmentNetwork()
        n1 = network.add_node("n1", "us-east-1")
        n2 = network.add_node("n2", "eu-west-1")
        valid, violations = policy.validate_placement([n1])
        assert valid
        valid, violations = policy.validate_placement([n1, n2])
        assert not valid
        assert len(violations) == 1

    def test_cross_jurisdiction_requirement(self):
        policy = GeoFencePolicy(
            allowed_jurisdictions={Jurisdiction.US, Jurisdiction.EU},
            require_cross_jurisdiction=True,
            min_jurisdictions=2,
        )
        network = CommitmentNetwork()
        n1 = network.add_node("n1", "us-east-1")
        n2 = network.add_node("n2", "us-west-2")
        # Both in US — fails cross-jurisdiction
        valid, violations = policy.validate_placement([n1, n2])
        assert not valid

    def test_geo_fence_on_commitment_network(self):
        """Geo-fence policy integrated with CommitmentNetwork._placement."""
        network = CommitmentNetwork()
        policy = GeoFencePolicy(
            allowed_jurisdictions={Jurisdiction.US}
        )
        network.set_geo_fence_policy(policy)
        network.add_node("us1", "us-east-1")
        network.add_node("us2", "us-west-2")
        network.add_node("eu1", "eu-west-1")

        shards = [os.urandom(64) for _ in range(4)]
        network.distribute_encrypted_shards("test-entity", shards)

        # EU node should have zero shards
        eu_node = network.nodes[2]
        assert eu_node.shard_count == 0

    def test_geo_fence_raises_when_no_eligible_nodes(self):
        network = CommitmentNetwork()
        policy = GeoFencePolicy(
            allowed_jurisdictions={Jurisdiction.JP}
        )
        network.set_geo_fence_policy(policy)
        network.add_node("us1", "us-east-1")
        with pytest.raises(ValueError, match="allowed jurisdictions"):
            network.distribute_encrypted_shards(
                "test", [os.urandom(32)]
            )


# ============================================================================
# Audit Logger
# ============================================================================

class TestComplianceAuditLogger:
    """Tests for the immutable audit log."""

    def test_log_event(self):
        logger = ComplianceAuditLogger()
        event = AuditEvent(
            event_type=AuditEventType.NODE_REGISTERED,
            actor_id="node-1",
            action="registered",
            epoch=1,
        )
        chain_hash = logger.log(event)
        assert chain_hash.startswith("blake2b:")
        assert logger.length == 1

    def test_chain_integrity_valid(self):
        logger = ComplianceAuditLogger()
        for i in range(10):
            logger.log(AuditEvent(
                event_type=AuditEventType.NODE_AUDITED,
                actor_id="system",
                action=f"audit-{i}",
                epoch=i,
            ))
        valid, idx = logger.verify_chain_integrity()
        assert valid
        assert idx == 10

    def test_chain_integrity_detects_tampering(self):
        logger = ComplianceAuditLogger()
        for i in range(5):
            logger.log(AuditEvent(
                event_type=AuditEventType.NODE_AUDITED,
                actor_id="system",
                action=f"audit-{i}",
                epoch=i,
            ))
        # Tamper with chain hash
        logger._chain_hashes[2] = "blake2b:tampered"
        valid, idx = logger.verify_chain_integrity()
        assert not valid
        assert idx == 2

    def test_query_by_event_type(self):
        logger = ComplianceAuditLogger()
        logger.log(AuditEvent(
            event_type=AuditEventType.NODE_REGISTERED,
            actor_id="n1", action="reg", epoch=1,
        ))
        logger.log(AuditEvent(
            event_type=AuditEventType.ACCESS_DENIED,
            actor_id="eve", action="denied", epoch=2,
        ))
        logger.log(AuditEvent(
            event_type=AuditEventType.NODE_REGISTERED,
            actor_id="n2", action="reg", epoch=3,
        ))
        results = logger.query(event_type=AuditEventType.NODE_REGISTERED)
        assert len(results) == 2

    def test_query_by_actor(self):
        logger = ComplianceAuditLogger()
        logger.log(AuditEvent(
            event_type=AuditEventType.ENTITY_COMMITTED,
            actor_id="alice", action="commit", epoch=1,
        ))
        logger.log(AuditEvent(
            event_type=AuditEventType.ENTITY_COMMITTED,
            actor_id="bob", action="commit", epoch=2,
        ))
        results = logger.query(actor_id="alice")
        assert len(results) == 1
        assert results[0].actor_id == "alice"

    def test_query_with_limit(self):
        logger = ComplianceAuditLogger()
        for i in range(20):
            logger.log(AuditEvent(
                event_type=AuditEventType.SHARD_STORED,
                actor_id="system", action=f"store-{i}", epoch=i,
            ))
        results = logger.query(limit=5)
        assert len(results) == 5

    def test_export_json(self):
        logger = ComplianceAuditLogger()
        logger.log(AuditEvent(
            event_type=AuditEventType.ENTITY_COMMITTED,
            actor_id="alice", action="commit", epoch=5,
        ))
        exported = logger.export_json(since_epoch=0)
        assert len(exported) == 1
        assert exported[0]["actor_id"] == "alice"

    def test_evict_expired(self):
        logger = ComplianceAuditLogger(retention_epochs=100)
        for i in range(10):
            logger.log(AuditEvent(
                event_type=AuditEventType.SHARD_STORED,
                actor_id="system", action=f"store-{i}", epoch=i,
            ))
        removed = logger.evict_expired(current_epoch=105)
        assert removed == 5  # epochs 0-4 should be evicted
        assert logger.length == 5

    def test_head_hash_changes(self):
        logger = ComplianceAuditLogger()
        h0 = logger.head_hash
        logger.log(AuditEvent(
            event_type=AuditEventType.NODE_REGISTERED,
            actor_id="n1", action="reg", epoch=1,
        ))
        h1 = logger.head_hash
        assert h0 != h1

    def test_audit_logger_on_commitment_network(self):
        """Audit logger integrated with CommitmentNetwork."""
        logger = ComplianceAuditLogger()
        network = CommitmentNetwork()
        network.set_audit_logger(logger)
        network.add_node("n1", "us-east-1")
        assert logger.length >= 1
        events = logger.query(event_type=AuditEventType.NODE_REGISTERED)
        assert len(events) == 1


# ============================================================================
# SIEM Export
# ============================================================================

class TestSIEMExporter:
    """Tests for SIEM-compatible audit event export."""

    def test_export_json(self):
        event = AuditEvent(
            event_type=AuditEventType.ACCESS_DENIED,
            actor_id="eve",
            action="unauthorized",
            epoch=1,
        )
        output = SIEMExporter.export_event(event, SIEMFormat.JSON)
        parsed = json.loads(output)
        assert parsed["actor_id"] == "eve"
        assert parsed["event_type"] == "access.denied"

    def test_export_cef(self):
        event = AuditEvent(
            event_type=AuditEventType.NODE_EVICTED,
            actor_id="system",
            target_id="bad-node",
            action="evicted",
            epoch=1,
        )
        output = SIEMExporter.export_event(event, SIEMFormat.CEF)
        assert output.startswith("CEF:0|LTP|")
        assert "act=evicted" in output
        assert "dst=bad-node" in output

    def test_export_json_ld(self):
        event = AuditEvent(
            event_type=AuditEventType.ENTITY_COMMITTED,
            actor_id="alice",
            target_id="entity-001",
            action="committed",
            epoch=5,
        )
        output = SIEMExporter.export_event(event, SIEMFormat.JSON_LD)
        parsed = json.loads(output)
        assert parsed["@context"] == "https://ltp.network/compliance/v1"
        assert parsed["@type"] == "AuditEvent"
        assert parsed["actor"]["id"] == "alice"

    def test_export_multiple_events(self):
        events = [
            AuditEvent(
                event_type=AuditEventType.SHARD_STORED,
                actor_id="n1", action=f"store-{i}", epoch=i,
            )
            for i in range(3)
        ]
        output = SIEMExporter.export_events(events, SIEMFormat.JSON)
        parsed = json.loads(output)
        assert len(parsed) == 3

    def test_cef_severity_mapping(self):
        # Security violation should be high severity
        event = AuditEvent(
            event_type=AuditEventType.SECURITY_VIOLATION,
            actor_id="attacker", action="exploit", epoch=1,
        )
        output = SIEMExporter.export_event(event, SIEMFormat.CEF)
        # Severity 9 for security violations
        assert "|9|" in output


# ============================================================================
# Key Rotation
# ============================================================================

class TestKeyRotation:
    """Tests for key rotation policy and manager."""

    def test_register_key(self):
        mgr = KeyRotationManager()
        kv = mgr.register_key("bob", "fp-abc", epoch=0)
        assert kv.version == 1
        assert kv.key_fingerprint == "fp-abc"
        assert kv.expires_epoch == 8760  # default max age

    def test_get_active_key(self):
        mgr = KeyRotationManager()
        mgr.register_key("bob", "fp-v1", epoch=0)
        mgr.register_key("bob", "fp-v2", epoch=100)
        active = mgr.get_active_key("bob")
        assert active.key_fingerprint == "fp-v2"

    def test_rotation_needed_at_expiry(self):
        mgr = KeyRotationManager(
            policy=KeyRotationPolicy(max_key_age_epochs=1000)
        )
        mgr.register_key("bob", "fp-v1", epoch=0)
        needs, reason = mgr.check_rotation_needed("bob", current_epoch=1000)
        assert needs
        assert reason == "key_expired"

    def test_rotation_warning(self):
        mgr = KeyRotationManager(
            policy=KeyRotationPolicy(
                max_key_age_epochs=1000,
                rotation_warning_epochs=100,
            )
        )
        mgr.register_key("bob", "fp-v1", epoch=0)
        needs, reason = mgr.check_rotation_needed("bob", current_epoch=950)
        assert needs
        assert reason == "approaching_expiry"

    def test_no_rotation_needed(self):
        mgr = KeyRotationManager(
            policy=KeyRotationPolicy(
                max_key_age_epochs=1000,
                rotation_warning_epochs=100,
            )
        )
        mgr.register_key("bob", "fp-v1", epoch=0)
        needs, reason = mgr.check_rotation_needed("bob", current_epoch=500)
        assert not needs
        assert reason is None

    def test_rotation_needed_no_key(self):
        mgr = KeyRotationManager()
        needs, reason = mgr.check_rotation_needed("unknown", current_epoch=0)
        assert needs
        assert reason == "no_active_key"

    def test_revoke_key(self):
        mgr = KeyRotationManager()
        kv = mgr.register_key("bob", "fp-v1", epoch=0)
        result = mgr.revoke_key("bob", kv.version, epoch=100, reason="compromised")
        assert result
        assert kv.revoked
        assert kv.revoked_epoch == 100

    def test_max_versions_retained(self):
        mgr = KeyRotationManager(
            policy=KeyRotationPolicy(max_versions_retained=3)
        )
        for i in range(5):
            mgr.register_key("bob", f"fp-v{i}", epoch=i * 100)
        history = mgr.get_key_history("bob")
        assert len(history) == 3

    def test_key_history_newest_first(self):
        mgr = KeyRotationManager()
        mgr.register_key("bob", "fp-old", epoch=0)
        mgr.register_key("bob", "fp-new", epoch=100)
        history = mgr.get_key_history("bob")
        assert history[0].key_fingerprint == "fp-new"

    def test_rotation_with_audit_logger(self):
        logger = ComplianceAuditLogger()
        mgr = KeyRotationManager(audit_logger=logger)
        mgr.register_key("bob", "fp-v1", epoch=0)
        assert logger.length >= 1
        events = logger.query(event_type=AuditEventType.KEY_GENERATED)
        assert len(events) == 1


# ============================================================================
# GDPR Deletion
# ============================================================================

class TestGDPRDeletion:
    """Tests for GDPR right-to-erasure with deletion proofs."""

    def _setup_network_with_entity(self):
        """Helper: create network with an entity's shards distributed."""
        network = CommitmentNetwork()
        n1 = network.add_node("node-a", "eu-west-1")
        n2 = network.add_node("node-b", "eu-central-1")
        shards = [os.urandom(128) for _ in range(4)]
        network.distribute_encrypted_shards("entity-to-delete", shards)
        return network, [n1, n2]

    def test_submit_deletion_request(self):
        gdpr = GDPRDeletionManager()
        req = gdpr.submit_request("entity-1", "subject-1", epoch=100)
        assert req.status == "pending"
        assert req.entity_id == "entity-1"

    def test_execute_deletion_removes_shards(self):
        network, nodes = self._setup_network_with_entity()
        total_before = sum(n.shard_count for n in nodes)
        assert total_before > 0

        gdpr = GDPRDeletionManager()
        req = gdpr.submit_request("entity-to-delete", "subject-1", epoch=100)
        proof = gdpr.execute_deletion(req.request_id, nodes, epoch=101)

        total_after = sum(n.shard_count for n in nodes)
        assert total_after == 0
        assert req.status == "completed"

    def test_deletion_produces_proof(self):
        network, nodes = self._setup_network_with_entity()
        gdpr = GDPRDeletionManager()
        req = gdpr.submit_request("entity-to-delete", "subject-1", epoch=100)
        proof = gdpr.execute_deletion(req.request_id, nodes, epoch=101)

        assert proof is not None
        assert proof.entity_id == "entity-to-delete"
        assert proof.shard_count_destroyed > 0
        assert proof.node_count_participating > 0
        assert proof.destruction_merkle_root.startswith("blake2b:")
        assert len(proof.node_attestations) > 0
        assert proof.proof_hash.startswith("blake2b:")

    def test_deletion_proof_retrievable(self):
        network, nodes = self._setup_network_with_entity()
        gdpr = GDPRDeletionManager()
        req = gdpr.submit_request("entity-to-delete", "subject-1", epoch=100)
        gdpr.execute_deletion(req.request_id, nodes, epoch=101)

        proof = gdpr.get_proof("entity-to-delete")
        assert proof is not None

    def test_deletion_proof_to_dict(self):
        network, nodes = self._setup_network_with_entity()
        gdpr = GDPRDeletionManager()
        req = gdpr.submit_request("entity-to-delete", "subject-1", epoch=100)
        proof = gdpr.execute_deletion(req.request_id, nodes, epoch=101)
        d = proof.to_dict()
        assert "entity_id" in d
        assert "destruction_merkle_root" in d
        assert "proof_hash" in d

    def test_double_deletion_idempotent(self):
        network, nodes = self._setup_network_with_entity()
        gdpr = GDPRDeletionManager()
        req = gdpr.submit_request("entity-to-delete", "subject-1", epoch=100)
        proof1 = gdpr.execute_deletion(req.request_id, nodes, epoch=101)
        proof2 = gdpr.execute_deletion(req.request_id, nodes, epoch=102)
        # Second call returns cached proof
        assert proof2 is proof1

    def test_list_pending_requests(self):
        gdpr = GDPRDeletionManager()
        gdpr.submit_request("e1", "s1", epoch=1)
        gdpr.submit_request("e2", "s2", epoch=2)
        pending = gdpr.list_pending_requests()
        assert len(pending) == 2

    def test_deletion_with_audit_logger(self):
        logger = ComplianceAuditLogger()
        network, nodes = self._setup_network_with_entity()
        gdpr = GDPRDeletionManager(audit_logger=logger)
        req = gdpr.submit_request("entity-to-delete", "subject-1", epoch=100)
        gdpr.execute_deletion(req.request_id, nodes, epoch=101)

        deletion_events = logger.query(
            event_type=AuditEventType.GDPR_DELETION_COMPLETE
        )
        assert len(deletion_events) == 1

    def test_deletion_nonexistent_request(self):
        gdpr = GDPRDeletionManager()
        result = gdpr.execute_deletion("nonexistent", [], epoch=1)
        assert result is None


# ============================================================================
# HSM Interface
# ============================================================================

class TestSoftwareHSM:
    """Tests for the software HSM implementation."""

    def test_generate_keypair(self):
        hsm = SoftwareHSM()
        result = hsm.generate_keypair("test-key")
        assert "key_id" in result
        assert "public_key" in result
        assert result["label"] == "test-key"

    def test_sign(self):
        hsm = SoftwareHSM()
        result = hsm.generate_keypair("sign-key")
        sig = hsm.sign(result["key_id"], b"test message")
        assert isinstance(sig, bytes)
        assert len(sig) > 0

    def test_destroy_key(self):
        hsm = SoftwareHSM()
        result = hsm.generate_keypair("temp-key")
        assert len(hsm.list_keys()) == 1
        destroyed = hsm.destroy_key(result["key_id"])
        assert destroyed
        assert len(hsm.list_keys()) == 0

    def test_destroy_nonexistent_key(self):
        hsm = SoftwareHSM()
        assert not hsm.destroy_key("nonexistent")

    def test_list_keys(self):
        hsm = SoftwareHSM()
        hsm.generate_keypair("key-1")
        hsm.generate_keypair("key-2")
        keys = hsm.list_keys()
        assert len(keys) == 2

    def test_export_public_key(self):
        hsm = SoftwareHSM()
        result = hsm.generate_keypair("export-key")
        pub = hsm.export_public_key(result["key_id"])
        assert isinstance(pub, bytes)
        assert len(pub) > 0

    def test_sign_nonexistent_key_raises(self):
        hsm = SoftwareHSM()
        with pytest.raises(KeyError):
            hsm.sign("nonexistent", b"test")

    def test_hsm_config(self):
        config = HSMConfig(provider="pkcs11", pkcs11_slot=1)
        hsm = SoftwareHSM(config)
        assert hsm.config.provider == "pkcs11"

    def test_key_label_prefix(self):
        config = HSMConfig(key_label_prefix="prod-")
        hsm = SoftwareHSM(config)
        result = hsm.generate_keypair("my-key")
        assert result["key_id"].startswith("prod-")


# ============================================================================
# Compliance Configuration
# ============================================================================

class TestComplianceConfig:
    """Tests for unified compliance configuration validation."""

    def test_fedramp_requires_fips(self):
        config = ComplianceConfig(
            frameworks={ComplianceFramework.FEDRAMP_MODERATE},
            crypto_mode=CryptoProviderMode.DEFAULT,
        )
        valid, violations = config.validate()
        assert not valid
        assert any("FIPS" in v for v in violations)

    def test_fedramp_requires_rbac(self):
        config = ComplianceConfig(
            frameworks={ComplianceFramework.FEDRAMP_MODERATE},
            crypto_mode=CryptoProviderMode.FIPS,
            enable_rbac=False,
            enable_audit_logging=True,
        )
        valid, violations = config.validate()
        assert not valid
        assert any("RBAC" in v for v in violations)

    def test_soc2_requires_key_rotation(self):
        config = ComplianceConfig(
            frameworks={ComplianceFramework.SOC2_TYPE2},
            enable_rbac=True,
            enable_audit_logging=True,
            enable_key_rotation=False,
        )
        valid, violations = config.validate()
        assert not valid
        assert any("key management" in v for v in violations)

    def test_soc2_valid_config(self):
        config = ComplianceConfig(
            frameworks={ComplianceFramework.SOC2_TYPE2},
            enable_rbac=True,
            enable_audit_logging=True,
            enable_key_rotation=True,
        )
        valid, violations = config.validate()
        assert valid
        assert len(violations) == 0

    def test_gdpr_requires_deletion(self):
        config = ComplianceConfig(
            frameworks={ComplianceFramework.GDPR},
            enable_gdpr_deletion=False,
            enable_audit_logging=True,
        )
        valid, violations = config.validate()
        assert not valid
        assert any("Art. 17" in v for v in violations)

    def test_gdpr_valid_config(self):
        config = ComplianceConfig(
            frameworks={ComplianceFramework.GDPR},
            enable_gdpr_deletion=True,
            enable_audit_logging=True,
        )
        valid, violations = config.validate()
        assert valid

    def test_pci_dss_requires_fips_and_rotation(self):
        config = ComplianceConfig(
            frameworks={ComplianceFramework.PCI_DSS},
            crypto_mode=CryptoProviderMode.DEFAULT,
            enable_key_rotation=False,
        )
        valid, violations = config.validate()
        assert not valid
        assert len(violations) >= 2

    def test_hipaa_requires_rbac_and_audit(self):
        config = ComplianceConfig(
            frameworks={ComplianceFramework.HIPAA},
            enable_rbac=False,
            enable_audit_logging=False,
        )
        valid, violations = config.validate()
        assert not valid
        assert any("164.312(a)" in v for v in violations)

    def test_basel_requires_hsm(self):
        config = ComplianceConfig(
            frameworks={ComplianceFramework.BASEL_III},
            enable_rbac=True,
            hsm_config=None,
        )
        valid, violations = config.validate()
        assert not valid
        assert any("hardware" in v.lower() for v in violations)

    def test_occ_custody_requirements(self):
        config = ComplianceConfig(
            frameworks={ComplianceFramework.OCC_CUSTODY},
            enable_rbac=False,
        )
        valid, violations = config.validate()
        assert not valid

    def test_controls_summary(self):
        config = ComplianceConfig(
            frameworks={ComplianceFramework.SOC2_TYPE2},
            enable_rbac=True,
            enable_audit_logging=True,
            enable_key_rotation=True,
        )
        summary = config.controls_summary()
        assert summary["rbac_enabled"] is True
        assert summary["audit_logging_enabled"] is True
        assert "soc2-type2" in summary["target_frameworks"]

    def test_empty_frameworks_always_valid(self):
        config = ComplianceConfig()
        valid, violations = config.validate()
        assert valid

    def test_multiple_frameworks(self):
        config = ComplianceConfig(
            frameworks={
                ComplianceFramework.SOC2_TYPE2,
                ComplianceFramework.GDPR,
            },
            enable_rbac=True,
            enable_audit_logging=True,
            enable_key_rotation=True,
            enable_gdpr_deletion=True,
        )
        valid, violations = config.validate()
        assert valid


# ============================================================================
# Integration: Audit Logger + Commitment Network
# ============================================================================

class TestComplianceIntegration:
    """Integration tests for compliance features with the commitment network."""

    def test_full_audit_trail(self):
        """End-to-end: nodes, shards, eviction all logged."""
        logger = ComplianceAuditLogger()
        network = CommitmentNetwork()
        network.set_audit_logger(logger)

        # Add nodes
        n1 = network.add_node("n1", "us-east-1")
        n2 = network.add_node("n2", "us-west-2")

        # Distribute shards
        shards = [os.urandom(64) for _ in range(4)]
        network.distribute_encrypted_shards("entity-1", shards)

        # Evict a node
        network.evict_node(n1)

        # Verify audit trail
        assert logger.length >= 4  # 2 registrations + 1 distribution + 1 eviction
        valid, _ = logger.verify_chain_integrity()
        assert valid

        # Check specific events
        reg_events = logger.query(event_type=AuditEventType.NODE_REGISTERED)
        assert len(reg_events) == 2
        evict_events = logger.query(event_type=AuditEventType.NODE_EVICTED)
        assert len(evict_events) == 1

    def test_geo_fence_with_audit(self):
        """Geo-fence + audit logger together."""
        logger = ComplianceAuditLogger()
        network = CommitmentNetwork()
        network.set_audit_logger(logger)
        network.set_geo_fence_policy(
            GeoFencePolicy(allowed_jurisdictions={Jurisdiction.US})
        )

        network.add_node("us1", "us-east-1")
        network.add_node("eu1", "eu-west-1")

        shards = [os.urandom(32) for _ in range(2)]
        network.distribute_encrypted_shards("entity-1", shards)

        # EU node should have no shards
        assert network.nodes[1].shard_count == 0
        # All events logged
        assert logger.length >= 3

    def test_soc2_compliant_setup(self):
        """Verify a SOC 2-compliant deployment configuration."""
        config = ComplianceConfig(
            frameworks={ComplianceFramework.SOC2_TYPE2},
            enable_rbac=True,
            enable_audit_logging=True,
            enable_key_rotation=True,
        )
        valid, violations = config.validate()
        assert valid

        # Set up all components
        logger = ComplianceAuditLogger(retention_epochs=26_280)
        rbac = RBACManager()
        rbac.set_audit_logger(logger)
        rotation = KeyRotationManager(
            policy=KeyRotationPolicy(max_key_age_epochs=8760),
            audit_logger=logger,
        )

        # Create policies
        rbac.create_policy("operator-1", {ComplianceRole.OPERATOR}, epoch=0)
        rbac.create_policy("auditor-1", {ComplianceRole.AUDITOR}, epoch=0)

        # Register keys
        rotation.register_key("operator-1", "fp-op1-v1", epoch=0)

        # Verify audit trail captures everything
        assert logger.length >= 3  # 2 policies + 1 key
        valid, _ = logger.verify_chain_integrity()
        assert valid
