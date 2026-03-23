// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ILTPAnchorRegistry} from "../src/interfaces/ILTPAnchorRegistry.sol";
import {LTPAnchorRegistry} from "../src/LTPAnchorRegistry.sol";
import {LTPMultiSig} from "../src/LTPMultiSig.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {TestSetup} from "./helpers/TestSetup.sol";

// ==========================================================================
// Core anchoring tests (through UUPS proxy, with entityIdHash)
// ==========================================================================

contract LTPAnchorRegistryTest is TestSetup {
    // 1. Happy path
    function test_anchor_happyPath() public {
        bytes32 digest = _digest(1);
        bytes32 entityId = _entityId(1);
        uint64 validUntil = uint64(block.timestamp + 3600);

        registry.anchor(digest, entityId, _merkleRoot(1), _policyHash(1), signerVkHash, 1, validUntil, 0);

        assertTrue(registry.isAnchored(digest));
        assertEq(registry.getEntityState(entityId), registry.STATE_ANCHORED());
        assertEq(registry.getSignerSequence(signerVkHash), 1);

        ILTPAnchorRegistry.AnchorRecord memory rec = registry.getAnchorRecord(digest);
        assertEq(rec.merkleRoot, _merkleRoot(1));
        assertEq(rec.policyHash, _policyHash(1));
        assertEq(rec.signerVkHash, signerVkHash);
        assertEq(rec.entityIdHash, entityId);
        assertEq(rec.sequence, 1);
        assertEq(rec.receiptType, 0);
        assertEq(rec.entityState, registry.STATE_ANCHORED());
        assertGt(rec.anchoredAt, 0);
    }

    // 2. Entity ID tracks state independently from anchor digest
    function test_anchor_entityIdSeparation() public {
        bytes32 entityId = _entityId(50);
        uint64 validUntil = uint64(block.timestamp + 3600);

        // Two different anchors for the same entity — first succeeds (UNKNOWN → ANCHORED)
        registry.anchor(_digest(50), entityId, _merkleRoot(50), _policyHash(50), signerVkHash, 1, validUntil, 0);
        assertEq(registry.getEntityState(entityId), registry.STATE_ANCHORED());

        // Second anchor for same entity reverts — ANCHORED → ANCHORED is not valid
        vm.expectRevert(
            abi.encodeWithSelector(
                ILTPAnchorRegistry.InvalidStateTransition.selector,
                registry.STATE_ANCHORED(),
                registry.STATE_ANCHORED()
            )
        );
        registry.anchor(_digest(51), entityId, _merkleRoot(51), _policyHash(51), signerVkHash, 2, validUntil, 0);
    }

    // 3. Replay rejection
    function test_anchor_replayRejected() public {
        bytes32 digest = _digest(2);
        uint64 validUntil = uint64(block.timestamp + 3600);
        registry.anchor(digest, _entityId(2), _merkleRoot(2), _policyHash(2), signerVkHash, 1, validUntil, 0);

        vm.expectRevert(abi.encodeWithSelector(ILTPAnchorRegistry.AlreadyAnchored.selector, digest));
        registry.anchor(digest, _entityId(99), _merkleRoot(2), _policyHash(2), signerVkHash, 2, validUntil, 0);
    }

    // 4. Sequence enforcement
    function test_anchor_sequenceTooLow() public {
        uint64 validUntil = uint64(block.timestamp + 3600);
        registry.anchor(_digest(3), _entityId(3), _merkleRoot(3), _policyHash(3), signerVkHash, 5, validUntil, 0);

        vm.expectRevert(
            abi.encodeWithSelector(ILTPAnchorRegistry.SequenceTooLow.selector, signerVkHash, 3, 5)
        );
        registry.anchor(_digest(4), _entityId(4), _merkleRoot(4), _policyHash(4), signerVkHash, 3, validUntil, 0);
    }

    function test_anchor_sequenceEqualReverts() public {
        uint64 validUntil = uint64(block.timestamp + 3600);
        registry.anchor(_digest(5), _entityId(5), _merkleRoot(5), _policyHash(5), signerVkHash, 1, validUntil, 0);

        vm.expectRevert(
            abi.encodeWithSelector(ILTPAnchorRegistry.SequenceTooLow.selector, signerVkHash, 1, 1)
        );
        registry.anchor(_digest(6), _entityId(6), _merkleRoot(6), _policyHash(6), signerVkHash, 1, validUntil, 0);
    }

    // 5. Temporal expiry
    function test_anchor_expired() public {
        uint64 validUntil = uint64(block.timestamp - 1);
        vm.expectRevert(
            abi.encodeWithSelector(ILTPAnchorRegistry.Expired.selector, validUntil, uint64(block.timestamp))
        );
        registry.anchor(_digest(7), _entityId(7), _merkleRoot(7), _policyHash(7), signerVkHash, 1, validUntil, 0);
    }

    function test_anchor_expiresAtCurrentTimestamp() public {
        uint64 validUntil = uint64(block.timestamp);
        vm.expectRevert(
            abi.encodeWithSelector(ILTPAnchorRegistry.Expired.selector, validUntil, uint64(block.timestamp))
        );
        registry.anchor(_digest(8), _entityId(8), _merkleRoot(8), _policyHash(8), signerVkHash, 1, validUntil, 0);
    }

    // 6. Signer authorization
    function test_anchor_unauthorizedSigner() public {
        bytes32 unknownSigner = keccak256("unknown-signer");
        uint64 validUntil = uint64(block.timestamp + 3600);
        vm.expectRevert(
            abi.encodeWithSelector(ILTPAnchorRegistry.UnauthorizedSigner.selector, unknownSigner)
        );
        registry.anchor(_digest(9), _entityId(9), _merkleRoot(9), _policyHash(9), unknownSigner, 1, validUntil, 0);
    }

    function test_anchor_revokedSigner() public {
        vm.prank(admin);
        registry.revokeSigner(signerVkHash);
        uint64 validUntil = uint64(block.timestamp + 3600);
        vm.expectRevert(
            abi.encodeWithSelector(ILTPAnchorRegistry.UnauthorizedSigner.selector, signerVkHash)
        );
        registry.anchor(_digest(10), _entityId(10), _merkleRoot(10), _policyHash(10), signerVkHash, 1, validUntil, 0);
    }

    // 7. Batch anchoring
    function test_batchAnchor_10items() public {
        uint256 count = 10;
        bytes32[] memory digests = new bytes32[](count);
        bytes32[] memory entityIds = new bytes32[](count);
        bytes32[] memory roots = new bytes32[](count);
        bytes32[] memory policies = new bytes32[](count);
        bytes32[] memory signers = new bytes32[](count);
        uint64[]  memory seqs = new uint64[](count);
        uint64[]  memory expiries = new uint64[](count);
        uint8[]   memory types = new uint8[](count);
        uint64 validUntil = uint64(block.timestamp + 3600);

        for (uint256 i = 0; i < count; i++) {
            digests[i]   = _digest(100 + i);
            entityIds[i] = _entityId(100 + i);
            roots[i]     = _merkleRoot(100 + i);
            policies[i]  = _policyHash(100 + i);
            signers[i]   = signerVkHash;
            seqs[i]      = uint64(i + 1);
            expiries[i]  = validUntil;
            types[i]     = 0;
        }

        registry.batchAnchor(digests, entityIds, roots, policies, signers, seqs, expiries, types);

        for (uint256 i = 0; i < count; i++) {
            assertTrue(registry.isAnchored(digests[i]));
        }
        assertEq(registry.getSignerSequence(signerVkHash), 10);
    }

    function test_batchAnchor_emptyReverts() public {
        bytes32[] memory empty;
        uint64[]  memory emptyU64;
        uint8[]   memory emptyU8;
        vm.expectRevert(abi.encodeWithSelector(ILTPAnchorRegistry.EmptyBatch.selector));
        registry.batchAnchor(empty, empty, empty, empty, empty, emptyU64, emptyU64, emptyU8);
    }

    // 8. Admin access control
    function test_registerSigner_nonAdminReverts() public {
        vm.prank(nonAdmin);
        vm.expectRevert(abi.encodeWithSelector(ILTPAnchorRegistry.NotAdmin.selector, nonAdmin));
        registry.registerSigner(signerVkHash2);
    }

    function test_revokeSigner_nonAdminReverts() public {
        vm.prank(nonAdmin);
        vm.expectRevert(abi.encodeWithSelector(ILTPAnchorRegistry.NotAdmin.selector, nonAdmin));
        registry.revokeSigner(signerVkHash);
    }

    function test_registerSigner_adminSucceeds() public {
        vm.prank(admin);
        registry.registerSigner(signerVkHash2);
        assertTrue(registry.authorizedSigners(signerVkHash2));
    }

    // 9. Multiple signers
    function test_multipleSignersIndependentSequences() public {
        vm.prank(admin);
        registry.registerSigner(signerVkHash2);
        uint64 validUntil = uint64(block.timestamp + 3600);

        registry.anchor(_digest(20), _entityId(20), _merkleRoot(20), _policyHash(20), signerVkHash, 5, validUntil, 0);
        registry.anchor(_digest(21), _entityId(21), _merkleRoot(21), _policyHash(21), signerVkHash2, 1, validUntil, 0);

        assertEq(registry.getSignerSequence(signerVkHash), 5);
        assertEq(registry.getSignerSequence(signerVkHash2), 1);
    }

    // 10. View defaults
    function test_isAnchored_unknown() public view {
        assertFalse(registry.isAnchored(bytes32(0)));
    }

    function test_getEntityState_defaultUnknown() public view {
        assertEq(registry.getEntityState(keccak256("nonexistent")), registry.STATE_UNKNOWN());
    }

    // 11. Version
    function test_version() public view {
        assertEq(registry.version(), 3);
    }
}

// ==========================================================================
// Pause tests
// ==========================================================================

contract PauseTest is TestSetup {
    function test_pause_blocksAnchor() public {
        vm.prank(admin);
        registry.pause();
        assertTrue(registry.paused());

        uint64 validUntil = uint64(block.timestamp + 3600);
        vm.expectRevert(abi.encodeWithSelector(ILTPAnchorRegistry.ContractPaused.selector));
        registry.anchor(_digest(1), _entityId(1), _merkleRoot(1), _policyHash(1), signerVkHash, 1, validUntil, 0);
    }

    function test_pause_blocksBatchAnchor() public {
        vm.prank(admin);
        registry.pause();

        bytes32[] memory d = new bytes32[](1);
        bytes32[] memory e = new bytes32[](1);
        bytes32[] memory r = new bytes32[](1);
        bytes32[] memory p = new bytes32[](1);
        bytes32[] memory s = new bytes32[](1);
        uint64[]  memory sq = new uint64[](1);
        uint64[]  memory ex = new uint64[](1);
        uint8[]   memory ty = new uint8[](1);
        d[0] = _digest(1); e[0] = _entityId(1); r[0] = _merkleRoot(1); p[0] = _policyHash(1);
        s[0] = signerVkHash; sq[0] = 1; ex[0] = uint64(block.timestamp + 3600); ty[0] = 0;

        vm.expectRevert(abi.encodeWithSelector(ILTPAnchorRegistry.ContractPaused.selector));
        registry.batchAnchor(d, e, r, p, s, sq, ex, ty);
    }

    function test_pause_blocksTransitionState() public {
        // Anchor first, then pause, then try to transition
        uint64 validUntil = uint64(block.timestamp + 3600);
        registry.anchor(_digest(1), _entityId(1), _merkleRoot(1), _policyHash(1), signerVkHash, 1, validUntil, 0);

        uint8 stateMaterialized = registry.STATE_MATERIALIZED();

        vm.prank(admin);
        registry.pause();

        vm.expectRevert(abi.encodeWithSelector(ILTPAnchorRegistry.ContractPaused.selector));
        registry.transitionState(_entityId(1), stateMaterialized, signerVkHash, 2, validUntil);
    }

    function test_unpause_restoresAnchoring() public {
        vm.prank(admin);
        registry.pause();

        vm.prank(admin);
        registry.unpause();
        assertFalse(registry.paused());

        uint64 validUntil = uint64(block.timestamp + 3600);
        registry.anchor(_digest(1), _entityId(1), _merkleRoot(1), _policyHash(1), signerVkHash, 1, validUntil, 0);
        assertTrue(registry.isAnchored(_digest(1)));
    }

    function test_pause_nonAdminReverts() public {
        vm.prank(nonAdmin);
        vm.expectRevert(abi.encodeWithSelector(ILTPAnchorRegistry.NotAdmin.selector, nonAdmin));
        registry.pause();
    }

    function test_pause_doesNotBlockViews() public {
        uint64 validUntil = uint64(block.timestamp + 3600);
        registry.anchor(_digest(1), _entityId(1), _merkleRoot(1), _policyHash(1), signerVkHash, 1, validUntil, 0);

        vm.prank(admin);
        registry.pause();

        // Views still work
        assertTrue(registry.isAnchored(_digest(1)));
        assertEq(registry.getSignerSequence(signerVkHash), 1);
        assertEq(registry.getEntityState(_entityId(1)), registry.STATE_ANCHORED());
    }
}

// ==========================================================================
// transitionState tests
// ==========================================================================

contract TransitionStateTest is TestSetup {
    bytes32 entityId;
    uint64 validUntil;

    function setUp() public override {
        super.setUp();
        entityId = _entityId(1);
        validUntil = uint64(block.timestamp + 3600);

        // Anchor an entity first (UNKNOWN → ANCHORED)
        registry.anchor(_digest(1), entityId, _merkleRoot(1), _policyHash(1), signerVkHash, 1, validUntil, 0);
    }

    function test_transitionState_anchoredToMaterialized() public {
        registry.transitionState(entityId, registry.STATE_MATERIALIZED(), signerVkHash, 2, validUntil);
        assertEq(registry.getEntityState(entityId), registry.STATE_MATERIALIZED());
        assertEq(registry.getSignerSequence(signerVkHash), 2);
    }

    function test_transitionState_anchoredToDisputed() public {
        registry.transitionState(entityId, registry.STATE_DISPUTED(), signerVkHash, 2, validUntil);
        assertEq(registry.getEntityState(entityId), registry.STATE_DISPUTED());
    }

    function test_transitionState_materializedToDeleted() public {
        registry.transitionState(entityId, registry.STATE_MATERIALIZED(), signerVkHash, 2, validUntil);
        registry.transitionState(entityId, registry.STATE_DELETED(), signerVkHash, 3, validUntil);
        assertEq(registry.getEntityState(entityId), registry.STATE_DELETED());
    }

    function test_transitionState_disputedToDeleted() public {
        registry.transitionState(entityId, registry.STATE_DISPUTED(), signerVkHash, 2, validUntil);
        registry.transitionState(entityId, registry.STATE_DELETED(), signerVkHash, 3, validUntil);
        assertEq(registry.getEntityState(entityId), registry.STATE_DELETED());
    }

    function test_transitionState_fullLifecycle() public {
        // ANCHORED → MATERIALIZED → DISPUTED → DELETED
        registry.transitionState(entityId, registry.STATE_MATERIALIZED(), signerVkHash, 2, validUntil);
        registry.transitionState(entityId, registry.STATE_DISPUTED(), signerVkHash, 3, validUntil);
        registry.transitionState(entityId, registry.STATE_DELETED(), signerVkHash, 4, validUntil);
        assertEq(registry.getEntityState(entityId), registry.STATE_DELETED());
        assertEq(registry.getSignerSequence(signerVkHash), 4);
    }

    function test_transitionState_invalidTransitionReverts() public {
        // ANCHORED → COMMITTED is not valid
        uint8 stateAnchored = registry.STATE_ANCHORED();
        uint8 stateCommitted = registry.STATE_COMMITTED();
        vm.expectRevert(
            abi.encodeWithSelector(
                ILTPAnchorRegistry.InvalidStateTransition.selector,
                stateAnchored,
                stateCommitted
            )
        );
        registry.transitionState(entityId, stateCommitted, signerVkHash, 2, validUntil);
    }

    function test_transitionState_unauthorizedSignerReverts() public {
        bytes32 unknownSigner = keccak256("unknown-signer");
        uint8 stateMaterialized = registry.STATE_MATERIALIZED();
        vm.expectRevert(
            abi.encodeWithSelector(ILTPAnchorRegistry.UnauthorizedSigner.selector, unknownSigner)
        );
        registry.transitionState(entityId, stateMaterialized, unknownSigner, 2, validUntil);
    }

    function test_transitionState_sequenceTooLowReverts() public {
        // Signer already at sequence 1 from the anchor call
        uint8 stateMaterialized = registry.STATE_MATERIALIZED();
        vm.expectRevert(
            abi.encodeWithSelector(ILTPAnchorRegistry.SequenceTooLow.selector, signerVkHash, 1, 1)
        );
        registry.transitionState(entityId, stateMaterialized, signerVkHash, 1, validUntil);
    }

    function test_transitionState_expiredReverts() public {
        uint8 stateMaterialized = registry.STATE_MATERIALIZED();
        uint64 pastExpiry = uint64(block.timestamp - 1);
        vm.expectRevert(
            abi.encodeWithSelector(ILTPAnchorRegistry.Expired.selector, pastExpiry, uint64(block.timestamp))
        );
        registry.transitionState(entityId, stateMaterialized, signerVkHash, 2, pastExpiry);
    }

    function test_transitionState_committedToAnchored() public {
        // Create a new entity, transition to COMMITTED, then to ANCHORED via transitionState
        bytes32 entityId2 = _entityId(200);
        registry.transitionState(entityId2, registry.STATE_COMMITTED(), signerVkHash, 2, validUntil);
        assertEq(registry.getEntityState(entityId2), registry.STATE_COMMITTED());

        registry.transitionState(entityId2, registry.STATE_ANCHORED(), signerVkHash, 3, validUntil);
        assertEq(registry.getEntityState(entityId2), registry.STATE_ANCHORED());
    }

    function test_transitionState_emitsEvents() public {
        vm.expectEmit(true, true, false, true);
        emit ILTPAnchorRegistry.StateTransitioned(
            entityId,
            signerVkHash,
            registry.STATE_ANCHORED(),
            registry.STATE_MATERIALIZED(),
            2
        );

        vm.expectEmit(true, false, false, true);
        emit ILTPAnchorRegistry.StateTransition(
            entityId,
            registry.STATE_ANCHORED(),
            registry.STATE_MATERIALIZED()
        );

        registry.transitionState(entityId, registry.STATE_MATERIALIZED(), signerVkHash, 2, validUntil);
    }
}

// ==========================================================================
// Batch query tests
// ==========================================================================

contract BatchQueryTest is TestSetup {
    function test_areAnchored_mixed() public {
        uint64 validUntil = uint64(block.timestamp + 3600);
        bytes32 d1 = _digest(1);
        bytes32 d2 = _digest(2);
        bytes32 d3 = _digest(3);

        // Only anchor d1 and d3
        registry.anchor(d1, _entityId(1), _merkleRoot(1), _policyHash(1), signerVkHash, 1, validUntil, 0);
        registry.anchor(d3, _entityId(3), _merkleRoot(3), _policyHash(3), signerVkHash, 2, validUntil, 0);

        bytes32[] memory digests = new bytes32[](3);
        digests[0] = d1;
        digests[1] = d2;
        digests[2] = d3;

        bool[] memory results = registry.areAnchored(digests);
        assertTrue(results[0]);
        assertFalse(results[1]);
        assertTrue(results[2]);
    }

    function test_getEntityStates_batch() public {
        uint64 validUntil = uint64(block.timestamp + 3600);
        bytes32 e1 = _entityId(1);
        bytes32 e2 = _entityId(2);
        bytes32 e3 = _entityId(3);

        // e1: ANCHORED, e2: UNKNOWN (never touched), e3: ANCHORED → MATERIALIZED
        registry.anchor(_digest(1), e1, _merkleRoot(1), _policyHash(1), signerVkHash, 1, validUntil, 0);
        registry.anchor(_digest(3), e3, _merkleRoot(3), _policyHash(3), signerVkHash, 2, validUntil, 0);
        registry.transitionState(e3, registry.STATE_MATERIALIZED(), signerVkHash, 3, validUntil);

        bytes32[] memory entityIds = new bytes32[](3);
        entityIds[0] = e1;
        entityIds[1] = e2;
        entityIds[2] = e3;

        uint8[] memory states = registry.getEntityStates(entityIds);
        assertEq(states[0], registry.STATE_ANCHORED());
        assertEq(states[1], registry.STATE_UNKNOWN());
        assertEq(states[2], registry.STATE_MATERIALIZED());
    }

    function test_getAnchorRecords_batch() public {
        uint64 validUntil = uint64(block.timestamp + 3600);
        bytes32 d1 = _digest(1);
        bytes32 d2 = _digest(2);

        registry.anchor(d1, _entityId(1), _merkleRoot(1), _policyHash(1), signerVkHash, 1, validUntil, 0);
        registry.anchor(d2, _entityId(2), _merkleRoot(2), _policyHash(2), signerVkHash, 2, validUntil, 1);

        bytes32[] memory digests = new bytes32[](2);
        digests[0] = d1;
        digests[1] = d2;

        ILTPAnchorRegistry.AnchorRecord[] memory records = registry.getAnchorRecords(digests);
        assertEq(records[0].merkleRoot, _merkleRoot(1));
        assertEq(records[0].entityIdHash, _entityId(1));
        assertEq(records[0].receiptType, 0);
        assertEq(records[1].merkleRoot, _merkleRoot(2));
        assertEq(records[1].entityIdHash, _entityId(2));
        assertEq(records[1].receiptType, 1);
    }

    function test_areAnchored_empty() public view {
        bytes32[] memory empty;
        bool[] memory results = registry.areAnchored(empty);
        assertEq(results.length, 0);
    }
}

// ==========================================================================
// Upgrade tests
// ==========================================================================

contract UpgradeTest is TestSetup {
    function test_upgrade_preservesState() public {
        // Anchor something before upgrade
        uint64 validUntil = uint64(block.timestamp + 3600);
        registry.anchor(_digest(1), _entityId(1), _merkleRoot(1), _policyHash(1), signerVkHash, 1, validUntil, 0);
        assertTrue(registry.isAnchored(_digest(1)));

        // Deploy new implementation
        LTPAnchorRegistry newImpl = new LTPAnchorRegistry();

        // Upgrade (admin only via UUPS)
        vm.prank(admin);
        UUPSUpgradeable(address(registry)).upgradeToAndCall(address(newImpl), "");

        // State is preserved
        assertTrue(registry.isAnchored(_digest(1)));
        assertEq(registry.getSignerSequence(signerVkHash), 1);
        assertEq(registry.admin(), admin);
        assertTrue(registry.authorizedSigners(signerVkHash));
        assertEq(registry.getEntityState(_entityId(1)), registry.STATE_ANCHORED());
    }

    function test_upgrade_nonAdminReverts() public {
        LTPAnchorRegistry newImpl = new LTPAnchorRegistry();

        vm.prank(nonAdmin);
        vm.expectRevert();
        UUPSUpgradeable(address(registry)).upgradeToAndCall(address(newImpl), "");
    }

    function test_implementationCannotBeInitialized() public {
        vm.expectRevert();
        implementation.initialize(admin);
    }
}

// ==========================================================================
// Admin transfer tests
// ==========================================================================

contract AdminTransferTest is TestSetup {
    function test_transferAdmin() public {
        address newAdmin = address(0xCAFE);
        vm.prank(admin);
        registry.transferAdmin(newAdmin);
        assertEq(registry.admin(), newAdmin);

        // Old admin can no longer act
        vm.prank(admin);
        vm.expectRevert(abi.encodeWithSelector(ILTPAnchorRegistry.NotAdmin.selector, admin));
        registry.registerSigner(signerVkHash2);

        // New admin can act
        vm.prank(newAdmin);
        registry.registerSigner(signerVkHash2);
        assertTrue(registry.authorizedSigners(signerVkHash2));
    }

    function test_transferAdmin_zeroReverts() public {
        vm.prank(admin);
        vm.expectRevert(abi.encodeWithSelector(ILTPAnchorRegistry.NotAdmin.selector, address(0)));
        registry.transferAdmin(address(0));
    }
}

// ==========================================================================
// Multi-sig tests
// ==========================================================================

contract MultiSigTest is TestSetup {
    LTPMultiSig public multisig;

    address public owner1 = address(0x1001);
    address public owner2 = address(0x1002);
    address public owner3 = address(0x1003);

    function setUp() public override {
        super.setUp();

        // Deploy 2-of-3 multi-sig
        address[] memory owners = new address[](3);
        owners[0] = owner1;
        owners[1] = owner2;
        owners[2] = owner3;
        multisig = new LTPMultiSig(owners, 2);

        // Transfer registry admin to multi-sig
        vm.prank(admin);
        registry.transferAdmin(address(multisig));
    }

    function test_multisig_registerSigner() public {
        // Owner1 submits registerSigner tx (auto-confirms)
        bytes memory data = abi.encodeCall(LTPAnchorRegistry.registerSigner, (signerVkHash2));
        vm.prank(owner1);
        uint256 txId = multisig.submitTransaction(address(registry), 0, data);

        // Only 1 confirmation — not enough
        vm.prank(owner1);
        vm.expectRevert(
            abi.encodeWithSelector(LTPMultiSig.InsufficientConfirmations.selector, txId, 1, 2)
        );
        multisig.executeTransaction(txId);

        // Owner2 confirms — now we have 2-of-3
        vm.prank(owner2);
        multisig.confirmTransaction(txId);

        // Execute
        vm.prank(owner1);
        multisig.executeTransaction(txId);

        assertTrue(registry.authorizedSigners(signerVkHash2));
    }

    function test_multisig_pause() public {
        bytes memory data = abi.encodeCall(LTPAnchorRegistry.pause, ());

        vm.prank(owner1);
        uint256 txId = multisig.submitTransaction(address(registry), 0, data);

        vm.prank(owner3);
        multisig.confirmTransaction(txId);

        vm.prank(owner2);
        multisig.executeTransaction(txId);

        assertTrue(registry.paused());
    }

    function test_multisig_upgrade() public {
        LTPAnchorRegistry newImpl = new LTPAnchorRegistry();

        bytes memory data = abi.encodeCall(
            UUPSUpgradeable.upgradeToAndCall, (address(newImpl), "")
        );

        vm.prank(owner1);
        uint256 txId = multisig.submitTransaction(address(registry), 0, data);

        vm.prank(owner2);
        multisig.confirmTransaction(txId);

        vm.prank(owner3);
        multisig.executeTransaction(txId);

        // Verify upgrade succeeded — version still accessible
        assertEq(registry.version(), 3);
    }

    function test_multisig_nonOwnerReverts() public {
        bytes memory data = abi.encodeCall(LTPAnchorRegistry.pause, ());
        vm.prank(nonAdmin);
        vm.expectRevert(abi.encodeWithSelector(LTPMultiSig.NotOwner.selector, nonAdmin));
        multisig.submitTransaction(address(registry), 0, data);
    }

    function test_multisig_revokeConfirmation() public {
        bytes memory data = abi.encodeCall(LTPAnchorRegistry.pause, ());

        vm.prank(owner1);
        uint256 txId = multisig.submitTransaction(address(registry), 0, data);

        // Owner1 revokes their confirmation
        vm.prank(owner1);
        multisig.revokeConfirmation(txId);

        // Now 0 confirmations — can't execute
        vm.prank(owner1);
        vm.expectRevert(
            abi.encodeWithSelector(LTPMultiSig.InsufficientConfirmations.selector, txId, 0, 2)
        );
        multisig.executeTransaction(txId);
    }

    function test_multisig_cannotDoubleExecute() public {
        bytes memory data = abi.encodeCall(LTPAnchorRegistry.pause, ());

        vm.prank(owner1);
        uint256 txId = multisig.submitTransaction(address(registry), 0, data);

        vm.prank(owner2);
        multisig.confirmTransaction(txId);

        vm.prank(owner1);
        multisig.executeTransaction(txId);

        vm.prank(owner1);
        vm.expectRevert(abi.encodeWithSelector(LTPMultiSig.TxAlreadyExecuted.selector, txId));
        multisig.executeTransaction(txId);
    }
}

// ==========================================================================
// Event indexing tests
// ==========================================================================

contract EventIndexingTest is TestSetup {
    function test_anchor_emitsAnchoredWithEntityId() public {
        bytes32 digest = _digest(1);
        bytes32 entityId = _entityId(1);
        uint64 validUntil = uint64(block.timestamp + 3600);

        vm.expectEmit(true, true, true, true);
        emit ILTPAnchorRegistry.Anchored(digest, entityId, signerVkHash, 1);

        registry.anchor(digest, entityId, _merkleRoot(1), _policyHash(1), signerVkHash, 1, validUntil, 0);
    }

    function test_anchor_emitsStateTransition() public {
        bytes32 entityId = _entityId(1);
        uint64 validUntil = uint64(block.timestamp + 3600);

        vm.expectEmit(true, false, false, true);
        emit ILTPAnchorRegistry.StateTransition(
            entityId,
            registry.STATE_UNKNOWN(),
            registry.STATE_ANCHORED()
        );

        registry.anchor(_digest(1), entityId, _merkleRoot(1), _policyHash(1), signerVkHash, 1, validUntil, 0);
    }

    function test_batchAnchor_emitsBatchAnchored() public {
        uint256 count = 3;
        bytes32[] memory digests = new bytes32[](count);
        bytes32[] memory entityIds = new bytes32[](count);
        bytes32[] memory roots = new bytes32[](count);
        bytes32[] memory policies = new bytes32[](count);
        bytes32[] memory signers = new bytes32[](count);
        uint64[]  memory seqs = new uint64[](count);
        uint64[]  memory expiries = new uint64[](count);
        uint8[]   memory types = new uint8[](count);
        uint64 validUntil = uint64(block.timestamp + 3600);

        for (uint256 i = 0; i < count; i++) {
            digests[i]   = _digest(200 + i);
            entityIds[i] = _entityId(200 + i);
            roots[i]     = _merkleRoot(200 + i);
            policies[i]  = _policyHash(200 + i);
            signers[i]   = signerVkHash;
            seqs[i]      = uint64(i + 1);
            expiries[i]  = validUntil;
            types[i]     = 0;
        }

        vm.expectEmit(false, true, false, true);
        emit ILTPAnchorRegistry.BatchAnchored(count, digests[0]);

        registry.batchAnchor(digests, entityIds, roots, policies, signers, seqs, expiries, types);
    }
}
