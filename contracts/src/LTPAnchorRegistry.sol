// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ILTPAnchorRegistry} from "./interfaces/ILTPAnchorRegistry.sol";

/// @title LTPAnchorRegistry
/// @notice On-chain registry for LTP anchor digests with state machine,
///         per-signer sequencing, and signer authorization.
/// @dev Thin on-chain, thick off-chain. No PQ signature verification on-chain
///      (ML-DSA-65 sigs are 3309B — hundreds of thousands of gas). The contract
///      is a registry of 32-byte digests with access control and sequencing.
///      All signature/proof verification happens off-chain via the Verification SDK.
contract LTPAnchorRegistry is ILTPAnchorRegistry {
    // -----------------------------------------------------------------------
    // Constants — EntityState enum mirrors Python src/ltp/anchor/state.py
    // -----------------------------------------------------------------------

    uint8 public constant STATE_UNKNOWN       = 0;
    uint8 public constant STATE_COMMITTED     = 1;
    uint8 public constant STATE_ANCHORED      = 2;
    uint8 public constant STATE_MATERIALIZED  = 3;
    uint8 public constant STATE_DISPUTED      = 4;
    uint8 public constant STATE_DELETED        = 5;

    // -----------------------------------------------------------------------
    // Storage
    // -----------------------------------------------------------------------

    address public admin;

    /// @notice anchorDigest => AnchorRecord
    mapping(bytes32 => AnchorRecord) private _anchors;

    /// @notice signerVkHash => highest accepted sequence number
    mapping(bytes32 => uint64) public signerSequences;

    /// @notice entityIdHash => EntityState (uint8)
    mapping(bytes32 => uint8) public entityStates;

    /// @notice signerVkHash => authorized flag
    mapping(bytes32 => bool) public authorizedSigners;

    // -----------------------------------------------------------------------
    // Constructor
    // -----------------------------------------------------------------------

    constructor(address _admin) {
        admin = _admin;
    }

    // -----------------------------------------------------------------------
    // Modifiers
    // -----------------------------------------------------------------------

    modifier onlyAdmin() {
        if (msg.sender != admin) revert NotAdmin(msg.sender);
        _;
    }

    // -----------------------------------------------------------------------
    // Write functions
    // -----------------------------------------------------------------------

    /// @inheritdoc ILTPAnchorRegistry
    function anchor(
        bytes32 anchorDigest,
        bytes32 merkleRoot,
        bytes32 policyHash,
        bytes32 signerVkHash,
        uint64  sequence,
        uint64  validUntil,
        uint8   receiptType
    ) external {
        _anchor(
            anchorDigest,
            merkleRoot,
            policyHash,
            signerVkHash,
            sequence,
            validUntil,
            receiptType
        );
    }

    /// @inheritdoc ILTPAnchorRegistry
    function batchAnchor(
        bytes32[] calldata anchorDigests,
        bytes32[] calldata merkleRoots,
        bytes32[] calldata policyHashes,
        bytes32[] calldata signerVkHashes,
        uint64[]  calldata sequences,
        uint64[]  calldata validUntils,
        uint8[]   calldata receiptTypes
    ) external {
        uint256 len = anchorDigests.length;
        if (len == 0) revert EmptyBatch();
        // All arrays must have the same length — checked implicitly by access
        for (uint256 i = 0; i < len; ++i) {
            _anchor(
                anchorDigests[i],
                merkleRoots[i],
                policyHashes[i],
                signerVkHashes[i],
                sequences[i],
                validUntils[i],
                receiptTypes[i]
            );
        }

        emit BatchAnchored(len, anchorDigests[0]);
    }

    /// @inheritdoc ILTPAnchorRegistry
    function registerSigner(bytes32 vkHash) external onlyAdmin {
        authorizedSigners[vkHash] = true;
        emit SignerRegistered(vkHash);
    }

    /// @inheritdoc ILTPAnchorRegistry
    function revokeSigner(bytes32 vkHash) external onlyAdmin {
        authorizedSigners[vkHash] = false;
        emit SignerRevoked(vkHash);
    }

    // -----------------------------------------------------------------------
    // View functions
    // -----------------------------------------------------------------------

    /// @inheritdoc ILTPAnchorRegistry
    function isAnchored(bytes32 anchorDigest) external view returns (bool) {
        return _anchors[anchorDigest].anchoredAt != 0;
    }

    /// @inheritdoc ILTPAnchorRegistry
    function getEntityState(bytes32 entityIdHash) external view returns (uint8) {
        return entityStates[entityIdHash];
    }

    /// @inheritdoc ILTPAnchorRegistry
    function getSignerSequence(bytes32 vkHash) external view returns (uint64) {
        return signerSequences[vkHash];
    }

    /// @inheritdoc ILTPAnchorRegistry
    function getAnchorRecord(bytes32 anchorDigest) external view returns (AnchorRecord memory) {
        return _anchors[anchorDigest];
    }

    // -----------------------------------------------------------------------
    // Internal
    // -----------------------------------------------------------------------

    /// @dev Core anchoring logic shared by anchor() and batchAnchor().
    function _anchor(
        bytes32 anchorDigest,
        bytes32 merkleRoot,
        bytes32 policyHash,
        bytes32 signerVkHash,
        uint64  sequence,
        uint64  validUntil,
        uint8   receiptType
    ) internal {
        // 1. Replay rejection: same anchorDigest cannot be anchored twice
        if (_anchors[anchorDigest].anchoredAt != 0) {
            revert AlreadyAnchored(anchorDigest);
        }

        // 2. Signer authorization (mirrors governance.py:143-173)
        if (!authorizedSigners[signerVkHash]) {
            revert UnauthorizedSigner(signerVkHash);
        }

        // 3. Sequence monotonicity (mirrors sequencing.py:68-74)
        uint64 currentSeq = signerSequences[signerVkHash];
        if (sequence <= currentSeq) {
            revert SequenceTooLow(signerVkHash, sequence, currentSeq);
        }

        // 4. Temporal expiry (mirrors sequencing.py:65-66)
        if (uint64(block.timestamp) >= validUntil) {
            revert Expired(validUntil, uint64(block.timestamp));
        }

        // 5. State transition: UNKNOWN → ANCHORED
        //    The entity is identified by the anchorDigest for state tracking.
        //    In practice, the entityIdHash would be derived off-chain and passed
        //    separately. For MVP, we use anchorDigest as the entity identifier.
        uint8 currentState = entityStates[anchorDigest];
        uint8 newState = STATE_ANCHORED;
        if (!_isValidTransition(currentState, newState)) {
            revert InvalidStateTransition(currentState, newState);
        }

        // 6. Store the anchor record
        _anchors[anchorDigest] = AnchorRecord({
            merkleRoot:    merkleRoot,
            policyHash:    policyHash,
            signerVkHash:  signerVkHash,
            sequence:      sequence,
            validUntil:    validUntil,
            targetChainId: uint64(block.chainid),
            receiptType:   receiptType,
            entityState:   newState,
            anchoredAt:    uint64(block.timestamp)
        });

        // 7. Update signer sequence HWM
        signerSequences[signerVkHash] = sequence;

        // 8. Update entity state
        entityStates[anchorDigest] = newState;

        emit Anchored(anchorDigest, signerVkHash, sequence);
        emit StateTransition(anchorDigest, currentState, newState);
    }

    /// @dev Validate entity state transitions. Mirrors Python state.py:37-51.
    ///      VALID_TRANSITIONS frozenset reproduced as boolean logic.
    function _isValidTransition(uint8 from_, uint8 to_) internal pure returns (bool) {
        // Happy path
        if (from_ == STATE_UNKNOWN   && to_ == STATE_COMMITTED)    return true;
        if (from_ == STATE_COMMITTED && to_ == STATE_ANCHORED)     return true;
        if (from_ == STATE_ANCHORED  && to_ == STATE_MATERIALIZED) return true;

        // Dispute path (from any active state)
        if (from_ == STATE_COMMITTED    && to_ == STATE_DISPUTED) return true;
        if (from_ == STATE_ANCHORED     && to_ == STATE_DISPUTED) return true;
        if (from_ == STATE_MATERIALIZED && to_ == STATE_DISPUTED) return true;

        // Deletion path (from any state except UNKNOWN)
        if (from_ == STATE_COMMITTED    && to_ == STATE_DELETED) return true;
        if (from_ == STATE_ANCHORED     && to_ == STATE_DELETED) return true;
        if (from_ == STATE_MATERIALIZED && to_ == STATE_DELETED) return true;
        if (from_ == STATE_DISPUTED     && to_ == STATE_DELETED) return true;

        // Also allow UNKNOWN → ANCHORED (direct anchoring without prior COMMITTED)
        if (from_ == STATE_UNKNOWN && to_ == STATE_ANCHORED) return true;

        return false;
    }
}
