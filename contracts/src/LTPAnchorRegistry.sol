// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ILTPAnchorRegistry} from "./interfaces/ILTPAnchorRegistry.sol";
import {Initializable} from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";

/// @title LTPAnchorRegistry
/// @author Javier Calderon Jr, CTO of Global Settlement (GSX)
/// @notice On-chain registry for LTP anchor digests with state machine,
///         per-signer sequencing, signer authorization, and emergency pause.
/// @dev Upgradeable via UUPS proxy pattern. Admin is expected to be a multi-sig.
///      Thin on-chain, thick off-chain — no PQ signature verification on-chain.
contract LTPAnchorRegistry is ILTPAnchorRegistry, Initializable, UUPSUpgradeable {
    // -----------------------------------------------------------------------
    // Constants — EntityState enum mirrors Python src/ltp/anchor/state.py
    // -----------------------------------------------------------------------

    uint8 public constant STATE_UNKNOWN       = 0;
    uint8 public constant STATE_COMMITTED     = 1;
    uint8 public constant STATE_ANCHORED      = 2;
    uint8 public constant STATE_MATERIALIZED  = 3;
    uint8 public constant STATE_DISPUTED      = 4;
    uint8 public constant STATE_DELETED       = 5;

    /// @notice Maximum items per batchAnchor call (gas DoS protection).
    uint256 public constant MAX_BATCH_SIZE = 100;

    // -----------------------------------------------------------------------
    // Storage (must be append-only for upgrade safety)
    // -----------------------------------------------------------------------

    address public admin;
    bool public paused;

    /// @notice anchorDigest => AnchorRecord
    mapping(bytes32 => AnchorRecord) private _anchors;

    /// @notice signerVkHash => highest accepted sequence number
    mapping(bytes32 => uint64) public signerSequences;

    /// @notice entityIdHash => EntityState (uint8)
    mapping(bytes32 => uint8) public entityStates;

    /// @notice signerVkHash => authorized flag
    mapping(bytes32 => bool) public authorizedSigners;

    // -----------------------------------------------------------------------
    // Constructor — disables initializers on the implementation contract
    // -----------------------------------------------------------------------

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    // -----------------------------------------------------------------------
    // Initializer (replaces constructor for proxy deployments)
    // -----------------------------------------------------------------------

    function initialize(address _admin) external initializer {
        if (_admin == address(0)) revert NotAdmin(address(0));
        admin = _admin;
        paused = false;
    }

    // -----------------------------------------------------------------------
    // Modifiers
    // -----------------------------------------------------------------------

    modifier onlyAdmin() {
        if (msg.sender != admin) revert NotAdmin(msg.sender);
        _;
    }

    modifier whenNotPaused() {
        if (paused) revert ContractPaused();
        _;
    }

    // -----------------------------------------------------------------------
    // Admin functions
    // -----------------------------------------------------------------------

    /// @notice Transfer admin role. Admin only.
    function transferAdmin(address newAdmin) external onlyAdmin {
        if (newAdmin == address(0)) revert NotAdmin(address(0));
        address oldAdmin = admin;
        admin = newAdmin;
        emit AdminTransferred(oldAdmin, newAdmin);
    }

    /// @notice Pause all anchoring operations. Admin only.
    function pause() external onlyAdmin {
        paused = true;
        emit Paused(msg.sender);
    }

    /// @notice Unpause anchoring operations. Admin only.
    function unpause() external onlyAdmin {
        paused = false;
        emit Unpaused(msg.sender);
    }

    // -----------------------------------------------------------------------
    // UUPS upgrade authorization
    // -----------------------------------------------------------------------

    /// @dev Only admin can authorize upgrades.
    function _authorizeUpgrade(address newImplementation) internal override onlyAdmin {}

    // -----------------------------------------------------------------------
    // Write functions
    // -----------------------------------------------------------------------

    /// @inheritdoc ILTPAnchorRegistry
    function anchor(
        bytes32 anchorDigest,
        bytes32 entityIdHash,
        bytes32 merkleRoot,
        bytes32 policyHash,
        bytes32 signerVkHash,
        uint64  sequence,
        uint64  validUntil,
        uint8   receiptType
    ) external whenNotPaused {
        _anchor(
            anchorDigest,
            entityIdHash,
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
        bytes32[] calldata entityIdHashes,
        bytes32[] calldata merkleRoots,
        bytes32[] calldata policyHashes,
        bytes32[] calldata signerVkHashes,
        uint64[]  calldata sequences,
        uint64[]  calldata validUntils,
        uint8[]   calldata receiptTypes
    ) external whenNotPaused {
        uint256 len = anchorDigests.length;
        if (len == 0) revert EmptyBatch();
        if (len > MAX_BATCH_SIZE) revert BatchTooLarge(len, MAX_BATCH_SIZE);
        if (
            entityIdHashes.length != len ||
            merkleRoots.length != len ||
            policyHashes.length != len ||
            signerVkHashes.length != len ||
            sequences.length != len ||
            validUntils.length != len ||
            receiptTypes.length != len
        ) revert ArrayLengthMismatch();
        for (uint256 i = 0; i < len; ++i) {
            _anchor(
                anchorDigests[i],
                entityIdHashes[i],
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
    function transitionState(
        bytes32 entityIdHash,
        uint8   newState,
        bytes32 signerVkHash,
        uint64  sequence,
        uint64  validUntil
    ) external whenNotPaused {
        // 1. Signer authorization
        if (!authorizedSigners[signerVkHash]) {
            revert UnauthorizedSigner(signerVkHash);
        }

        // 2. Sequence monotonicity
        uint64 currentSeq = signerSequences[signerVkHash];
        if (sequence <= currentSeq) {
            revert SequenceTooLow(signerVkHash, sequence, currentSeq);
        }

        // 3. Temporal expiry
        if (uint64(block.timestamp) >= validUntil) {
            revert Expired(validUntil, uint64(block.timestamp));
        }

        // 4. State transition validation
        uint8 currentState = entityStates[entityIdHash];
        if (!_isValidTransition(currentState, newState)) {
            revert InvalidStateTransition(currentState, newState);
        }

        // 5. Update state
        entityStates[entityIdHash] = newState;

        // 6. Update signer sequence HWM
        signerSequences[signerVkHash] = sequence;

        emit StateTransitioned(entityIdHash, signerVkHash, currentState, newState, sequence);
        emit StateTransition(entityIdHash, currentState, newState);
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

    /// @inheritdoc ILTPAnchorRegistry
    function areAnchored(bytes32[] calldata anchorDigests) external view returns (bool[] memory) {
        bool[] memory results = new bool[](anchorDigests.length);
        for (uint256 i = 0; i < anchorDigests.length; ++i) {
            results[i] = _anchors[anchorDigests[i]].anchoredAt != 0;
        }
        return results;
    }

    /// @inheritdoc ILTPAnchorRegistry
    function getEntityStates(
        bytes32[] calldata entityIdHashes
    ) external view returns (uint8[] memory) {
        uint8[] memory results = new uint8[](entityIdHashes.length);
        for (uint256 i = 0; i < entityIdHashes.length; ++i) {
            results[i] = entityStates[entityIdHashes[i]];
        }
        return results;
    }

    /// @inheritdoc ILTPAnchorRegistry
    function getAnchorRecords(
        bytes32[] calldata anchorDigests
    ) external view returns (AnchorRecord[] memory) {
        AnchorRecord[] memory results = new AnchorRecord[](anchorDigests.length);
        for (uint256 i = 0; i < anchorDigests.length; ++i) {
            results[i] = _anchors[anchorDigests[i]];
        }
        return results;
    }

    /// @notice Returns the implementation version for upgrade tracking.
    function version() external pure returns (uint256) {
        return 5;
    }

    // -----------------------------------------------------------------------
    // Internal
    // -----------------------------------------------------------------------

    /// @dev Core anchoring logic shared by anchor() and batchAnchor().
    function _anchor(
        bytes32 anchorDigest,
        bytes32 entityIdHash,
        bytes32 merkleRoot,
        bytes32 policyHash,
        bytes32 signerVkHash,
        uint64  sequence,
        uint64  validUntil,
        uint8   receiptType
    ) internal {
        // 1. Replay rejection
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

        // 5. State transition: entity state → ANCHORED
        uint8 currentState = entityStates[entityIdHash];
        uint8 newState = STATE_ANCHORED;
        if (!_isValidTransition(currentState, newState)) {
            revert InvalidStateTransition(currentState, newState);
        }

        // 6. Store the anchor record
        _anchors[anchorDigest] = AnchorRecord({
            merkleRoot:    merkleRoot,
            policyHash:    policyHash,
            signerVkHash:  signerVkHash,
            entityIdHash:  entityIdHash,
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
        entityStates[entityIdHash] = newState;

        emit Anchored(anchorDigest, entityIdHash, signerVkHash, sequence);
        emit StateTransition(entityIdHash, currentState, newState);
    }

    /// @dev Validate entity state transitions. Mirrors Python state.py:37-51.
    function _isValidTransition(uint8 from_, uint8 to_) internal pure returns (bool) {
        if (from_ == STATE_UNKNOWN   && to_ == STATE_COMMITTED)    return true;
        if (from_ == STATE_COMMITTED && to_ == STATE_ANCHORED)     return true;
        if (from_ == STATE_ANCHORED  && to_ == STATE_MATERIALIZED) return true;
        if (from_ == STATE_COMMITTED    && to_ == STATE_DISPUTED) return true;
        if (from_ == STATE_ANCHORED     && to_ == STATE_DISPUTED) return true;
        if (from_ == STATE_MATERIALIZED && to_ == STATE_DISPUTED) return true;
        if (from_ == STATE_COMMITTED    && to_ == STATE_DELETED) return true;
        if (from_ == STATE_ANCHORED     && to_ == STATE_DELETED) return true;
        if (from_ == STATE_MATERIALIZED && to_ == STATE_DELETED) return true;
        if (from_ == STATE_DISPUTED     && to_ == STATE_DELETED) return true;
        if (from_ == STATE_UNKNOWN && to_ == STATE_ANCHORED) return true;
        return false;
    }

    // -----------------------------------------------------------------------
    // Storage gap — reserves slots for future upgrades without colliding
    // with derived contract storage. Standard OpenZeppelin pattern.
    // -----------------------------------------------------------------------

    uint256[50] private __gap;
}
