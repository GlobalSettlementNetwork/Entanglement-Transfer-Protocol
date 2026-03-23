// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title ILTPAnchorRegistry
/// @notice Interface for the LTP on-chain anchor registry.
/// @dev Stores anchor digests, enforces state machine transitions,
///      tracks per-signer sequences, and manages signer authorization.
interface ILTPAnchorRegistry {
    // -----------------------------------------------------------------------
    // Structs
    // -----------------------------------------------------------------------

    struct AnchorRecord {
        bytes32 merkleRoot;
        bytes32 policyHash;
        bytes32 signerVkHash;
        uint64  sequence;
        uint64  validUntil;
        uint64  targetChainId;
        uint8   receiptType;
        uint8   entityState;
        uint64  anchoredAt;
    }

    // -----------------------------------------------------------------------
    // Events
    // -----------------------------------------------------------------------

    event Anchored(
        bytes32 indexed anchorDigest,
        bytes32 indexed signerVkHash,
        uint64 sequence
    );

    event BatchAnchored(
        uint256 count,
        bytes32 indexed firstDigest
    );

    event SignerRegistered(bytes32 indexed vkHash);
    event SignerRevoked(bytes32 indexed vkHash);

    event StateTransition(
        bytes32 indexed entityIdHash,
        uint8 fromState,
        uint8 toState
    );

    // -----------------------------------------------------------------------
    // Errors
    // -----------------------------------------------------------------------

    error AlreadyAnchored(bytes32 anchorDigest);
    error SequenceTooLow(bytes32 signerVkHash, uint64 provided, uint64 current);
    error Expired(uint64 validUntil, uint64 blockTimestamp);
    error UnauthorizedSigner(bytes32 signerVkHash);
    error InvalidStateTransition(uint8 fromState, uint8 toState);
    error NotAdmin(address caller);
    error EmptyBatch();

    // -----------------------------------------------------------------------
    // Write functions
    // -----------------------------------------------------------------------

    /// @notice Anchor a single trust artifact on-chain.
    function anchor(
        bytes32 anchorDigest,
        bytes32 merkleRoot,
        bytes32 policyHash,
        bytes32 signerVkHash,
        uint64  sequence,
        uint64  validUntil,
        uint8   receiptType
    ) external;

    /// @notice Anchor multiple trust artifacts in a single transaction.
    function batchAnchor(
        bytes32[] calldata anchorDigests,
        bytes32[] calldata merkleRoots,
        bytes32[] calldata policyHashes,
        bytes32[] calldata signerVkHashes,
        uint64[]  calldata sequences,
        uint64[]  calldata validUntils,
        uint8[]   calldata receiptTypes
    ) external;

    /// @notice Register an authorized signer by VK hash. Admin only.
    function registerSigner(bytes32 vkHash) external;

    /// @notice Revoke an authorized signer. Admin only.
    function revokeSigner(bytes32 vkHash) external;

    // -----------------------------------------------------------------------
    // View functions
    // -----------------------------------------------------------------------

    /// @notice Check if an anchor digest has been recorded.
    function isAnchored(bytes32 anchorDigest) external view returns (bool);

    /// @notice Get the entity state for an entity ID hash.
    function getEntityState(bytes32 entityIdHash) external view returns (uint8);

    /// @notice Get the current sequence for a signer VK hash.
    function getSignerSequence(bytes32 vkHash) external view returns (uint64);

    /// @notice Get the full anchor record for a digest.
    function getAnchorRecord(bytes32 anchorDigest) external view returns (AnchorRecord memory);
}
