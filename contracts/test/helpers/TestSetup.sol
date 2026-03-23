// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {LTPAnchorRegistry} from "../../src/LTPAnchorRegistry.sol";

/// @title TestSetup
/// @notice Shared test fixtures for LTPAnchorRegistry tests.
abstract contract TestSetup is Test {
    LTPAnchorRegistry public registry;

    address public admin = address(0xAD);
    address public nonAdmin = address(0xBEEF);

    bytes32 public signerVkHash = keccak256("test-signer-vk");
    bytes32 public signerVkHash2 = keccak256("test-signer-vk-2");

    function setUp() public virtual {
        registry = new LTPAnchorRegistry(admin);

        // Register a default signer
        vm.prank(admin);
        registry.registerSigner(signerVkHash);
    }

    /// @dev Helper to create a unique anchor digest from a seed.
    function _digest(uint256 seed) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("anchor-digest-", seed));
    }

    /// @dev Helper to create a unique merkle root from a seed.
    function _merkleRoot(uint256 seed) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("merkle-root-", seed));
    }

    /// @dev Helper to create a unique policy hash from a seed.
    function _policyHash(uint256 seed) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("policy-hash-", seed));
    }
}
