// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import {LTPAnchorRegistry} from "../src/LTPAnchorRegistry.sol";

/// @title DeployTestnet
/// @notice Deployment script for GSX Testnet.
contract DeployTestnet is Script {
    function run() external {
        // msg.sender is set by --private-key flag
        vm.startBroadcast();

        LTPAnchorRegistry registry = new LTPAnchorRegistry(msg.sender);

        vm.stopBroadcast();

        console.log("=== GSX Testnet Deployment ===");
        console.log("LTPAnchorRegistry:", address(registry));
        console.log("Admin:", msg.sender);
        console.log("Chain ID:", block.chainid);
    }
}
