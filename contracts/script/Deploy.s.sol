// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import {LTPAnchorRegistry} from "../src/LTPAnchorRegistry.sol";

/// @title Deploy
/// @notice Local deployment script for LTPAnchorRegistry (anvil / local EVM).
contract Deploy is Script {
    function run() external {
        uint256 deployerKey = vm.envOr("DEPLOYER_PRIVATE_KEY", uint256(0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80));
        address deployer = vm.addr(deployerKey);

        vm.startBroadcast(deployerKey);

        LTPAnchorRegistry registry = new LTPAnchorRegistry(deployer);

        vm.stopBroadcast();

        console.log("LTPAnchorRegistry deployed at:", address(registry));
        console.log("Admin:", deployer);
    }
}
