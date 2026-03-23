// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import {LTPAnchorRegistry} from "../src/LTPAnchorRegistry.sol";
import {LTPMultiSig} from "../src/LTPMultiSig.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

/// @title DeployTestnet
/// @notice GSX Testnet deployment — UUPS proxy + 2-of-2 multi-sig admin.
contract DeployTestnet is Script {
    function run() external {
        vm.startBroadcast();

        // 1. Deploy implementation
        LTPAnchorRegistry implementation = new LTPAnchorRegistry();

        // 2. Deploy proxy with msg.sender as initial admin
        bytes memory initData = abi.encodeCall(LTPAnchorRegistry.initialize, (msg.sender));
        ERC1967Proxy proxy = new ERC1967Proxy(address(implementation), initData);
        LTPAnchorRegistry registry = LTPAnchorRegistry(address(proxy));

        // 3. Deploy 2-of-2 multi-sig with both operator wallets
        address deployer = msg.sender;
        address operator = vm.envAddress("GSX_OPERATOR_ADDRESS");

        address[] memory owners = new address[](2);
        owners[0] = deployer;
        owners[1] = operator;
        LTPMultiSig multisig = new LTPMultiSig(owners, 2);

        // 4. Transfer admin to multi-sig
        registry.transferAdmin(address(multisig));

        vm.stopBroadcast();

        console.log("=== GSX Testnet Deployment (v2 - Upgradeable) ===");
        console.log("Implementation:", address(implementation));
        console.log("Proxy (registry):", address(proxy));
        console.log("MultiSig admin:", address(multisig));
        console.log("Owner 1 (deployer):", deployer);
        console.log("Owner 2 (operator):", operator);
        console.log("Chain ID:", block.chainid);
    }
}
