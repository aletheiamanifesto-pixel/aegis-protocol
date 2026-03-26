// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title DeployAegisEURC
 * @notice Foundry deployment script for AegisEURC and a mock ComplianceRegistry.
 *
 * Usage (local Anvil):
 *   forge script script/DeployAegisEURC.s.sol:DeployAegisEURC \
 *       --rpc-url http://127.0.0.1:8545 \
 *       --broadcast \
 *       -vvvv
 *
 * For a live network, set DEPLOYER_PRIVATE_KEY and ADMIN_ADDRESS env vars
 * and pass --verify --etherscan-api-key <KEY>.
 */

import "forge-std/Script.sol";
import "../src/AegisEURC.sol";
import "../src/IComplianceRegistry.sol";

// ─── Minimal Mock Registry (for testnet/local use only) ─────────────────────
contract MockComplianceRegistry is IComplianceRegistry {
    mapping(address => bool) private _verified;

    function setVerified(address account, bool status) external {
        _verified[account] = status;
    }

    function isVerified(address account) external view override returns (bool) {
        return _verified[account];
    }
}

// ─── Deployment Script ──────────────────────────────────────────────────────
contract DeployAegisEURC is Script {
    function run() external {
        // Read the deployer private key from environment (or use default Anvil key).
        uint256 deployerPrivateKey = vm.envOr(
            "DEPLOYER_PRIVATE_KEY",
            uint256(0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80) // Anvil #0
        );
        address admin = vm.envOr("ADMIN_ADDRESS", vm.addr(deployerPrivateKey));

        vm.startBroadcast(deployerPrivateKey);

        // 1. Deploy the mock compliance registry (replace with real registry on mainnet).
        MockComplianceRegistry registry = new MockComplianceRegistry();
        console.log("MockComplianceRegistry deployed at:", address(registry));

        // 2. Whitelist the admin so it can receive minted tokens.
        registry.setVerified(admin, true);

        // 3. Deploy AegisEURC.
        AegisEURC eurc = new AegisEURC(address(registry), admin);
        console.log("AegisEURC deployed at:", address(eurc));
        console.log("Admin:", admin);

        vm.stopBroadcast();
    }
}
