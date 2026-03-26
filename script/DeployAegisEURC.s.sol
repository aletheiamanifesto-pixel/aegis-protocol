// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "../src/AegisEURC.sol";

/**
 * @title DeployAegisEURC
 * @notice Script Foundry per il deploy di AegisEURC su una rete EVM.
 *
 * @dev Utilizzo:
 *
 *   # Deploy su rete locale (Anvil)
 *   forge script script/DeployAegisEURC.s.sol:DeployAegisEURC \
 *       --rpc-url http://127.0.0.1:8545 \
 *       --broadcast
 *
 *   # Deploy su testnet (es. Sepolia) con verifica su Etherscan
 *   forge script script/DeployAegisEURC.s.sol:DeployAegisEURC \
 *       --rpc-url $SEPOLIA_RPC_URL \
 *       --private-key $DEPLOYER_PRIVATE_KEY \
 *       --broadcast \
 *       --verify \
 *       --etherscan-api-key $ETHERSCAN_API_KEY
 *
 *   Variabili d'ambiente richieste:
 *     - DEPLOYER_PRIVATE_KEY: Chiave privata del deployer
 *     - ADMIN_ADDRESS:        Indirizzo dell'admin iniziale (opzionale, default = deployer)
 *     - COMPLIANCE_REGISTRY:  Indirizzo del ComplianceRegistry già deployato
 */
contract DeployAegisEURC is Script {
    function run() external {
        // ── Leggi configurazione da variabili d'ambiente ────────────────
        uint256 deployerPrivateKey = vm.envUint("DEPLOYER_PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);

        // Admin: usa ADMIN_ADDRESS se impostata, altrimenti il deployer
        address admin = vm.envOr("ADMIN_ADDRESS", deployer);

        // ComplianceRegistry: deve essere già deployato
        address complianceRegistry = vm.envAddress("COMPLIANCE_REGISTRY");

        // ── Log pre-deploy ──────────────────────────────────────────────
        console.log("=== AegisEURC Deployment ===");
        console.log("Deployer:            ", deployer);
        console.log("Admin:               ", admin);
        console.log("ComplianceRegistry:  ", complianceRegistry);
        console.log("Chain ID:            ", block.chainid);

        // ── Deploy ──────────────────────────────────────────────────────
        vm.startBroadcast(deployerPrivateKey);

        AegisEURC token = new AegisEURC(admin, complianceRegistry);

        vm.stopBroadcast();

        // ── Log post-deploy ─────────────────────────────────────────────
        console.log("---");
        console.log("AegisEURC deployed at:", address(token));
        console.log("Name:                ", token.name());
        console.log("Symbol:              ", token.symbol());
        console.log("Decimals:            ", token.decimals());
    }
}
