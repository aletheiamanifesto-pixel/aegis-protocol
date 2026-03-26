// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "../AegisSmartAccount.sol";
import "../contracts/MockEURC.sol";

/**
 * @title DeployAegis
 * @notice Foundry deployment script for AegisSmartAccount + optional MockEURC.
 *
 * Usage (testnet):
 *   forge script script/DeployAegis.s.sol:DeployAegis \
 *       --rpc-url $RPC_URL \
 *       --broadcast \
 *       --private-key $PRIVATE_KEY \
 *       -vvvv
 */
contract DeployAegis is Script {
    /// @notice Initial MockEURC supply: 1 000 000 EURC (6 decimals).
    uint256 constant MOCK_EURC_SUPPLY = 1_000_000 * 1e6;

    function run() external {
        // Load deployer from the environment private key.
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);

        vm.startBroadcast(deployerPrivateKey);

        // 1. Deploy AegisSmartAccount with the deployer as _owner.
        AegisSmartAccount account = new AegisSmartAccount(deployer);
        console.log("AegisSmartAccount deployed at:", address(account));

        // 2. Deploy MockEURC and wire it to the smart account.
        MockEURC eurc = new MockEURC(address(account), MOCK_EURC_SUPPLY);
        console.log("MockEURC deployed at:", address(eurc));

        // 3. Link MockEURC as the EURC token inside the smart account.
        account.setEurcToken(address(eurc));
        console.log("EURC token set on AegisSmartAccount");

        vm.stopBroadcast();
    }
}
