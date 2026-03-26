// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/**
 * @title MockEURC
 * @notice A simple ERC-20 mock representing Euro Coin (EURC) for testnet use.
 */
contract MockEURC is ERC20 {
    uint8 private constant _DECIMALS = 6; // EURC uses 6 decimals like USDC

    constructor(address initialHolder, uint256 initialSupply) ERC20("Mock EURC", "mEURC") {
        _mint(initialHolder, initialSupply);
    }

    function decimals() public pure override returns (uint8) {
        return _DECIMALS;
    }
}
