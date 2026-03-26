// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title INonceManager
 * @notice Manages nonces for accounts in the EntryPoint (ERC-4337).
 * @dev Nonces are split into a 192-bit key and a 64-bit sequence number.
 *      This allows parallel nonce spaces per account.
 */
interface INonceManager {
    /**
     * @notice Returns the next valid nonce for `sender` under `key`.
     * @param sender The account address.
     * @param key    The nonce key (upper 192 bits).
     * @return nonce The full nonce (key | sequence).
     */
    function getNonce(address sender, uint192 key) external view returns (uint256 nonce);

    /**
     * @notice Manually increments the nonce for the sender under the given key.
     * @param key The nonce key to increment.
     */
    function incrementNonce(uint192 key) external;
}
