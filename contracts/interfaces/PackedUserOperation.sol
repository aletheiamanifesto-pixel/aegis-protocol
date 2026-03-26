// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title PackedUserOperation
 * @notice ERC-4337 v0.7 packed user operation struct.
 * @dev Gas-optimized struct using bytes32 packing for gas limit fields.
 *      Used by the EntryPoint to relay meta-transactions from Bundlers.
 *
 *      Layout of `accountGasLimits` (bytes32):
 *        [0:16]  – verificationGasLimit
 *        [16:32] – callGasLimit
 *
 *      Layout of `gasFees` (bytes32):
 *        [0:16]  – maxPriorityFeePerGas
 *        [16:32] – maxFeePerGas
 */
struct PackedUserOperation {
    address sender;
    uint256 nonce;
    bytes initCode;
    bytes callData;
    bytes32 accountGasLimits;
    uint256 preVerificationGas;
    bytes32 gasFees;
    bytes paymasterAndData;
    bytes signature;
}
