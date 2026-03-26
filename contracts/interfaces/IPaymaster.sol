// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {PackedUserOperation} from "./PackedUserOperation.sol";

/**
 * @title IPaymaster
 * @notice ERC-4337 Paymaster interface.
 * @dev A Paymaster is a contract that sponsors gas for UserOperations.
 *      The EntryPoint calls `validatePaymasterUserOp` during the validation
 *      phase and `postOp` after execution.
 *
 *      Bundlers use this interface to determine whether a Paymaster is willing
 *      to sponsor a given UserOperation.
 */
interface IPaymaster {
    /// @notice Mode passed to `postOp`.
    enum PostOpMode {
        /// @dev The UserOperation succeeded.
        opSucceeded,
        /// @dev The UserOperation reverted.
        opReverted,
        /// @dev A previous `postOp` call reverted (second invocation).
        postOpReverted
    }

    /**
     * @notice Validates whether the Paymaster will sponsor the UserOperation.
     * @param userOp          The packed UserOperation.
     * @param userOpHash      Hash of the UserOperation.
     * @param maxCost         Maximum gas cost that the Paymaster must cover.
     * @return context        Opaque data returned to `postOp`.
     * @return validationData Packed validation result (same format as IAccount).
     */
    function validatePaymasterUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 maxCost
    ) external returns (bytes memory context, uint256 validationData);

    /**
     * @notice Called after UserOperation execution for accounting / refund logic.
     * @param mode            Whether the operation succeeded, reverted, or postOp reverted.
     * @param context         Context data returned from `validatePaymasterUserOp`.
     * @param actualGasCost   Actual gas consumed by the UserOperation.
     * @param actualUserOpFeePerGas  Effective gas price of the UserOperation.
     */
    function postOp(
        PostOpMode mode,
        bytes calldata context,
        uint256 actualGasCost,
        uint256 actualUserOpFeePerGas
    ) external;
}
