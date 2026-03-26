// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {PackedUserOperation} from "./PackedUserOperation.sol";

/**
 * @title IAccount
 * @notice ERC-4337 Account interface.
 * @dev Must be implemented by every smart-contract wallet that wishes to
 *      participate in the ERC-4337 UserOperation flow.
 *
 *      The EntryPoint calls `validateUserOp` before executing the callData
 *      embedded in the UserOperation. The account MUST verify the signature
 *      and pay back `missingAccountFunds` to the EntryPoint.
 */
interface IAccount {
    /**
     * @notice Validates a UserOperation and pays prefund to the EntryPoint.
     * @param userOp          The packed user operation to validate.
     * @param userOpHash      Hash of the UserOperation (excluding the signature).
     * @param missingAccountFunds  Amount of ETH the account must deposit to
     *                             the EntryPoint to cover gas.
     * @return validationData  Packed validation result:
     *                         - `0` on success
     *                         - `1` on signature failure
     *                         - `(validAfter, validUntil, authorizer)` packed
     *                           as `uint48 validAfter | uint48 validUntil << 48 | address authorizer << 96`
     */
    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external returns (uint256 validationData);
}
