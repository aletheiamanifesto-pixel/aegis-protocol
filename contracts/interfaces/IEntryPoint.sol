// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {PackedUserOperation} from "./PackedUserOperation.sol";
import {IStakeManager} from "./IStakeManager.sol";
import {INonceManager} from "./INonceManager.sol";

/**
 * @title IEntryPoint
 * @notice ERC-4337 EntryPoint interface (v0.7).
 * @dev The EntryPoint is the singleton contract that Bundlers call to execute
 *      batches of UserOperations. It is responsible for:
 *        1. Calling `validateUserOp` on the sender account.
 *        2. Optionally calling `validatePaymasterUserOp` on a Paymaster.
 *        3. Executing the UserOperation calldata against the account.
 *        4. Handling gas accounting and refunds.
 */
interface IEntryPoint is IStakeManager, INonceManager {
    /* ───────────────────── Errors ───────────────────── */

    /// @dev Returned when a UserOperation fails validation.
    error FailedOp(uint256 opIndex, string reason);

    /// @dev Returned when a UserOperation fails with a revert reason from the account.
    error FailedOpWithRevert(uint256 opIndex, string reason, bytes inner);

    /// @dev Signal to the off-chain bundler about a signature validation failure.
    error SignatureValidationFailed(address aggregator);

    /* ───────────────────── Events ───────────────────── */

    /// @notice Emitted after each successful UserOperation execution.
    event UserOperationEvent(
        bytes32 indexed userOpHash,
        address indexed sender,
        address indexed paymaster,
        uint256 nonce,
        bool success,
        uint256 actualGasCost,
        uint256 actualGasUsed
    );

    /// @notice Emitted if the UserOperation callData reverts.
    event UserOperationRevertReason(
        bytes32 indexed userOpHash,
        address indexed sender,
        uint256 nonce,
        bytes revertReason
    );

    /// @notice Emitted when the EntryPoint receives a prefund deposit.
    event UserOperationPrefundTooLow(
        bytes32 indexed userOpHash,
        address indexed sender,
        uint256 nonce
    );

    /* ─────────────── Core Functions ─────────────── */

    /**
     * @notice Executes a batch of UserOperations.
     * @param ops            Array of packed UserOperations.
     * @param beneficiary    Address to receive gas refunds.
     */
    function handleOps(
        PackedUserOperation[] calldata ops,
        address payable beneficiary
    ) external;

    /**
     * @notice Returns the hash of the given UserOperation.
     * @param userOp The UserOperation to hash.
     * @return The unique hash used for signature verification.
     */
    function getUserOpHash(PackedUserOperation calldata userOp) external view returns (bytes32);

    /**
     * @notice Simulates the validation phase of a UserOperation.
     * @dev Always reverts with `ValidationResult` or `ValidationResultWithAggregation`.
     * @param userOp The UserOperation to simulate.
     */
    function simulateValidation(PackedUserOperation calldata userOp) external;
}
