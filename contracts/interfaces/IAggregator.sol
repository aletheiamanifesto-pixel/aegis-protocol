// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {PackedUserOperation} from "./PackedUserOperation.sol";

/**
 * @title IAggregator
 * @notice ERC-4337 Signature Aggregator interface.
 * @dev Used by Bundlers to aggregate multiple UserOperation signatures into
 *      a single aggregated signature, reducing on-chain verification cost.
 *
 *      A smart-account can designate an Aggregator by returning its address
 *      in the `authorizer` field of `validationData`.
 */
interface IAggregator {
    /**
     * @notice Validates the aggregated signature for a batch of UserOperations.
     * @param userOps           Array of UserOperations sharing this aggregator.
     * @param signature         The aggregated signature bytes.
     */
    function validateSignatures(
        PackedUserOperation[] calldata userOps,
        bytes calldata signature
    ) external view;

    /**
     * @notice Validates a single UserOperation's signature against the aggregator.
     * @param userOp  The UserOperation to validate.
     * @return sigForAggregation Bytes to include in the aggregated signature.
     */
    function validateUserOpSignature(
        PackedUserOperation calldata userOp
    ) external view returns (bytes memory sigForAggregation);

    /**
     * @notice Aggregates an array of per-op signatures into one.
     * @param userOps Array of UserOperations whose signatures are to be aggregated.
     * @return aggregatedSignature The combined signature.
     */
    function aggregateSignatures(
        PackedUserOperation[] calldata userOps
    ) external view returns (bytes memory aggregatedSignature);
}
