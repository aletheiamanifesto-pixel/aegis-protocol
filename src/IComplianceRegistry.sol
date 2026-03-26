// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title IComplianceRegistry
 * @notice Interface for an external AML/KYC compliance registry.
 * @dev This registry is queried by AegisEURC before every token transfer
 *      to ensure both counterparties satisfy MiCA and AML requirements.
 */
interface IComplianceRegistry {
    /**
     * @notice Returns `true` if `account` has completed KYC/AML verification
     *         and is not subject to any sanctions.
     * @param account The address to verify.
     * @return verified `true` when the address is allowed to send/receive tokens.
     */
    function isVerified(address account) external view returns (bool verified);
}
