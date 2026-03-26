// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title IStakeManager
 * @notice Manages deposits and stakes for accounts and paymasters on the EntryPoint.
 * @dev Part of the ERC-4337 EntryPoint specification.
 */
interface IStakeManager {
    /// @notice Emitted when a deposit is made.
    event Deposited(address indexed account, uint256 totalDeposit);

    /// @notice Emitted when funds are withdrawn.
    event Withdrawn(address indexed account, address withdrawAddress, uint256 amount);

    /// @notice Emitted on stake lock.
    event StakeLocked(address indexed account, uint256 totalStaked, uint256 unstakeDelaySec);

    /// @notice Emitted on stake unlock request.
    event StakeUnlocked(address indexed account, uint256 withdrawTime);

    /// @notice Emitted when stake is withdrawn.
    event StakeWithdrawn(address indexed account, address withdrawAddress, uint256 amount);

    /// @notice Deposit info per account.
    struct DepositInfo {
        uint256 deposit;
        bool staked;
        uint112 stake;
        uint32 unstakeDelaySec;
        uint48 withdrawTime;
    }

    /**
     * @notice Returns the deposit info for the given account.
     * @param account The account address.
     * @return info The deposit information.
     */
    function getDepositInfo(address account) external view returns (DepositInfo memory info);

    /**
     * @notice Returns the current deposit balance of the account.
     * @param account The account address.
     * @return The deposit balance.
     */
    function balanceOf(address account) external view returns (uint256);

    /**
     * @notice Adds to the deposit of the caller.
     * @param account The account to credit.
     */
    function depositTo(address account) external payable;

    /**
     * @notice Adds stake for the caller with a given unstake delay.
     * @param unstakeDelaySec Minimum seconds before stake can be withdrawn.
     */
    function addStake(uint32 unstakeDelaySec) external payable;

    /**
     * @notice Begins the unstake delay for the caller.
     */
    function unlockStake() external;

    /**
     * @notice Withdraws the caller's stake after the delay.
     * @param withdrawAddress Address to receive the withdrawn stake.
     */
    function withdrawStake(address payable withdrawAddress) external;

    /**
     * @notice Withdraws from the caller's deposit.
     * @param withdrawAddress Address to receive the withdrawn funds.
     * @param withdrawAmount  Amount to withdraw.
     */
    function withdrawTo(address payable withdrawAddress, uint256 withdrawAmount) external;
}
