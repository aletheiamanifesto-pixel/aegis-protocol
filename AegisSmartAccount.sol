// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title AegisSmartAccount
 * @notice A digital safe that can only hold and transfer EURC (Euro Digital).
 *         - Owner  : the wallet holder who can deposit, withdraw, and transfer EURC.
 *         - Regulator : a compliance controller who can freeze / unfreeze the account
 *                       if suspicious activity is detected.
 *
 * Only the designated EURC ERC-20 token is accepted; any other token or native
 * ETH sent to this contract is rejected.
 */

// ---------- Minimal ERC-20 interface (EURC) ----------
interface IERC20 {
    function totalSupply() external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function allowance(address owner, address spender) external view returns (uint256);
    function approve(address spender, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
}

contract AegisSmartAccount {

    // ----------------------------------------------------------------
    // State
    // ----------------------------------------------------------------

    /// @notice The wallet owner who can move funds.
    address public owner;

    /// @notice The regulator / compliance controller.
    address public regulator;

    /// @notice The only ERC-20 token this account is allowed to hold.
    IERC20 public immutable eurc;

    /// @notice When `true` all outgoing transfers are blocked.
    bool public frozen;

    // ----------------------------------------------------------------
    // Events
    // ----------------------------------------------------------------

    event Deposited(address indexed from, uint256 amount);
    event Withdrawn(address indexed to, uint256 amount);
    event Transferred(address indexed to, uint256 amount);
    event AccountFrozen(address indexed byRegulator, string reason);
    event AccountUnfrozen(address indexed byRegulator);
    event OwnerChanged(address indexed previousOwner, address indexed newOwner);
    event RegulatorChanged(address indexed previousRegulator, address indexed newRegulator);

    // ----------------------------------------------------------------
    // Modifiers
    // ----------------------------------------------------------------

    modifier onlyOwner() {
        require(msg.sender == owner, "AegisSmartAccount: caller is not the owner");
        _;
    }

    modifier onlyRegulator() {
        require(msg.sender == regulator, "AegisSmartAccount: caller is not the regulator");
        _;
    }

    modifier notFrozen() {
        require(!frozen, "AegisSmartAccount: account is frozen");
        _;
    }

    // ----------------------------------------------------------------
    // Constructor
    // ----------------------------------------------------------------

    /**
     * @param _eurc      Address of the EURC (Euro Digital) ERC-20 token.
     * @param _owner     Initial wallet owner.
     * @param _regulator Initial regulator / compliance controller.
     */
    constructor(address _eurc, address _owner, address _regulator) {
        require(_eurc != address(0), "AegisSmartAccount: EURC address is zero");
        require(_owner != address(0), "AegisSmartAccount: owner address is zero");
        require(_regulator != address(0), "AegisSmartAccount: regulator address is zero");

        eurc = IERC20(_eurc);
        owner = _owner;
        regulator = _regulator;
    }

    // ----------------------------------------------------------------
    // Owner functions
    // ----------------------------------------------------------------

    /**
     * @notice Deposit EURC into the safe.
     *         The caller must have previously approved this contract to spend
     *         at least `amount` EURC tokens.
     * @param amount The number of EURC tokens to deposit (in smallest unit).
     */
    function deposit(uint256 amount) external onlyOwner notFrozen {
        require(amount > 0, "AegisSmartAccount: amount must be > 0");
        bool ok = eurc.transferFrom(msg.sender, address(this), amount);
        require(ok, "AegisSmartAccount: EURC transferFrom failed");
        emit Deposited(msg.sender, amount);
    }

    /**
     * @notice Withdraw EURC back to the owner's external wallet.
     * @param amount The number of EURC tokens to withdraw.
     */
    function withdraw(uint256 amount) external onlyOwner notFrozen {
        require(amount > 0, "AegisSmartAccount: amount must be > 0");
        require(eurc.balanceOf(address(this)) >= amount, "AegisSmartAccount: insufficient balance");
        bool ok = eurc.transfer(msg.sender, amount);
        require(ok, "AegisSmartAccount: EURC transfer failed");
        emit Withdrawn(msg.sender, amount);
    }

    /**
     * @notice Transfer EURC from the safe to another address.
     * @param to     Recipient address.
     * @param amount The number of EURC tokens to send.
     */
    function transferEURC(address to, uint256 amount) external onlyOwner notFrozen {
        require(to != address(0), "AegisSmartAccount: recipient is zero address");
        require(amount > 0, "AegisSmartAccount: amount must be > 0");
        require(eurc.balanceOf(address(this)) >= amount, "AegisSmartAccount: insufficient balance");
        bool ok = eurc.transfer(to, amount);
        require(ok, "AegisSmartAccount: EURC transfer failed");
        emit Transferred(to, amount);
    }

    /**
     * @notice Transfer ownership of the safe to a new address.
     * @param newOwner The address of the new owner.
     */
    function changeOwner(address newOwner) external onlyOwner {
        require(newOwner != address(0), "AegisSmartAccount: new owner is zero address");
        address previousOwner = owner;
        owner = newOwner;
        emit OwnerChanged(previousOwner, newOwner);
    }

    // ----------------------------------------------------------------
    // Regulator functions
    // ----------------------------------------------------------------

    /**
     * @notice Freeze the account – all outgoing EURC transfers are blocked.
     * @param reason A human-readable reason stored in the event log.
     */
    function freeze(string calldata reason) external onlyRegulator {
        require(!frozen, "AegisSmartAccount: already frozen");
        frozen = true;
        emit AccountFrozen(msg.sender, reason);
    }

    /**
     * @notice Unfreeze the account – normal operations resume.
     */
    function unfreeze() external onlyRegulator {
        require(frozen, "AegisSmartAccount: not frozen");
        frozen = false;
        emit AccountUnfrozen(msg.sender);
    }

    /**
     * @notice Transfer the regulator role to a new address.
     * @param newRegulator The address of the new regulator.
     */
    function changeRegulator(address newRegulator) external onlyRegulator {
        require(newRegulator != address(0), "AegisSmartAccount: new regulator is zero address");
        address previousRegulator = regulator;
        regulator = newRegulator;
        emit RegulatorChanged(previousRegulator, newRegulator);
    }

    // ----------------------------------------------------------------
    // View helpers
    // ----------------------------------------------------------------

    /**
     * @notice Returns the EURC balance held by this safe.
     */
    function balance() external view returns (uint256) {
        return eurc.balanceOf(address(this));
    }

    // ----------------------------------------------------------------
    // Reject native ETH
    // ----------------------------------------------------------------

    /**
     * @dev Reject any native ETH sent to the contract so that only EURC
     *      can be held.
     */
    receive() external payable {
        revert("AegisSmartAccount: ETH not accepted, use EURC");
    }

    fallback() external payable {
        revert("AegisSmartAccount: ETH not accepted, use EURC");
    }
}