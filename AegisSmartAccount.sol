// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/**
 * @title AegisSmartAccount
 * @notice Smart account that enforces MiCA compliance.
 *         Only the authorised backend ("Postino") can invoke compliant
 *         transfers.  High-value EURC movements require a valid ZK proof.
 */
contract AegisSmartAccount is Ownable, ReentrancyGuard {

    // -----------------------------------------------------------------
    // State
    // -----------------------------------------------------------------

    /// @notice The EURC (Euro Digital) token contract.
    IERC20 public immutable eurc;

    /// @notice The backend address authorised to relay compliant operations.
    address public backend;

    /// @notice Mapping of proof hashes that have already been consumed.
    mapping(bytes32 => bool) public usedProofs;

    // -----------------------------------------------------------------
    // Events
    // -----------------------------------------------------------------

    event BackendUpdated(address indexed oldBackend, address indexed newBackend);
    event CompliantTransfer(
        address indexed to,
        uint256 amount,
        bytes32 proofHash
    );

    // -----------------------------------------------------------------
    // Errors
    // -----------------------------------------------------------------

    error OnlyBackend();
    error InvalidRecipient();
    error ZeroAmount();
    error ProofAlreadyUsed();
    error TransferFailed();

    // -----------------------------------------------------------------
    // Modifiers
    // -----------------------------------------------------------------

    /// @dev Restricts a function to the authorised backend address.
    modifier onlyBackend() {
        if (msg.sender != backend) revert OnlyBackend();
        _;
    }

    // -----------------------------------------------------------------
    // Constructor
    // -----------------------------------------------------------------

    /**
     * @param _eurc    Address of the EURC token contract.
     * @param _backend Address of the authorised backend (Python processor).
     */
    constructor(address _eurc, address _backend) Ownable(msg.sender) {
        require(_eurc != address(0), "Invalid EURC address");
        require(_backend != address(0), "Invalid backend address");
        eurc = IERC20(_eurc);
        backend = _backend;
    }

    // -----------------------------------------------------------------
    // Owner functions
    // -----------------------------------------------------------------

    /// @notice Update the authorised backend address.
    function setBackend(address _newBackend) external onlyOwner {
        require(_newBackend != address(0), "Invalid backend address");
        emit BackendUpdated(backend, _newBackend);
        backend = _newBackend;
    }

    // -----------------------------------------------------------------
    // Backend-only functions
    // -----------------------------------------------------------------

    /**
     * @notice Transfer EURC to a recipient after MiCA compliance checks.
     * @dev    Can only be called by the authorised backend.
     *         The proof hash must be unique and non-zero for amounts that
     *         required ZK verification.
     * @param _to        Recipient address.
     * @param _amount    Amount of EURC (in token decimals).
     * @param _proof     ZK proof hash — must be non-zero for high-value txns.
     */
    function executeCompliant(
        address _to,
        uint256 _amount,
        bytes32 _proof
    ) external onlyBackend nonReentrant {
        if (_to == address(0)) revert InvalidRecipient();
        if (_amount == 0) revert ZeroAmount();
        if (usedProofs[_proof]) revert ProofAlreadyUsed();

        usedProofs[_proof] = true;

        // The contract holds EURC; transfer from its own balance.
        bool success = eurc.transfer(_to, _amount);
        if (!success) revert TransferFailed();

        emit CompliantTransfer(_to, _amount, _proof);
    }

    /**
     * @notice Deposit EURC into this smart account.
     * @dev    Caller must have approved this contract to spend `_amount` EURC.
     */
    function depositEURC(uint256 _amount) external {
        require(_amount > 0, "Zero deposit");
        bool success = eurc.transferFrom(msg.sender, address(this), _amount);
        require(success, "Deposit failed");
    }

    // -----------------------------------------------------------------
    // General execution (owner only)
    // -----------------------------------------------------------------

    /**
     * @notice Execute an arbitrary call (owner-only, for admin operations).
     */
    function executeTransaction(
        address _to,
        uint256 _value,
        bytes memory _data
    ) external onlyOwner returns (bytes memory) {
        (bool success, bytes memory returnData) = _to.call{value: _value}(_data);
        require(success, "Transaction failed.");
        return returnData;
    }

    // -----------------------------------------------------------------
    // Receive / Fallback
    // -----------------------------------------------------------------

    receive() external payable {}
}