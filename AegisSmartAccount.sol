// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/**
 * @title AegisSmartAccount
 * @notice ERC-4337 inspired smart account with ZK proof registration
 *         and MiCA-compliant EURC transaction support.
 */
contract AegisSmartAccount is Ownable, ReentrancyGuard {

    // ── Events ──────────────────────────────────────────────────────────
    event ZkProofRegistered(bytes32 indexed proofHash, bytes32 indexed calldataHash, uint256 timestamp);
    event TransactionExecuted(address indexed to, uint256 value, bytes data, bool success);
    event CompliantTransfer(address indexed token, address indexed to, uint256 amount, bytes32 proofHash);

    // ── State ───────────────────────────────────────────────────────────
    /// @notice Mapping of proof hashes that have been registered on-chain.
    mapping(bytes32 => bool) public registeredProofs;

    /// @notice Optional: address of the compliant EURC token.
    address public eurcToken;

    // ── Constructor ─────────────────────────────────────────────────────
    /**
     * @param _owner The initial owner (deployer / admin / bundler).
     */
    constructor(address _owner) Ownable(_owner) {}

    // ── Core Functions ──────────────────────────────────────────────────

    /**
     * @notice Register a ZK proof hash on-chain.
     * @param _proofHash  The keccak256 hash of the ZK proof payload.
     * @param _calldataHash  The keccak256 hash of the related calldata.
     */
    function registerZkProof(bytes32 _proofHash, bytes32 _calldataHash) external onlyOwner {
        require(_proofHash != bytes32(0), "Aegis: empty proof hash");
        require(!registeredProofs[_proofHash], "Aegis: proof already registered");

        registeredProofs[_proofHash] = true;
        emit ZkProofRegistered(_proofHash, _calldataHash, block.timestamp);
    }

    /**
     * @notice Execute an arbitrary call from this smart account.
     * @param _to    Target address.
     * @param _value ETH value to forward.
     * @param _data  Calldata payload.
     * @return returnData  The bytes returned by the call.
     */
    function execute(
        address _to,
        uint256 _value,
        bytes calldata _data
    ) external onlyOwner nonReentrant returns (bytes memory returnData) {
        require(_to != address(0), "Aegis: zero address");
        bool success;
        (success, returnData) = _to.call{value: _value}(_data);
        require(success, "Aegis: execution failed");
        emit TransactionExecuted(_to, _value, _data, success);
    }

    /**
     * @notice Transfer EURC tokens only if a ZK proof has been registered.
     * @param _to         Recipient address.
     * @param _amount     Amount of EURC to transfer.
     * @param _proofHash  Previously registered proof hash.
     */
    function onlyCompliantEURC(
        address _to,
        uint256 _amount,
        bytes32 _proofHash
    ) external onlyOwner nonReentrant {
        require(eurcToken != address(0), "Aegis: EURC token not set");
        require(registeredProofs[_proofHash], "Aegis: proof not registered");
        require(_to != address(0), "Aegis: zero recipient");

        bool ok = IERC20(eurcToken).transfer(_to, _amount);
        require(ok, "Aegis: EURC transfer failed");
        emit CompliantTransfer(eurcToken, _to, _amount, _proofHash);
    }

    // ── Admin Helpers ───────────────────────────────────────────────────

    /**
     * @notice Set the EURC token address.
     */
    function setEurcToken(address _eurcToken) external onlyOwner {
        require(_eurcToken != address(0), "Aegis: zero address");
        eurcToken = _eurcToken;
    }

    /**
     * @notice Check whether a proof has been registered.
     */
    function isProofRegistered(bytes32 _proofHash) external view returns (bool) {
        return registeredProofs[_proofHash];
    }

    /// @notice Allow receiving ETH.
    receive() external payable {}
}