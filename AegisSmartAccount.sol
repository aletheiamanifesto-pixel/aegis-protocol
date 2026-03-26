// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

// ---------------------------------------------------------------------------
// ERC-4337 Type Definitions
// ---------------------------------------------------------------------------

/**
 * @notice Packed representation of a User Operation as defined by ERC-4337.
 * @dev Fields are laid out to minimise calldata cost (shorter dynamic fields last).
 */
struct PackedUserOperation {
    address sender;
    uint256 nonce;
    bytes initCode;
    bytes callData;
    bytes32 accountGasLimits;   // verificationGasLimit (high 128) | callGasLimit (low 128)
    uint256 preVerificationGas;
    bytes32 gasFees;            // maxPriorityFeePerGas (high 128) | maxFeePerGas (low 128)
    bytes paymasterAndData;
    bytes signature;
}

// ---------------------------------------------------------------------------
// Interfaces
// ---------------------------------------------------------------------------

/**
 * @title IAccount
 * @notice ERC-4337 account interface that every Smart Contract Wallet must implement.
 */
interface IAccount {
    /**
     * @notice Validate a User Operation sent by the EntryPoint.
     * @param userOp          The packed user operation.
     * @param userOpHash      Hash of the user operation (including chain-id & entry-point address).
     * @param missingAccountFunds Amount of ETH the account must pre-fund into the EntryPoint.
     * @return validationData Packed value: sigFailure (1 bit) | validUntil (48 bits) | validAfter (48 bits).
     *                        Return 0 for a valid, time-unrestricted signature.
     */
    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external returns (uint256 validationData);
}

/**
 * @title IEntryPoint
 * @notice Minimal interface for the canonical ERC-4337 EntryPoint contract.
 *         Only the subset required by AegisSmartAccount is declared here.
 */
interface IEntryPoint {
    /**
     * @notice Returns the deposit balance of `account` held by the EntryPoint.
     */
    function balanceOf(address account) external view returns (uint256);

    /**
     * @notice Deposit ETH on behalf of `account`.
     */
    function depositTo(address account) external payable;

    /**
     * @notice Withdraw `withdrawAmount` of ETH from the EntryPoint deposit.
     */
    function withdrawTo(address payable withdrawAddress, uint256 withdrawAmount) external;

    /**
     * @notice Returns the on-chain nonce for `sender` at `key` (ERC-4337 §3.1).
     */
    function getNonce(address sender, uint192 key) external view returns (uint256 nonce);
}

/**
 * @title IPaymaster
 * @notice Interface that a Paymaster contract must expose so that the EntryPoint
 *         can validate and post-process gas sponsorship.
 */
interface IPaymaster {
    /**
     * @notice Called by the EntryPoint before executing the user operation.
     * @param userOp      The user operation being validated.
     * @param userOpHash  Hash of the user operation.
     * @param maxCost     Maximum gas cost the paymaster may be charged.
     * @return context    Arbitrary data forwarded to `postOp`.
     * @return validationData Same encoding as IAccount.validateUserOp.
     */
    function validatePaymasterUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 maxCost
    ) external returns (bytes memory context, uint256 validationData);

    /**
     * @notice Called by the EntryPoint after the user operation has been executed.
     * @param mode    0 = success, 1 = revert, 2 = postOp revert.
     * @param context The value returned by `validatePaymasterUserOp`.
     * @param actualGasCost Actual gas cost charged (in wei).
     * @param actualUserOpFeePerGas The fee per gas used for the operation.
     */
    function postOp(
        uint8 mode,
        bytes calldata context,
        uint256 actualGasCost,
        uint256 actualUserOpFeePerGas
    ) external;
}

// ---------------------------------------------------------------------------
// AegisSmartAccount
// ---------------------------------------------------------------------------

/**
 * @title AegisSmartAccount
 * @author Aegis Protocol – Principal Blockchain Engineering Team
 * @notice Institutional-grade ERC-4337 Smart Contract Wallet with:
 *         - ECDSA-based `validateUserOp` for EntryPoint integration
 *         - ERC-6900-style modular execution (`execute`, `executeBatch`)
 *         - ZK-SNARK privacy hook (`validateZkProof`) — placeholder for Noir/Circom
 *         - Selective-Disclosure Viewing Keys Registry (`encryptedViewingKeys`)
 *         - EURC collateral-integrity constraint (`onlyCompliantEURC`)
 *         - Role-based access control via OpenZeppelin AccessControl
 * @dev All functions follow the ERC-4337 v0.7 specification.
 *      Gas optimisations applied: `calldata` over `memory` wherever possible,
 *      tight struct packing, and `unchecked` arithmetic for loop counters.
 */
contract AegisSmartAccount is IAccount, AccessControl, ReentrancyGuard {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;
    using SafeERC20 for IERC20;

    // ------------------------------------------------------------------
    // Constants & roles
    // ------------------------------------------------------------------

    /// @notice Magic value returned by `validateUserOp` on success (ERC-4337).
    uint256 private constant _SIG_VALIDATION_SUCCESS = 0;

    /// @notice Magic value returned by `validateUserOp` on signature failure (ERC-4337).
    uint256 private constant _SIG_VALIDATION_FAILED = 1;

    /// @notice Role granted to the owner / primary signer of this account.
    bytes32 public constant OWNER_ROLE = keccak256("OWNER_ROLE");

    /// @notice Role granted to authorised regulatory entities allowed to register viewing keys.
    bytes32 public constant REGULATOR_ROLE = keccak256("REGULATOR_ROLE");

    /// @notice Role granted to ZK-proof verifier contracts / off-chain oracles.
    bytes32 public constant ZK_VERIFIER_ROLE = keccak256("ZK_VERIFIER_ROLE");

    // ------------------------------------------------------------------
    // Immutables
    // ------------------------------------------------------------------

    /// @notice The canonical ERC-4337 EntryPoint this account is bound to.
    IEntryPoint public immutable entryPoint;

    /// @notice The EURC token address for the Aegis collateral constraint.
    address public immutable eurcToken;

    // ------------------------------------------------------------------
    // State
    // ------------------------------------------------------------------

    /**
     * @notice Viewing Keys Registry for Selective Disclosure.
     * @dev Maps a subject address to its AES-256-GCM encrypted viewing key
     *      (encrypted off-chain with the regulator's public key).
     *      Regulators with the appropriate private key can decrypt metadata.
     */
    mapping(address => bytes) public encryptedViewingKeys;

    /**
     * @notice Registry of ZK-proof hashes that have been validated on-chain.
     * @dev Maps a `proofHash` (keccak256 of the ZK proof's public inputs) to
     *      the keccak256 hash of the calldata the proof commits to.
     *      A zero value means the proof has not been registered.
     */
    mapping(bytes32 => bytes32) public verifiedProofs;

    // ------------------------------------------------------------------
    // Events
    // ------------------------------------------------------------------

    /// @notice Emitted when the account successfully executes a single call.
    event Executed(address indexed target, uint256 value, bytes data);

    /// @notice Emitted when the account successfully executes a batch of calls.
    event BatchExecuted(uint256 indexed callCount);

    /// @notice Emitted when a ZK proof is validated and recorded.
    event ZkProofValidated(bytes32 indexed proofHash, address indexed caller);

    /// @notice Emitted when an encrypted viewing key is registered.
    event ViewingKeyRegistered(address indexed subject, address indexed registrar);

    /// @notice Emitted when ETH is pre-funded into the EntryPoint.
    event EntryPointPrefunded(uint256 amount);

    // ------------------------------------------------------------------
    // Errors
    // ------------------------------------------------------------------

    /// @dev Thrown when `msg.sender` is neither the owner nor the EntryPoint.
    error UnauthorizedCaller(address caller);

    /// @dev Thrown when a ZK proof has not been validated for the given hash.
    error InvalidZkProof(bytes32 proofHash);

    /// @dev Thrown when a token address other than EURC is used.
    error NonCompliantToken(address token);

    /// @dev Thrown when a low-level call inside `execute` or `executeBatch` reverts.
    error CallFailed(uint256 index, bytes returnData);

    /// @dev Thrown when `executeBatch` receives mismatched array lengths.
    error BatchLengthMismatch();

    // ------------------------------------------------------------------
    // Modifiers
    // ------------------------------------------------------------------

    /**
     * @notice Restricts access to the canonical EntryPoint or the account owner.
     * @dev Used on `execute`, `executeBatch`, and other privileged functions so
     *      that they can be driven either by the EntryPoint (UserOp flow) or
     *      directly by an authorised owner (e.g. via `eth_sendTransaction`).
     */
    modifier onlyEntryPointOrOwner() {
        if (msg.sender != address(entryPoint) && !hasRole(OWNER_ROLE, msg.sender)) {
            revert UnauthorizedCaller(msg.sender);
        }
        _;
    }

    /**
     * @notice Ensures the supplied token address is the protocol-approved EURC token.
     * @dev Guarantees 1:1 collateral integrity by preventing interaction with
     *      arbitrary ERC-20 contracts.
     * @param token The ERC-20 token address to validate.
     */
    modifier onlyCompliantEURC(address token) {
        if (token != eurcToken) {
            revert NonCompliantToken(token);
        }
        _;
    }

    // ------------------------------------------------------------------
    // Constructor
    // ------------------------------------------------------------------

    /**
     * @notice Deploy a new AegisSmartAccount.
     * @param _entryPoint The address of the canonical ERC-4337 EntryPoint.
     * @param _owner      The address that will hold the OWNER_ROLE.
     * @param _eurcToken  The address of the Aegis EURC token (collateral constraint).
     */
    constructor(address _entryPoint, address _owner, address _eurcToken) {
        require(_entryPoint != address(0), "AegisSmartAccount: zero entryPoint");
        require(_owner != address(0), "AegisSmartAccount: zero owner");
        require(_eurcToken != address(0), "AegisSmartAccount: zero eurcToken");

        entryPoint = IEntryPoint(_entryPoint);
        eurcToken = _eurcToken;

        // AccessControl: the deployer grants OWNER_ROLE to _owner and renounces admin.
        _grantRole(DEFAULT_ADMIN_ROLE, _owner);
        _grantRole(OWNER_ROLE, _owner);
    }

    // ------------------------------------------------------------------
    // Receive / Fallback
    // ------------------------------------------------------------------

    /// @notice Allow the account to receive ETH (e.g. for EntryPoint pre-funding).
    receive() external payable {}

    // ------------------------------------------------------------------
    // ERC-4337 – validateUserOp
    // ------------------------------------------------------------------

    /**
     * @notice Validate a User Operation submitted by the EntryPoint.
     * @dev Implements IAccount.validateUserOp (ERC-4337 §4.2).
     *      Validation steps:
     *        1. Verify that `msg.sender` is the trusted EntryPoint.
     *        2. Recover the signer from the EIP-191 hash of `userOpHash`.
     *        3. Confirm the recovered address holds OWNER_ROLE.
     *        4. Pre-fund the EntryPoint if `missingAccountFunds > 0`.
     *      The function never reverts — it returns `_SIG_VALIDATION_FAILED` on
     *      invalid signatures so that bundlers can handle the failure gracefully.
     * @param userOp          The packed user operation.
     * @param userOpHash      ERC-4337 hash covering the op + chain-id + entryPoint.
     * @param missingAccountFunds ETH the account must send to the EntryPoint.
     * @return validationData 0 on success, 1 on signature failure (ERC-4337 §4.2).
     */
    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external override returns (uint256 validationData) {
        // Only the bound EntryPoint is allowed to call this function.
        if (msg.sender != address(entryPoint)) {
            revert UnauthorizedCaller(msg.sender);
        }

        // Validate the ECDSA signature over the EIP-191 prefixed hash.
        validationData = _validateSignature(userOp, userOpHash);

        // Pre-fund the EntryPoint deposit if required.
        if (missingAccountFunds > 0) {
            entryPoint.depositTo{value: missingAccountFunds}(address(this));
            emit EntryPointPrefunded(missingAccountFunds);
        }
    }

    // ------------------------------------------------------------------
    // ERC-6900-style Modular Execution
    // ------------------------------------------------------------------

    /**
     * @notice Execute a single low-level call from this account.
     * @dev Can be called by the EntryPoint (UserOp flow) or directly by the owner.
     *      Emits {Executed} on success.
     * @param target The address to call.
     * @param value  Native ETH value to forward (in wei).
     * @param data   Encoded call data.
     * @return returnData The raw bytes returned by the target.
     */
    function execute(
        address target,
        uint256 value,
        bytes calldata data
    ) external onlyEntryPointOrOwner nonReentrant returns (bytes memory returnData) {
        returnData = _call(target, value, data, 0);
        emit Executed(target, value, data);
    }

    /**
     * @notice Execute a batch of calls atomically from this account.
     * @dev All calls are executed in order; the entire batch reverts on any single failure.
     *      Array lengths for `targets`, `values`, and `dataArr` must match.
     *      Emits {BatchExecuted} with the number of calls on success.
     * @param targets Array of destination addresses.
     * @param values  Array of native ETH amounts (in wei) per call.
     * @param dataArr Array of encoded call data per call.
     */
    function executeBatch(
        address[] calldata targets,
        uint256[] calldata values,
        bytes[] calldata dataArr
    ) external onlyEntryPointOrOwner nonReentrant {
        uint256 len = targets.length;
        if (len != values.length || len != dataArr.length) {
            revert BatchLengthMismatch();
        }

        for (uint256 i; i < len;) {
            _call(targets[i], values[i], dataArr[i], i);
            unchecked { ++i; }
        }

        emit BatchExecuted(len);
    }

    // ------------------------------------------------------------------
    // The Shield – ZK-Privacy Hook
    // ------------------------------------------------------------------

    /**
     * @notice Validate a ZK-SNARK proof before allowing privacy-sensitive operations.
     * @dev Acts as a guardian gate for operations that require zero-knowledge
     *      attestation. This is a placeholder integration point for Noir / Circom
     *      verifier contracts. In production, replace the placeholder body with a
     *      call to the on-chain SNARK verifier (e.g. `IVerifier(verifier).verify(...)`).
     *
     *      Workflow:
     *        1. A `ZK_VERIFIER_ROLE` holder (typically the on-chain SNARK verifier contract)
     *           calls `registerZkProof(proofHash, calldataHash)` after verifying the proof,
     *           where `proofHash = keccak256(publicInputs)` and
     *           `calldataHash = keccak256(calleeData)`.
     *        2. The caller invokes `validateZkProof(proofHash, calleeData)`.
     *        3. This function confirms that `proofHash` was registered and that the
     *           registered calldata commitment matches the supplied `calleeData`.
     *        4. Emits {ZkProofValidated} on success; reverts otherwise.
     *
     * @param proofHash  keccak256 of the ZK proof's public inputs, as registered by the verifier.
     * @param calleeData Encoded calldata that the proof commits to.
     */
    function validateZkProof(
        bytes32 proofHash,
        bytes calldata calleeData
    ) external {
        // Retrieve the calldata hash that was committed to when the proof was registered.
        bytes32 committedCalldataHash = verifiedProofs[proofHash];
        if (committedCalldataHash == bytes32(0)) {
            revert InvalidZkProof(proofHash);
        }

        // Confirm the supplied calleeData matches the committed calldata hash.
        if (keccak256(calleeData) != committedCalldataHash) {
            revert InvalidZkProof(proofHash);
        }

        emit ZkProofValidated(proofHash, msg.sender);
    }

    /**
     * @notice Register a validated ZK proof on-chain.
     * @dev Only accounts holding `ZK_VERIFIER_ROLE` may call this function.
     *      In production, this role should be assigned exclusively to the deployed
     *      Noir/Circom verifier contract so that proofs cannot be registered without
     *      passing the cryptographic verification step.
     * @param proofHash    keccak256 of the ZK proof's public inputs.
     * @param calldataHash keccak256 of the calldata the proof commits to.
     */
    function registerZkProof(
        bytes32 proofHash,
        bytes32 calldataHash
    ) external onlyRole(ZK_VERIFIER_ROLE) {
        require(calldataHash != bytes32(0), "AegisSmartAccount: zero calldataHash");
        verifiedProofs[proofHash] = calldataHash;
        emit ZkProofValidated(proofHash, msg.sender);
    }

    // ------------------------------------------------------------------
    // Viewing Keys Registry – Selective Disclosure
    // ------------------------------------------------------------------

    /**
     * @notice Register an encrypted viewing key for a subject address.
     * @dev Only accounts holding `REGULATOR_ROLE` may call this function.
     *      The `encryptedKey` must be the subject's viewing key encrypted with
     *      the regulator's public key (e.g. ECIES / AES-256-GCM off-chain).
     *      Emits {ViewingKeyRegistered}.
     * @param subject      The on-chain address the viewing key pertains to.
     * @param encryptedKey The encrypted viewing key bytes (ciphertext + IV + tag).
     */
    function registerViewingKey(
        address subject,
        bytes calldata encryptedKey
    ) external onlyRole(REGULATOR_ROLE) {
        encryptedViewingKeys[subject] = encryptedKey;
        emit ViewingKeyRegistered(subject, msg.sender);
    }

    /**
     * @notice Revoke the encrypted viewing key for a subject address.
     * @dev Only accounts holding `REGULATOR_ROLE` may call this function.
     * @param subject The on-chain address whose viewing key is to be deleted.
     */
    function revokeViewingKey(address subject) external onlyRole(REGULATOR_ROLE) {
        delete encryptedViewingKeys[subject];
    }

    // ------------------------------------------------------------------
    // EURC Collateral Helpers
    // ------------------------------------------------------------------

    /**
     * @notice Transfer EURC tokens from this account to `recipient`.
     * @dev Enforces the `onlyCompliantEURC` constraint — any attempt to use
     *      a token other than the protocol-approved EURC address will revert.
     *      Can only be initiated by the EntryPoint (via UserOp) or the owner.
     * @param token     Must equal `eurcToken`; enforced by `onlyCompliantEURC`.
     * @param recipient The address that will receive the EURC tokens.
     * @param amount    Amount of EURC (in its smallest unit) to transfer.
     */
    function transferEURC(
        address token,
        address recipient,
        uint256 amount
    ) external onlyEntryPointOrOwner onlyCompliantEURC(token) nonReentrant {
        IERC20(token).safeTransfer(recipient, amount);
    }

    // ------------------------------------------------------------------
    // EntryPoint Deposit Management
    // ------------------------------------------------------------------

    /**
     * @notice Deposit ETH into the EntryPoint on behalf of this account.
     * @dev Anyone may top up the account's EntryPoint deposit.
     */
    function addDeposit() external payable {
        entryPoint.depositTo{value: msg.value}(address(this));
    }

    /**
     * @notice Withdraw ETH from the EntryPoint deposit.
     * @param withdrawAddress Destination for the withdrawn ETH.
     * @param amount          Amount of ETH to withdraw (in wei).
     */
    function withdrawDeposit(
        address payable withdrawAddress,
        uint256 amount
    ) external onlyRole(OWNER_ROLE) {
        entryPoint.withdrawTo(withdrawAddress, amount);
    }

    /**
     * @notice Returns the ETH deposit balance held by the EntryPoint for this account.
     */
    function getDeposit() external view returns (uint256) {
        return entryPoint.balanceOf(address(this));
    }

    // ------------------------------------------------------------------
    // Internal Helpers
    // ------------------------------------------------------------------

    /**
     * @dev Validate the ECDSA signature inside a UserOperation.
     *      Returns `_SIG_VALIDATION_SUCCESS` (0) if the recovered signer holds
     *      OWNER_ROLE, `_SIG_VALIDATION_FAILED` (1) otherwise.
     *      Does NOT revert so that the EntryPoint can handle failures gracefully.
     */
    function _validateSignature(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    ) internal view returns (uint256) {
        // EIP-191: "\x19Ethereum Signed Message:\n32" prefix.
        bytes32 ethSignedHash = userOpHash.toEthSignedMessageHash();

        // Recover signer; ECDSA.recover reverts on malformed signatures, so we use tryRecover.
        (address recovered, ECDSA.RecoverError err,) = ECDSA.tryRecover(ethSignedHash, userOp.signature);
        if (err != ECDSA.RecoverError.NoError) {
            return _SIG_VALIDATION_FAILED;
        }
        if (!hasRole(OWNER_ROLE, recovered)) {
            return _SIG_VALIDATION_FAILED;
        }
        return _SIG_VALIDATION_SUCCESS;
    }

    /**
     * @dev Execute a single low-level call and revert on failure.
     * @param target The destination address.
     * @param value  ETH value to forward.
     * @param data   Encoded calldata.
     * @param index  Position in the batch (used in error reporting).
     */
    function _call(
        address target,
        uint256 value,
        bytes calldata data,
        uint256 index
    ) internal returns (bytes memory returnData) {
        bool ok;
        (ok, returnData) = target.call{value: value}(data);
        if (!ok) {
            revert CallFailed(index, returnData);
        }
    }
}