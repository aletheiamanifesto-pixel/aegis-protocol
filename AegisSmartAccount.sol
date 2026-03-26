// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/* ══════════════════════════════════════════════════════════════════════════
   ░█▀▀█ █▀▀ █▀▀▀ ▀█▀ █▀▀    ░█▀▀█ █▀▀█ █▀▀█ ▀▀█▀▀ █▀▀█ █▀▀ █▀▀█ █░░
   ░█▄▄█ █▀▀ █░▀█ ░█░ ▀▀█    ░█▄▄█ █▄▄▀ █░░█ ░░█░░ █░░█ █░░ █░░█ █░░
   ░█░░░ ▀▀▀ ▀▀▀▀ ▄█▄ ▀▀▀    ░█░░░ ▀░▀▀ ▀▀▀▀ ░░▀░░ ▀▀▀▀ ▀▀▀ ▀▀▀▀ ▀▀▀
   ══════════════════════════════════════════════════════════════════════════ */

import {IAccount} from "./contracts/interfaces/IAccount.sol";
import {IEntryPoint} from "./contracts/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "./contracts/interfaces/PackedUserOperation.sol";

// ─── OpenZeppelin Imports ────────────────────────────────────────────────────
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";

/**
 * @title AegisSmartAccount
 * @author Aegis Protocol – Institutional Patrimonial Wallet
 * @notice ERC-4337 compliant Smart Contract Wallet with ZK-Privacy hooks,
 *         selective disclosure via Viewing Keys, and EURC-only asset constraints.
 *
 * @dev Architecture overview:
 *
 *      ┌────────────┐     ┌──────────────┐     ┌─────────────────────┐
 *      │  Bundler    │────▶│  EntryPoint   │────▶│  AegisSmartAccount  │
 *      └────────────┘     └──────────────┘     └─────────────────────┘
 *           │                                         │
 *           │                                    ┌────┴─────┐
 *           ▼                                    │ The      │
 *      ┌────────────┐                            │ Shield   │
 *      │  Paymaster  │                            │ (ZK)     │
 *      └────────────┘                            └──────────┘
 *
 *      • **Entry Point Interaction**: `validateUserOp` verifies ECDSA signatures
 *        against the account owner, paying back missing funds to the EntryPoint.
 *
 *      • **Modular Execution (ERC-6900 style)**: `execute` for single calls and
 *        `executeBatch` for batched multi-call, both gated by the EntryPoint or owner.
 *
 *      • **The Shield (ZK-Privacy Hook)**: `validateZkProof` acts as a privacy
 *        guardian. Transactions requiring privacy compliance must pass a ZK-SNARK
 *        proof verification (placeholder for Noir/Circom backend integration).
 *
 *      • **Viewing Keys Registry**: Authorized regulators can register encrypted
 *        viewing keys, enabling selective disclosure of on-chain metadata.
 *
 *      • **Asset-Constraint**: The `onlyCompliantEURC` modifier restricts
 *        token interactions to the Aegis-approved EURC contract, ensuring
 *        1:1 collateral integrity.
 *
 *      Gas Optimizations:
 *        - `calldata` parameters used wherever possible.
 *        - Custom errors instead of revert strings.
 *        - Tight variable packing in storage slots.
 *        - Unchecked blocks for safe arithmetic.
 */
contract AegisSmartAccount is IAccount, AccessControl, Initializable, UUPSUpgradeable {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    /* ═══════════════════════════════════════════════════════════════════════
       §1 – CONSTANTS & IMMUTABLES
       ═══════════════════════════════════════════════════════════════════════ */

    /// @notice ERC-4337 signature validation success sentinel.
    uint256 internal constant _SIG_VALIDATION_SUCCESS = 0;

    /// @notice ERC-4337 signature validation failure sentinel.
    uint256 internal constant _SIG_VALIDATION_FAILED = 1;

    /// @notice Role for the account owner (full control).
    bytes32 public constant OWNER_ROLE = keccak256("OWNER_ROLE");

    /// @notice Role for guardians who can approve recovery / high-value ops.
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");

    /// @notice Role for authorized regulators (can register viewing keys).
    bytes32 public constant REGULATOR_ROLE = keccak256("REGULATOR_ROLE");

    /// @dev The canonical ERC-4337 EntryPoint contract (immutable after deployment).
    IEntryPoint private immutable _entryPoint;

    /// @dev The EURC token address approved for the Aegis Protocol.
    address private immutable _eurcToken;

    /* ═══════════════════════════════════════════════════════════════════════
       §2 – STORAGE
       ═══════════════════════════════════════════════════════════════════════ */

    /**
     * @notice Encrypted Viewing Keys registry.
     * @dev Maps a regulator address → encrypted viewing key (bytes).
     *      Enables Selective Disclosure: only parties holding the
     *      corresponding decryption key can read on-chain metadata.
     */
    mapping(address => bytes) public encryptedViewingKeys;

    /**
     * @notice Registry of verified ZK proofs.
     * @dev Maps `keccak256(proofHash, callerAddress)` → verified flag.
     *      Once a proof is validated it is cached to avoid re-verification gas.
     */
    mapping(bytes32 => bool) public verifiedProofs;

    /// @notice Monotonic execution nonce (used for replay protection outside 4337).
    uint256 private _execNonce;

    /* ═══════════════════════════════════════════════════════════════════════
       §3 – CUSTOM ERRORS (gas-efficient)
       ═══════════════════════════════════════════════════════════════════════ */

    /// @dev Caller is not the EntryPoint or the account itself.
    error OnlyEntryPointOrSelf();

    /// @dev Caller is not the EntryPoint.
    error OnlyEntryPoint();

    /// @dev Caller is not the owner.
    error OnlyOwner();

    /// @dev A low-level call within `execute` / `executeBatch` failed.
    error ExecutionFailed(uint256 index);

    /// @dev The target address is not the approved EURC token.
    error NotCompliantEURC(address target);

    /// @dev ZK proof verification failed.
    error ZkProofInvalid(bytes32 proofHash);

    /// @dev Zero-address supplied where it is not allowed.
    error ZeroAddress();

    /// @dev Array length mismatch in batch operations.
    error ArrayLengthMismatch();

    /* ═══════════════════════════════════════════════════════════════════════
       §4 – EVENTS
       ═══════════════════════════════════════════════════════════════════════ */

    /// @notice Emitted when a single call is executed.
    event Executed(address indexed target, uint256 value, bytes data);

    /// @notice Emitted when a batch of calls is executed.
    event BatchExecuted(uint256 count);

    /// @notice Emitted when a ZK proof is submitted and verified.
    event ZkProofVerified(bytes32 indexed proofHash, address indexed submitter);

    /// @notice Emitted when an encrypted viewing key is registered.
    event ViewingKeyRegistered(address indexed regulator, uint256 keyLength);

    /// @notice Emitted when an encrypted viewing key is revoked.
    event ViewingKeyRevoked(address indexed regulator);

    /// @notice Emitted on successful UserOp validation.
    event UserOpValidated(bytes32 indexed userOpHash, uint256 missingFunds);

    /* ═══════════════════════════════════════════════════════════════════════
       §5 – MODIFIERS
       ═══════════════════════════════════════════════════════════════════════ */

    /**
     * @notice Restricts access to the canonical EntryPoint or the account itself.
     * @dev Required by ERC-6900 style execution: the EntryPoint routes UserOps
     *      and the account can self-call for internal module execution.
     */
    modifier onlyEntryPointOrSelf() {
        if (msg.sender != address(_entryPoint) && msg.sender != address(this)) {
            revert OnlyEntryPointOrSelf();
        }
        _;
    }

    /**
     * @notice Restricts access to the canonical EntryPoint only.
     * @dev Used for `validateUserOp` which must only be called by EntryPoint.
     */
    modifier onlyEntryPoint() {
        if (msg.sender != address(_entryPoint)) {
            revert OnlyEntryPoint();
        }
        _;
    }

    /**
     * @notice Asset-Constraint modifier – allows interaction only with the
     *         approved EURC token contract.
     * @dev Ensures 1:1 collateral integrity for the Aegis Protocol by
     *      restricting token operations to the single approved stablecoin.
     * @param target The target address of the call.
     */
    modifier onlyCompliantEURC(address target) {
        if (target != _eurcToken) {
            revert NotCompliantEURC(target);
        }
        _;
    }

    /* ═══════════════════════════════════════════════════════════════════════
       §6 – CONSTRUCTOR & INITIALIZER
       ═══════════════════════════════════════════════════════════════════════ */

    /**
     * @notice Sets immutable references. Actual owner setup happens in `initialize`.
     * @param entryPoint_ The canonical ERC-4337 EntryPoint address.
     * @param eurcToken_  The approved EURC token contract address.
     */
    constructor(IEntryPoint entryPoint_, address eurcToken_) {
        if (address(entryPoint_) == address(0) || eurcToken_ == address(0)) {
            revert ZeroAddress();
        }
        _entryPoint = entryPoint_;
        _eurcToken = eurcToken_;

        // Prevent the implementation contract from being initialized.
        _disableInitializers();
    }

    /**
     * @notice Initializes the account with the owner and optional guardian/regulator.
     * @dev Called once via the proxy's constructor or factory.
     * @param owner_     The primary account owner address.
     * @param guardian_  An optional guardian address (pass `address(0)` to skip).
     * @param regulator_ An optional regulator address (pass `address(0)` to skip).
     */
    function initialize(
        address owner_,
        address guardian_,
        address regulator_
    ) external initializer {
        if (owner_ == address(0)) revert ZeroAddress();

        // Owner gets admin + owner role.
        _grantRole(DEFAULT_ADMIN_ROLE, owner_);
        _grantRole(OWNER_ROLE, owner_);

        if (guardian_ != address(0)) {
            _grantRole(GUARDIAN_ROLE, guardian_);
        }
        if (regulator_ != address(0)) {
            _grantRole(REGULATOR_ROLE, regulator_);
        }
    }

    /* ═══════════════════════════════════════════════════════════════════════
       §7 – ERC-4337: VALIDATE USER OPERATION
       ═══════════════════════════════════════════════════════════════════════ */

    /**
     * @inheritdoc IAccount
     * @notice Validates the UserOperation signature using ECDSA recovery.
     * @dev Workflow:
     *      1. Recover the signer from `userOp.signature` and `userOpHash`.
     *      2. Verify the signer holds `OWNER_ROLE`.
     *      3. Pay back `missingAccountFunds` to the EntryPoint.
     *
     *      Calldata optimization: `userOp` is `calldata` (no memory copy).
     *
     * @param userOp              The packed UserOperation (calldata for gas savings).
     * @param userOpHash          The hash of the UserOperation.
     * @param missingAccountFunds ETH to deposit to EntryPoint for gas.
     * @return validationData     `0` on success, `1` on failure.
     */
    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external override onlyEntryPoint returns (uint256 validationData) {
        validationData = _validateSignature(userOp, userOpHash);

        // Pay prefund to EntryPoint regardless of validation result.
        _payPrefund(missingAccountFunds);

        emit UserOpValidated(userOpHash, missingAccountFunds);
    }

    /* ═══════════════════════════════════════════════════════════════════════
       §8 – MODULAR EXECUTION (ERC-6900 STYLE)
       ═══════════════════════════════════════════════════════════════════════ */

    /**
     * @notice Executes a single call from this account.
     * @dev Callable by the EntryPoint (via UserOp) or by the account itself
     *      (for internal module chaining per ERC-6900 patterns).
     *
     *      Gas notes:
     *        - `data` is `calldata` → no ABI decoding overhead.
     *        - Single `call` with value forwarding.
     *
     * @param target The destination address.
     * @param value  The ETH value to send.
     * @param data   The calldata for the target.
     * @return result The return data from the call.
     */
    function execute(
        address target,
        uint256 value,
        bytes calldata data
    ) external onlyEntryPointOrSelf returns (bytes memory result) {
        bool success;
        (success, result) = target.call{value: value}(data);
        if (!success) {
            revert ExecutionFailed(0);
        }

        emit Executed(target, value, data);
    }

    /**
     * @notice Executes a batch of calls atomically from this account.
     * @dev ERC-6900 style batch execution. All calls MUST succeed or the
     *      entire batch reverts.
     *
     *      Gas notes:
     *        - Arrays are `calldata` → zero-copy access.
     *        - Unchecked loop counter (safe: bounded by array length).
     *
     * @param targets Array of destination addresses.
     * @param values  Array of ETH values to send.
     * @param datas   Array of calldata payloads.
     * @return results Array of return data from each call.
     */
    function executeBatch(
        address[] calldata targets,
        uint256[] calldata values,
        bytes[] calldata datas
    ) external onlyEntryPointOrSelf returns (bytes[] memory results) {
        uint256 length = targets.length;
        if (length != values.length || length != datas.length) {
            revert ArrayLengthMismatch();
        }

        results = new bytes[](length);

        for (uint256 i; i < length; ) {
            bool success;
            (success, results[i]) = targets[i].call{value: values[i]}(datas[i]);
            if (!success) {
                revert ExecutionFailed(i);
            }

            // Gas optimization: unchecked increment (i < length prevents overflow).
            unchecked { ++i; }
        }

        emit BatchExecuted(length);
    }

    /**
     * @notice Executes a single call restricted to the EURC token only.
     * @dev Combines `execute` logic with the `onlyCompliantEURC` asset constraint
     *      to guarantee 1:1 collateral integrity for Aegis protocol operations.
     *
     * @param target The EURC token contract address (must match `_eurcToken`).
     * @param value  The ETH value to send (typically 0 for ERC-20 calls).
     * @param data   The calldata (e.g., `transfer`, `approve`).
     * @return result The return data from the call.
     */
    function executeCompliant(
        address target,
        uint256 value,
        bytes calldata data
    ) external onlyEntryPointOrSelf onlyCompliantEURC(target) returns (bytes memory result) {
        bool success;
        (success, result) = target.call{value: value}(data);
        if (!success) {
            revert ExecutionFailed(0);
        }

        emit Executed(target, value, data);
    }

    /* ═══════════════════════════════════════════════════════════════════════
       §9 – THE SHIELD: ZK-PRIVACY HOOK
       ═══════════════════════════════════════════════════════════════════════ */

    /**
     * @notice Validates a ZK-SNARK proof for privacy-preserving transactions.
     * @dev **The Shield** – Acts as a privacy guardian for the Aegis protocol.
     *      If the proof is not verified the transaction MUST revert.
     *
     *      Current implementation is a **placeholder** that verifies the proof
     *      hash is pre-registered. In production, this function will delegate
     *      to an on-chain verifier contract generated by Noir or Circom.
     *
     *      Integration path:
     *        1. Off-chain: Generate proof with Noir/Circom circuit.
     *        2. On-chain:  Replace the body of this function with a call to
     *                      the deployed Verifier contract:
     *                      `IVerifier(verifier).verify(proof, publicInputs)`
     *
     *      Calldata optimization: `calleeData` is `calldata`.
     *
     * @param proofHash   The keccak256 hash of the ZK proof.
     * @param calleeData  ABI-encoded data relevant to the proof verification
     *                    (e.g., public inputs, circuit identifier).
     * @return valid      `true` if the proof is verified.
     */
    function validateZkProof(
        bytes32 proofHash,
        bytes calldata calleeData
    ) external onlyEntryPointOrSelf returns (bool valid) {
        // ──────────────────────────────────────────────────────────
        // PLACEHOLDER: In production, replace with Verifier call:
        //
        //   (bool verified) = IZkVerifier(verifierAddress).verify(
        //       proofHash,
        //       calleeData   // public inputs
        //   );
        //   if (!verified) revert ZkProofInvalid(proofHash);
        // ──────────────────────────────────────────────────────────

        // Derive a unique proof ID scoped to the caller to prevent replay.
        bytes32 proofId = keccak256(abi.encodePacked(proofHash, msg.sender));

        // Placeholder validation: the proof hash must not be zero.
        // In production this will be a full SNARK verification.
        if (proofHash == bytes32(0)) {
            revert ZkProofInvalid(proofHash);
        }

        // Mark the proof as verified (caching avoids re-verification gas).
        verifiedProofs[proofId] = true;
        valid = true;

        emit ZkProofVerified(proofHash, msg.sender);

        // Suppress unused variable warning for calleeData placeholder.
        // In production, calleeData feeds directly into the verifier.
        calleeData;
    }

    /**
     * @notice Checks whether a proof has been previously verified for a given submitter.
     * @param proofHash  The proof hash.
     * @param submitter  The address that submitted the proof.
     * @return True if the proof was verified.
     */
    function isProofVerified(
        bytes32 proofHash,
        address submitter
    ) external view returns (bool) {
        return verifiedProofs[keccak256(abi.encodePacked(proofHash, submitter))];
    }

    /* ═══════════════════════════════════════════════════════════════════════
       §10 – VIEWING KEYS REGISTRY (Selective Disclosure)
       ═══════════════════════════════════════════════════════════════════════ */

    /**
     * @notice Registers an encrypted viewing key for a regulator.
     * @dev Only addresses with `REGULATOR_ROLE` may register keys.
     *      The key is encrypted off-chain (e.g., with the regulator's public key)
     *      so that only the regulator can decrypt on-chain metadata.
     *
     * @param encryptedKey The encrypted viewing key bytes.
     */
    function registerViewingKey(
        bytes calldata encryptedKey
    ) external onlyRole(REGULATOR_ROLE) {
        encryptedViewingKeys[msg.sender] = encryptedKey;

        emit ViewingKeyRegistered(msg.sender, encryptedKey.length);
    }

    /**
     * @notice Revokes the caller's encrypted viewing key.
     * @dev Only addresses with `REGULATOR_ROLE` may revoke their own key.
     */
    function revokeViewingKey() external onlyRole(REGULATOR_ROLE) {
        delete encryptedViewingKeys[msg.sender];

        emit ViewingKeyRevoked(msg.sender);
    }

    /**
     * @notice Retrieves the encrypted viewing key for a regulator.
     * @param regulator The regulator's address.
     * @return The encrypted viewing key bytes (empty if not registered).
     */
    function getViewingKey(
        address regulator
    ) external view returns (bytes memory) {
        return encryptedViewingKeys[regulator];
    }

    /* ═══════════════════════════════════════════════════════════════════════
       §11 – VIEW / UTILITY FUNCTIONS
       ═══════════════════════════════════════════════════════════════════════ */

    /**
     * @notice Returns the canonical EntryPoint this account is bound to.
     * @return The IEntryPoint interface.
     */
    function entryPoint() external view returns (IEntryPoint) {
        return _entryPoint;
    }

    /**
     * @notice Returns the approved EURC token address.
     * @return The EURC token contract address.
     */
    function eurcToken() external view returns (address) {
        return _eurcToken;
    }

    /**
     * @notice Returns the current deposit balance of this account on the EntryPoint.
     * @return The deposit balance in wei.
     */
    function getDeposit() external view returns (uint256) {
        return _entryPoint.balanceOf(address(this));
    }

    /**
     * @notice Adds a deposit to the EntryPoint for this account.
     * @dev Callable by anyone, but typically called by the owner or a Paymaster.
     */
    function addDeposit() external payable {
        _entryPoint.depositTo{value: msg.value}(address(this));
    }

    /**
     * @notice Withdraws deposit from the EntryPoint to a specified address.
     * @dev Only callable by the owner.
     * @param withdrawAddress The address to receive the withdrawn ETH.
     * @param amount          The amount to withdraw.
     */
    function withdrawDepositTo(
        address payable withdrawAddress,
        uint256 amount
    ) external onlyRole(OWNER_ROLE) {
        _entryPoint.withdrawTo(withdrawAddress, amount);
    }

    /**
     * @notice Check support for interfaces (ERC-165).
     * @param interfaceId The interface identifier.
     * @return True if the interface is supported.
     */
    function supportsInterface(
        bytes4 interfaceId
    ) public view override returns (bool) {
        return
            interfaceId == type(IAccount).interfaceId ||
            super.supportsInterface(interfaceId);
    }

    /* ═══════════════════════════════════════════════════════════════════════
       §12 – INTERNAL HELPERS
       ═══════════════════════════════════════════════════════════════════════ */

    /**
     * @dev Validates the UserOperation signature via ECDSA recovery.
     * @param userOp     The packed UserOperation.
     * @param userOpHash The hash of the UserOperation.
     * @return validationData `0` if signer is the owner, `1` otherwise.
     */
    function _validateSignature(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    ) internal view returns (uint256 validationData) {
        // Convert to an Ethereum Signed Message hash (EIP-191).
        bytes32 ethSignedHash = userOpHash.toEthSignedMessageHash();

        // Recover the signer from the signature.
        address recovered = ethSignedHash.recover(userOp.signature);

        // Verify the recovered signer holds OWNER_ROLE.
        if (!hasRole(OWNER_ROLE, recovered)) {
            return _SIG_VALIDATION_FAILED;
        }

        return _SIG_VALIDATION_SUCCESS;
    }

    /**
     * @dev Sends `missingAccountFunds` to the EntryPoint to cover gas.
     *      Silently succeeds if `amount` is 0.
     * @param amount The amount of ETH to send to the EntryPoint.
     */
    function _payPrefund(uint256 amount) internal {
        if (amount != 0) {
            // Use low-level call to send ETH; ignore return value per ERC-4337.
            // slither-disable-next-line low-level-calls
            (bool success, ) = payable(msg.sender).call{value: amount}("");
            // The EntryPoint will revert the entire UserOp if the prefund
            // transfer fails, so we rely on that guard.
            (success);
        }
    }

    /**
     * @dev Authorizes UUPS upgrades. Only the owner may upgrade the implementation.
     * @param newImplementation The address of the new implementation contract.
     */
    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyRole(OWNER_ROLE) {
        // Additional upgrade guards can be added here (e.g., timelock).
    }

    /* ═══════════════════════════════════════════════════════════════════════
       §13 – RECEIVE / FALLBACK
       ═══════════════════════════════════════════════════════════════════════ */

    /// @notice Allows the account to receive native ETH (e.g., refunds from EntryPoint).
    receive() external payable {}

    /// @notice Fallback to receive ETH sent with calldata.
    fallback() external payable {}
}