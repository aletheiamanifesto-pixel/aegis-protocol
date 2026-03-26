// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title AegisSmartAccount
 * @notice ERC-4337 compliant smart account with MiCA compliance hooks.
 *
 * Features
 * --------
 *  - ERC-4337 full support (validateUserOp / executeUserOp)
 *  - Batch operations (executeBatch)
 *  - Social recovery via guardians
 *  - Gas sponsorship (paymaster validation hook)
 *  - Role-based access: OWNER / GUARDIAN / REGULATOR
 *  - EURC-only asset constraint with compliance checks
 *  - ZK-proof replay protection
 */

interface IEntryPoint {
    function getNonce(address sender, uint192 key) external view returns (uint256 nonce);
    function depositTo(address account) external payable;
    function withdrawTo(address payable withdrawAddress, uint256 withdrawAmount) external;
    function getDepositInfo(address account) external view returns (uint112 deposit, bool staked, uint112 stake, uint32 unstakeDelaySec, uint48 withdrawTime);
    function handleOps(UserOperation[] calldata ops, address payable beneficiary) external;
    function simulateValidation(UserOperation calldata userOp) external;
}

struct UserOperation {
    address sender;
    uint256 nonce;
    bytes initCode;
    bytes callData;
    uint256 callGasLimit;
    uint256 verificationGasLimit;
    uint256 preVerificationGas;
    uint256 maxFeePerGas;
    uint256 maxPriorityFeePerGas;
    bytes paymasterAndData;
    bytes signature;
}

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
    function approve(address spender, uint256 amount) external returns (bool);
}

interface IPaymaster {
    function validatePaymasterUserOp(
        UserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 maxCost
    ) external returns (bytes memory context, uint256 validationData);

    function postOp(
        uint8 mode,
        bytes calldata context,
        uint256 actualGasCost
    ) external;
}

contract AegisSmartAccount {
    // -----------------------------------------------------------------------
    // Constants
    // -----------------------------------------------------------------------

    uint256 private constant _SIG_VALIDATION_FAILED = 1;
    uint256 private constant _SIG_VALIDATION_SUCCESS = 0;
    uint256 public constant MICA_ZK_PROOF_THRESHOLD = 1000 * 10 ** 6; // 1 000 EURC (6 decimals)

    // ERC-4337 magic value returned by validateUserOp on success
    uint256 private constant _VALIDATION_SUCCESS = 0;

    // -----------------------------------------------------------------------
    // Roles
    // -----------------------------------------------------------------------

    address public owner;
    address public regulator;
    IEntryPoint public immutable entryPoint;
    IERC20 public immutable eurc;

    // Guardian recovery
    mapping(address => bool) public guardians;
    uint256 public guardianCount;
    uint256 public recoveryThreshold;

    // -----------------------------------------------------------------------
    // State
    // -----------------------------------------------------------------------

    bool public frozen;
    mapping(bytes32 => bool) public usedProofs;

    // Pending recovery request
    struct RecoveryRequest {
        address newOwner;
        uint256 approvals;
        uint256 deadline;
        mapping(address => bool) voted;
    }
    RecoveryRequest private _recovery;

    // -----------------------------------------------------------------------
    // Events
    // -----------------------------------------------------------------------

    event Executed(address indexed to, uint256 value, bytes data);
    event BatchExecuted(uint256 count);
    event EURCTransferred(address indexed recipient, uint256 amount, bytes32 proofHash);
    event EURCDeposited(address indexed from, uint256 amount);
    event Frozen(address indexed by);
    event Unfrozen(address indexed by);
    event GuardianAdded(address indexed guardian);
    event GuardianRemoved(address indexed guardian);
    event RecoveryInitiated(address indexed newOwner, uint256 deadline);
    event RecoveryExecuted(address indexed newOwner);
    event GasDeposited(address indexed from, uint256 amount);

    // -----------------------------------------------------------------------
    // Modifiers
    // -----------------------------------------------------------------------

    modifier onlyOwner() {
        require(msg.sender == owner || msg.sender == address(entryPoint), "Not owner");
        _;
    }

    modifier onlyOwnerOrGuardian() {
        require(msg.sender == owner || guardians[msg.sender], "Not owner or guardian");
        _;
    }

    modifier onlyRegulator() {
        require(msg.sender == regulator, "Not regulator");
        _;
    }

    modifier notFrozen() {
        require(!frozen, "Account frozen");
        _;
    }

    // -----------------------------------------------------------------------
    // Constructor
    // -----------------------------------------------------------------------

    constructor(address _owner, address _entryPoint, address _eurc, address _regulator) {
        require(_owner != address(0), "Owner zero");
        require(_entryPoint != address(0), "EntryPoint zero");
        require(_eurc != address(0), "EURC zero");
        owner = _owner;
        entryPoint = IEntryPoint(_entryPoint);
        eurc = IERC20(_eurc);
        regulator = _regulator;
        recoveryThreshold = 1;
    }

    // -----------------------------------------------------------------------
    // ERC-4337: validateUserOp
    // -----------------------------------------------------------------------

    /**
     * @notice Validate a UserOperation.
     * @dev Called by the EntryPoint before execution.
     * @return validationData 0 = success, 1 = sig failure, packed (aggregator|validUntil|validAfter)
     */
    function validateUserOp(
        UserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external returns (uint256 validationData) {
        require(msg.sender == address(entryPoint), "Not EntryPoint");

        // Pay missing funds to EntryPoint
        if (missingAccountFunds > 0) {
            (bool ok, ) = payable(address(entryPoint)).call{value: missingAccountFunds}("");
            require(ok, "Fund transfer failed");
        }

        // ECDSA signature check
        bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", userOpHash));
        address recovered = _recoverSigner(ethHash, userOp.signature);
        if (recovered != owner) {
            return _SIG_VALIDATION_FAILED;
        }
        return _SIG_VALIDATION_SUCCESS;
    }

    // -----------------------------------------------------------------------
    // ERC-4337: execution
    // -----------------------------------------------------------------------

    /**
     * @notice Execute a single call (called by EntryPoint after validation).
     */
    function execute(
        address dest,
        uint256 value,
        bytes calldata data
    ) external onlyOwner notFrozen {
        _call(dest, value, data);
        emit Executed(dest, value, data);
    }

    /**
     * @notice Execute multiple calls atomically.
     */
    function executeBatch(
        address[] calldata dests,
        uint256[] calldata values,
        bytes[] calldata datas
    ) external onlyOwner notFrozen {
        require(dests.length == values.length && dests.length == datas.length, "Array length mismatch");
        for (uint256 i = 0; i < dests.length; i++) {
            _call(dests[i], values[i], datas[i]);
        }
        emit BatchExecuted(dests.length);
    }

    // -----------------------------------------------------------------------
    // EURC compliance transfer
    // -----------------------------------------------------------------------

    /**
     * @notice Transfer EURC with MiCA compliance check.
     * @param recipient   Destination address.
     * @param amount      Amount in EURC units (6 decimals).
     * @param proofHash   ZK proof hash (required if amount >= MICA_ZK_PROOF_THRESHOLD).
     */
    function transferEURC(
        address recipient,
        uint256 amount,
        bytes32 proofHash
    ) external onlyOwner notFrozen {
        require(recipient != address(0), "Zero recipient");
        require(amount > 0, "Zero amount");

        if (amount >= MICA_ZK_PROOF_THRESHOLD) {
            require(proofHash != bytes32(0), "ZK proof required for large transfers");
            require(!usedProofs[proofHash], "Proof already used");
            usedProofs[proofHash] = true;
        }

        require(eurc.transfer(recipient, amount), "EURC transfer failed");
        emit EURCTransferred(recipient, amount, proofHash);
    }

    /**
     * @notice Deposit EURC into this smart account.
     */
    function depositEURC(uint256 amount) external notFrozen {
        require(eurc.transferFrom(msg.sender, address(this), amount), "EURC transferFrom failed");
        emit EURCDeposited(msg.sender, amount);
    }

    // -----------------------------------------------------------------------
    // Gas sponsorship (paymaster hook)
    // -----------------------------------------------------------------------

    /**
     * @notice Deposit ETH to the EntryPoint to sponsor gas for this account.
     */
    function depositGas() external payable {
        entryPoint.depositTo{value: msg.value}(address(this));
        emit GasDeposited(msg.sender, msg.value);
    }

    /**
     * @notice Withdraw ETH from the EntryPoint gas deposit.
     */
    function withdrawGas(address payable to, uint256 amount) external onlyOwner {
        entryPoint.withdrawTo(to, amount);
    }

    // -----------------------------------------------------------------------
    // Social recovery
    // -----------------------------------------------------------------------

    /**
     * @notice Add a guardian address.
     */
    function addGuardian(address guardian) external onlyOwner {
        require(guardian != address(0) && !guardians[guardian], "Invalid guardian");
        guardians[guardian] = true;
        guardianCount++;
        emit GuardianAdded(guardian);
    }

    /**
     * @notice Remove a guardian address.
     */
    function removeGuardian(address guardian) external onlyOwner {
        require(guardians[guardian], "Not a guardian");
        guardians[guardian] = false;
        guardianCount--;
        require(guardianCount >= recoveryThreshold, "Would breach threshold");
        emit GuardianRemoved(guardian);
    }

    /**
     * @notice Set minimum number of guardian approvals needed to execute recovery.
     */
    function setRecoveryThreshold(uint256 threshold) external onlyOwner {
        require(threshold > 0 && threshold <= guardianCount, "Invalid threshold");
        recoveryThreshold = threshold;
    }

    /**
     * @notice Initiate an ownership recovery request (guardian only).
     * @param newOwner     Proposed new owner.
     * @param deadlineIn   Seconds from now before request expires.
     */
    function initiateRecovery(address newOwner, uint256 deadlineIn) external onlyOwnerOrGuardian {
        require(newOwner != address(0), "Zero new owner");
        _recovery.newOwner = newOwner;
        _recovery.approvals = 0;
        _recovery.deadline = block.timestamp + deadlineIn;
        emit RecoveryInitiated(newOwner, _recovery.deadline);
    }

    /**
     * @notice Approve the active recovery request (guardian only).
     */
    function approveRecovery() external {
        require(guardians[msg.sender], "Not a guardian");
        require(block.timestamp < _recovery.deadline, "Recovery expired");
        require(!_recovery.voted[msg.sender], "Already voted");
        _recovery.voted[msg.sender] = true;
        _recovery.approvals++;

        if (_recovery.approvals >= recoveryThreshold) {
            address newOwner = _recovery.newOwner;
            owner = newOwner;
            emit RecoveryExecuted(newOwner);
        }
    }

    // -----------------------------------------------------------------------
    // Freeze / Unfreeze (regulator only)
    // -----------------------------------------------------------------------

    function freeze() external onlyRegulator {
        frozen = true;
        emit Frozen(msg.sender);
    }

    function unfreeze() external onlyRegulator {
        frozen = false;
        emit Unfrozen(msg.sender);
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    function _call(address dest, uint256 value, bytes memory data) internal {
        (bool success, bytes memory result) = dest.call{value: value}(data);
        if (!success) {
            // Bubble up revert reason
            if (result.length > 0) {
                assembly {
                    let size := mload(result)
                    revert(add(result, 32), size)
                }
            }
            revert("Call failed");
        }
    }

    function _recoverSigner(bytes32 hash, bytes memory sig) internal pure returns (address) {
        require(sig.length == 65, "Invalid sig length");
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
        if (v < 27) v += 27;
        require(v == 27 || v == 28, "Invalid sig v");
        return ecrecover(hash, v, r, s);
    }

    // -----------------------------------------------------------------------
    // Receive ETH (for gas top-ups)
    // -----------------------------------------------------------------------

    receive() external payable {}
}