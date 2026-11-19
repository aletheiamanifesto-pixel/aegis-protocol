// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

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

contract AegisSmartAccount {
    uint256 private constant _SIG_VALIDATION_FAILED = 1;
    uint256 private constant _SIG_VALIDATION_SUCCESS = 0;
    uint256 public constant MICA_ZK_PROOF_THRESHOLD = 1000 * 10 ** 6;

    address public owner;
    address public regulator;
    IEntryPoint public immutable entryPoint;
    IERC20 public immutable eurc;

    mapping(address => bool) public guardians;
    uint256 public guardianCount;
    uint256 public recoveryThreshold;

    bool public frozen;
    mapping(bytes32 => bool) public usedProofs;

    /// @dev Each recovery is a "round" with its own votes: after execution or cancellation
    ///      the next one starts clean (previously `voted` was never reset → single-use recovery).
    struct RecoveryRequest {
        address newOwner;
        uint256 approvals;
        uint256 deadline; // by when the approvals must be collected
        uint256 readyAt; // threshold reached: executable from this moment (owner can cancel)
        bool active;
    }
    RecoveryRequest private _recovery;
    uint256 public recoveryRound;
    mapping(uint256 => mapping(address => bool)) private _recoveryVoted;

    /// @notice Window in which the real owner can cancel a recovery that reached the threshold.
    uint256 public constant RECOVERY_DELAY = 2 days;
    uint256 public constant MAX_RECOVERY_WINDOW = 30 days;

    event Executed(address indexed to, uint256 value, bytes data);
    event BatchExecuted(uint256 count);
    event EURCTransferred(address indexed recipient, uint256 amount, bytes32 proofHash);
    event EURCDeposited(address indexed from, uint256 amount);
    event Frozen(address indexed by);
    event Unfrozen(address indexed by);
    event GuardianAdded(address indexed guardian);
    event GuardianRemoved(address indexed guardian);
    event RecoveryInitiated(address indexed newOwner, uint256 deadline);
    event RecoveryApproved(address indexed guardian, uint256 approvals);
    event RecoveryReady(address indexed newOwner, uint256 readyAt);
    event RecoveryCancelled(uint256 round);
    event RecoveryExecuted(address indexed newOwner);

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

    function validateUserOp(
        UserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external returns (uint256 validationData) {
        require(msg.sender == address(entryPoint), "Not EntryPoint");
        if (missingAccountFunds > 0) {
            (bool ok, ) = payable(address(entryPoint)).call{value: missingAccountFunds}("");
            require(ok, "Fund transfer failed");
        }
        bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", userOpHash));
        address recovered = _recoverSigner(ethHash, userOp.signature);
        if (recovered != owner) {
            return _SIG_VALIDATION_FAILED;
        }
        return _SIG_VALIDATION_SUCCESS;
    }

    function execute(address dest, uint256 value, bytes calldata data) external onlyOwner notFrozen {
        _call(dest, value, data);
        emit Executed(dest, value, data);
    }

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

    function transferEURC(address recipient, uint256 amount, bytes32 proofHash) external onlyOwner notFrozen {
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

    function depositEURC(uint256 amount) external notFrozen {
        require(eurc.transferFrom(msg.sender, address(this), amount), "EURC transferFrom failed");
        emit EURCDeposited(msg.sender, amount);
    }

    function addGuardian(address guardian) external onlyOwner {
        require(guardian != address(0) && !guardians[guardian], "Invalid guardian");
        guardians[guardian] = true;
        guardianCount++;
        emit GuardianAdded(guardian);
    }

    function removeGuardian(address guardian) external onlyOwner {
        require(guardians[guardian], "Not a guardian");
        guardians[guardian] = false;
        guardianCount--;
        require(guardianCount >= recoveryThreshold, "Would breach threshold");
        emit GuardianRemoved(guardian);
    }

    function setRecoveryThreshold(uint256 threshold) external onlyOwner {
        require(threshold > 0 && threshold <= guardianCount, "Invalid threshold");
        recoveryThreshold = threshold;
    }

    /// @notice Start a recovery. A recovery that is still open (not expired) cannot be
    ///         overwritten by a guardian: no "reset" griefing of other people's votes.
    function initiateRecovery(address newOwner, uint256 deadlineIn) external onlyOwnerOrGuardian {
        require(newOwner != address(0), "Zero new owner");
        require(deadlineIn > 0 && deadlineIn <= MAX_RECOVERY_WINDOW, "Invalid window");
        require(!_recovery.active || block.timestamp >= _recovery.deadline && _recovery.readyAt == 0, "Recovery in progress");
        recoveryRound++;
        _recovery = RecoveryRequest({
            newOwner: newOwner,
            approvals: 0,
            deadline: block.timestamp + deadlineIn,
            readyAt: 0,
            active: true
        });
        emit RecoveryInitiated(newOwner, _recovery.deadline);
    }

    function approveRecovery() external {
        require(guardians[msg.sender], "Not a guardian");
        require(_recovery.active, "No active recovery");
        require(block.timestamp < _recovery.deadline, "Recovery expired");
        require(!_recoveryVoted[recoveryRound][msg.sender], "Already voted");
        _recoveryVoted[recoveryRound][msg.sender] = true;
        _recovery.approvals++;
        emit RecoveryApproved(msg.sender, _recovery.approvals);
        if (_recovery.approvals >= recoveryThreshold && _recovery.readyAt == 0) {
            _recovery.readyAt = block.timestamp + RECOVERY_DELAY;
            emit RecoveryReady(_recovery.newOwner, _recovery.readyAt);
        }
    }

    /// @notice After the delay, anyone can execute a recovery that reached the threshold.
    function executeRecovery() external {
        require(_recovery.active && _recovery.readyAt != 0, "Recovery not ready");
        require(block.timestamp >= _recovery.readyAt, "Delay not elapsed");
        address newOwner = _recovery.newOwner;
        _recovery.active = false;
        owner = newOwner;
        emit RecoveryExecuted(newOwner);
    }

    /// @notice The real owner can cancel a recovery (e.g. compromised guardians).
    function cancelRecovery() external onlyOwner {
        require(_recovery.active, "No active recovery");
        _recovery.active = false;
        emit RecoveryCancelled(recoveryRound);
    }

    function getRecovery()
        external
        view
        returns (address newOwner, uint256 approvals, uint256 deadline, uint256 readyAt, bool active, uint256 round)
    {
        RecoveryRequest storage r = _recovery;
        return (r.newOwner, r.approvals, r.deadline, r.readyAt, r.active, recoveryRound);
    }

    function freeze() external onlyRegulator {
        frozen = true;
        emit Frozen(msg.sender);
    }

    function unfreeze() external onlyRegulator {
        frozen = false;
        emit Unfrozen(msg.sender);
    }

    function _call(address dest, uint256 value, bytes memory data) internal {
        (bool success, bytes memory result) = dest.call{value: value}(data);
        if (!success) {
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

    receive() external payable {}
}
