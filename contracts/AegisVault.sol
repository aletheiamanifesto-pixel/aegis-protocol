// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title AegisVault
 * @notice Reserve vault ensuring 1:1 backing of AEGIS EUR with real EUR.
 *
 * Flow:
 *   deposit(amount): EUR verified off-chain -> mint AEGIS EUR 1:1
 *   withdraw(amount): burn AEGIS EUR -> trigger EUR bank transfer
 */

interface IAegisEUR {
    function mint(address to, uint256 amount) external;
    function burn(address from, uint256 amount) external;
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
    function totalSupply() external view returns (uint256);
}

contract AegisVault {
    address public owner;
    IAegisEUR public immutable aegisEUR;

    uint256 public totalEURDeposited;
    uint256 public totalEURWithdrawn;

    bytes32[] public auditReports;

    mapping(address => bool) public signers;
    uint256 public signerCount;
    uint256 public requiredSignatures;

    /// @dev Each mint/burn is an operation identified by its parameters: it executes
    ///      only when `requiredSignatures` distinct signers have approved it.
    struct Operation {
        uint256 approvals;
        bool executed;
        mapping(address => bool) voted;
    }
    mapping(bytes32 => Operation) private _operations;
    /// @dev Withdrawals: the USER puts the tokens in escrow in the vault (requestWithdrawal), the signers
    ///      can only burn THOSE tokens after paying (completeWithdrawal) or return them
    ///      (rejectWithdrawal). Nobody can burn another person's balance anymore.
    enum WithdrawalStatus { None, Pending, Completed, Refunded }
    struct Withdrawal {
        address user;
        uint256 amount;
        bytes32 payoutRefHash; // hash of the bank payout details chosen by the user
        uint64 createdAt;
        WithdrawalStatus status;
    }
    mapping(uint256 => Withdrawal) public withdrawals;
    uint256 public withdrawalCount;
    uint256 public totalEscrowed;
    /// @notice After this time a request that was never completed can be taken back by the user.
    uint256 public constant WITHDRAWAL_TIMEOUT = 7 days;

    // ---- Independent reserve attestation (bank / auditor / Proof-of-Reserve oracle) ----
    address public attestor;
    uint256 public attestedReserve;
    uint256 public attestedAt;
    bytes32 public attestationReportHash;
    /// @notice If true, minting is never allowed beyond the reserve attested by the attestor.
    bool public enforceAttestedReserve;
    uint256 public constant ATTESTATION_MAX_AGE = 1 days;

    event Deposited(address indexed user, uint256 amount, bytes32 txReference);
    event WithdrawalRequested(uint256 indexed id, address indexed user, uint256 amount, bytes32 payoutRefHash);
    /// @dev `bankTxRef` is a reference of the bank transfer: never IBANs or personal data on-chain (GDPR).
    event Withdrawn(uint256 indexed id, address indexed user, uint256 amount, bytes32 bankTxRef);
    event WithdrawalRefunded(uint256 indexed id, address indexed user, uint256 amount);
    event OperationApproved(bytes32 indexed opId, address indexed signer, uint256 approvals, uint256 required);
    event ReserveProven(uint256 totalSupply, uint256 eurReserve, uint256 ratio);
    event ReserveAttested(uint256 reserve, bytes32 reportHash, uint256 timestamp);
    event AttestorChanged(address indexed attestor, bool enforce);
    event AuditReportSubmitted(bytes32 reportHash, uint256 timestamp);
    event SignerAdded(address indexed signer);
    event SignerRemoved(address indexed signer);
    event Paused(address indexed by);
    event Unpaused(address indexed by);

    bool public paused;

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    modifier onlySigner() {
        require(signers[msg.sender], "Not a signer");
        _;
    }

    modifier whenNotPaused() {
        require(!paused, "Contract paused");
        _;
    }

    constructor(address _aegisEUR, address[] memory _signers, uint256 _requiredSigs) {
        require(_aegisEUR != address(0), "AegisEUR zero");
        require(_signers.length >= _requiredSigs && _requiredSigs > 0, "Invalid multi-sig config");

        owner = msg.sender;
        aegisEUR = IAegisEUR(_aegisEUR);
        requiredSignatures = _requiredSigs;

        for (uint256 i = 0; i < _signers.length; i++) {
            require(_signers[i] != address(0) && !signers[_signers[i]], "Invalid signer");
            signers[_signers[i]] = true;
            signerCount++;
            emit SignerAdded(_signers[i]);
        }
    }

    /// @notice Approve (and, at the threshold, execute) a mint against an EUR bank transfer
    ///         identified by `txRef`. The same `txRef` can never be minted twice.
    function deposit(address user, uint256 amount, bytes32 txRef) external whenNotPaused onlySigner {
        require(user != address(0), "User zero");
        require(amount > 0, "Zero amount");
        bytes32 opId = keccak256(abi.encode("DEPOSIT", user, amount, txRef));
        if (!_approve(opId)) return;

        if (enforceAttestedReserve) {
            require(isAttestationFresh(), "Reserve attestation stale");
            require(aegisEUR.totalSupply() + amount <= attestedReserve, "Exceeds attested reserve");
        }
        totalEURDeposited += amount;
        aegisEUR.mint(user, amount);

        emit Deposited(user, amount, txRef);
    }

    /// @notice The USER requests a withdrawal: the tokens leave their balance and are held in escrow
    ///         by the vault (requires approve). `payoutRefHash` binds the request to the payout details.
    function requestWithdrawal(uint256 amount, bytes32 payoutRefHash) external whenNotPaused returns (uint256 id) {
        require(amount > 0, "Zero amount");
        require(payoutRefHash != bytes32(0), "Missing payout ref");
        require(aegisEUR.transferFrom(msg.sender, address(this), amount), "Escrow failed");
        id = ++withdrawalCount;
        withdrawals[id] = Withdrawal(msg.sender, amount, payoutRefHash, uint64(block.timestamp), WithdrawalStatus.Pending);
        totalEscrowed += amount;
        emit WithdrawalRequested(id, msg.sender, amount, payoutRefHash);
    }

    /// @notice Signers (multisig) confirm the EUR payout and burn ONLY the tokens in escrow
    ///         for this request. `payoutRefHash` must match the one chosen by the user.
    function completeWithdrawal(uint256 id, bytes32 payoutRefHash, bytes32 bankTxRef) external whenNotPaused onlySigner {
        Withdrawal storage w = withdrawals[id];
        require(w.status == WithdrawalStatus.Pending, "Not pending");
        require(w.payoutRefHash == payoutRefHash, "Payout ref mismatch");
        bytes32 opId = keccak256(abi.encode("WITHDRAW", id, payoutRefHash, bankTxRef));
        if (!_approve(opId)) return;

        w.status = WithdrawalStatus.Completed;
        totalEscrowed -= w.amount;
        totalEURWithdrawn += w.amount;
        aegisEUR.burn(address(this), w.amount);
        emit Withdrawn(id, w.user, w.amount, bankTxRef);
    }

    /// @notice Signers (multisig) reject a request: the tokens go back to the user.
    function rejectWithdrawal(uint256 id) external onlySigner {
        Withdrawal storage w = withdrawals[id];
        require(w.status == WithdrawalStatus.Pending, "Not pending");
        if (!_approve(keccak256(abi.encode("REJECT_WITHDRAW", id)))) return;
        _refund(id);
    }

    /// @notice If the payout does not arrive within WITHDRAWAL_TIMEOUT, the user takes back their tokens.
    function cancelWithdrawal(uint256 id) external {
        Withdrawal storage w = withdrawals[id];
        require(w.status == WithdrawalStatus.Pending, "Not pending");
        require(msg.sender == w.user, "Not your withdrawal");
        require(block.timestamp >= w.createdAt + WITHDRAWAL_TIMEOUT, "Timeout not reached");
        _refund(id);
    }

    function _refund(uint256 id) internal {
        Withdrawal storage w = withdrawals[id];
        w.status = WithdrawalStatus.Refunded;
        totalEscrowed -= w.amount;
        require(aegisEUR.transfer(w.user, w.amount), "Refund failed");
        emit WithdrawalRefunded(id, w.user, w.amount);
    }

    /// @dev Records the caller's vote. Returns true when the operation reaches the threshold
    ///      (and marks it executed).
    function _approve(bytes32 opId) internal returns (bool) {
        Operation storage op = _operations[opId];
        require(!op.executed, "Already executed");
        require(!op.voted[msg.sender], "Already approved");
        op.voted[msg.sender] = true;
        op.approvals++;
        emit OperationApproved(opId, msg.sender, op.approvals, requiredSignatures);
        if (op.approvals < requiredSignatures) return false;
        op.executed = true;
        return true;
    }

    function getOperation(bytes32 opId) external view returns (uint256 approvals, bool executed) {
        Operation storage op = _operations[opId];
        return (op.approvals, op.executed);
    }

    /// @notice Reserve according to the vault's internal bookkeeping (what the signers declared).
    ///         Useful for consistency checks, but it is NOT a proof: see attestReserve().
    function proveReserve() external {
        uint256 supply = aegisEUR.totalSupply();
        uint256 eurReserve = totalEURDeposited - totalEURWithdrawn;

        uint256 ratio = supply == 0 ? 10000 : (eurReserve * 10000) / supply;

        emit ReserveProven(supply, eurReserve, ratio);
    }

    function getReserveRatio() external view returns (uint256) {
        uint256 supply = aegisEUR.totalSupply();
        if (supply == 0) return 10000;

        uint256 eurReserve = totalEURDeposited - totalEURWithdrawn;
        return (eurReserve * 10000) / supply;
    }

    // ---- Independent attestation ----

    /// @notice Called by an entity INDEPENDENT of the signers (custodian bank, auditor,
    ///         Proof-of-Reserve oracle or zkTLS verifier) with the EUR balance actually held.
    function attestReserve(uint256 reserve, bytes32 reportHash) external {
        require(msg.sender == attestor && attestor != address(0), "Not attestor");
        attestedReserve = reserve;
        attestedAt = block.timestamp;
        attestationReportHash = reportHash;
        emit ReserveAttested(reserve, reportHash, block.timestamp);
    }

    function isAttestationFresh() public view returns (bool) {
        return attestedAt != 0 && block.timestamp - attestedAt <= ATTESTATION_MAX_AGE;
    }

    /// @notice Ratio (basis points) between the attested reserve and the supply in circulation.
    function getAttestedReserveRatio() external view returns (uint256) {
        uint256 supply = aegisEUR.totalSupply();
        if (supply == 0) return 10000;
        return (attestedReserve * 10000) / supply;
    }

    function setAttestor(address _attestor, bool _enforce) external onlyOwner {
        require(!signers[_attestor], "Attestor must be independent of signers");
        attestor = _attestor;
        enforceAttestedReserve = _enforce;
        emit AttestorChanged(_attestor, _enforce);
    }

    function auditReport(bytes32 reportHash) external onlySigner {
        require(reportHash != bytes32(0), "Empty report hash");
        auditReports.push(reportHash);
        emit AuditReportSubmitted(reportHash, block.timestamp);
    }

    function getAuditReports() external view returns (bytes32[] memory) {
        return auditReports;
    }

    function pause() external onlyOwner {
        paused = true;
        emit Paused(msg.sender);
    }

    function unpause() external onlyOwner {
        paused = false;
        emit Unpaused(msg.sender);
    }

    function addSigner(address signer) external onlyOwner {
        require(signer != address(0) && !signers[signer], "Already signer");
        require(signer != attestor, "Attestor must be independent of signers");
        signers[signer] = true;
        signerCount++;
        emit SignerAdded(signer);
    }

    function removeSigner(address signer) external onlyOwner {
        require(signers[signer], "Not signer");
        require(signerCount > requiredSignatures, "Would breach threshold");
        signers[signer] = false;
        signerCount--;
        emit SignerRemoved(signer);
    }

    function setRequiredSignatures(uint256 required) external onlyOwner {
        require(required > 0 && required <= signerCount, "Invalid threshold");
        requiredSignatures = required;
    }
}
