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

    struct Operation {
        bytes4 selector;
        bytes params;
        uint256 approvals;
        bool executed;
        mapping(address => bool) voted;
    }
    mapping(bytes32 => Operation) private _operations;

    event Deposited(address indexed user, uint256 amount, bytes32 txReference);
    event Withdrawn(address indexed user, uint256 amount, string iban);
    event ReserveProven(uint256 totalSupply, uint256 eurReserve, uint256 ratio);
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
            signers[_signers[i]] = true;
            signerCount++;
            emit SignerAdded(_signers[i]);
        }
    }

    function deposit(address user, uint256 amount, bytes32 txRef) external whenNotPaused onlySigner {
        require(user != address(0), "User zero");
        require(amount > 0, "Zero amount");

        totalEURDeposited += amount;
        aegisEUR.mint(user, amount);

        emit Deposited(user, amount, txRef);
    }

    function withdraw(address user, uint256 amount, string calldata iban) external whenNotPaused onlySigner {
        require(user != address(0), "User zero");
        require(amount > 0, "Zero amount");
        require(aegisEUR.balanceOf(user) >= amount, "Insufficient AEGIS EUR");

        totalEURWithdrawn += amount;
        aegisEUR.burn(user, amount);

        emit Withdrawn(user, amount, iban);
    }

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
        require(!signers[signer], "Already signer");
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
