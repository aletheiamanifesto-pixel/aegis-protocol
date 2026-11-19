// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title AegisEUR
 * @notice ERC-20 token for 1:1 euro, issued by AegisVault ("own e-money token" strategy:
 *         requires a licensed issuer (EMI/bank) under MiCA).
 *
 * IMPORTANT: balances and transfers of this token are PUBLIC like any ERC-20.
 * Confidentiality is provided by ShieldedPool, which accepts any ERC-20 (EURC, EURe or this
 * token). `transferWithProof` and `updateBalanceCommitment` are LEGACY: they give no
 * privacy and are kept only for compatibility; do not use them in new integrations.
 *
 * - Mint/burn only by the vault (multisig with independent reserve attestation)
 * - MiCA freeze/unfreeze (REGULATOR_ROLE)
 */

interface INoirVerifier {
    function verifyProof(bytes calldata proof, bytes32[] calldata publicInputs) external returns (bool);
}

contract AegisEUR {
    string public constant name = "AEGIS Euro";
    string public constant symbol = "AEGIS-EUR";
    uint8 public constant decimals = 6;

    uint256 private _totalSupply;
    mapping(address => uint256) private _balances;
    mapping(address => mapping(address => uint256)) private _allowances;

    address public owner;
    mapping(address => bool) public minters;
    mapping(address => bool) public regulators;
    address public vault;
    INoirVerifier public verifier;

    mapping(address => bool) public frozen;
    mapping(address => bytes32) public balanceCommitments;
    mapping(bytes32 => bool) public usedProofHashes;

    uint256 public constant MICA_ZK_THRESHOLD = 1000 * 10 ** 6;

    bool public paused;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    event Mint(address indexed to, uint256 amount, address indexed minter);
    event Burn(address indexed from, uint256 amount);
    event ProofAttached(address indexed from, address indexed to, bytes32 proofHash);
    event Frozen(address indexed account, address indexed by);
    event Unfrozen(address indexed account, address indexed by);
    event CommitmentUpdated(address indexed account, bytes32 commitment);
    event MinterAdded(address indexed minter);
    event MinterRemoved(address indexed minter);
    event RegulatorAdded(address indexed regulator);
    event RegulatorRemoved(address indexed regulator);
    event Paused(address indexed by);
    event Unpaused(address indexed by);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    modifier onlyMinter() {
        require(minters[msg.sender] || msg.sender == vault, "Not minter");
        _;
    }

    modifier onlyRegulator() {
        require(regulators[msg.sender], "Not regulator");
        _;
    }

    modifier notFrozen(address account) {
        require(!frozen[account], "Account frozen");
        _;
    }

    modifier whenNotPaused() {
        require(!paused, "Contract paused");
        _;
    }

    constructor(address _vault, address _regulator) {
        require(_vault != address(0), "Vault zero");
        require(_regulator != address(0), "Regulator zero");
        owner = msg.sender;
        vault = _vault;
        minters[_vault] = true;
        regulators[_regulator] = true;
        regulators[msg.sender] = true;
    }

    function totalSupply() external view returns (uint256) {
        return _totalSupply;
    }

    function balanceOf(address account) external view returns (uint256) {
        return _balances[account];
    }

    function allowance(address _owner, address spender) external view returns (uint256) {
        return _allowances[_owner][spender];
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        _allowances[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transfer(address to, uint256 amount)
        external
        whenNotPaused
        notFrozen(msg.sender)
        notFrozen(to)
        returns (bool)
    {
        _transfer(msg.sender, to, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount)
        external
        whenNotPaused
        notFrozen(from)
        notFrozen(to)
        returns (bool)
    {
        require(_allowances[from][msg.sender] >= amount, "Insufficient allowance");
        _allowances[from][msg.sender] -= amount;
        _transfer(from, to, amount);
        return true;
    }

    function mint(address to, uint256 amount) external whenNotPaused onlyMinter notFrozen(to) {
        require(to != address(0), "Mint to zero");
        require(amount > 0, "Zero amount");
        _balances[to] += amount;
        _totalSupply += amount;
        emit Transfer(address(0), to, amount);
        emit Mint(to, amount, msg.sender);
    }

    function burn(address from, uint256 amount) external whenNotPaused onlyMinter {
        require(_balances[from] >= amount, "Insufficient balance");
        _balances[from] -= amount;
        _totalSupply -= amount;
        emit Transfer(from, address(0), amount);
        emit Burn(from, amount);
    }

    function transferWithProof(
        address to,
        uint256 amount,
        bytes calldata proof
    ) external whenNotPaused notFrozen(msg.sender) notFrozen(to) {
        bytes32 proofHash = keccak256(proof);
        require(!usedProofHashes[proofHash], "Proof already used");

        if (amount >= MICA_ZK_THRESHOLD && address(verifier) != address(0)) {
            bytes32[] memory publicInputs = new bytes32[](2);
            publicInputs[0] = bytes32(uint256(uint160(msg.sender)));
            publicInputs[1] = bytes32(amount);
            require(verifier.verifyProof(proof, publicInputs), "Invalid ZK proof");
        }

        usedProofHashes[proofHash] = true;
        _transfer(msg.sender, to, amount);
        emit ProofAttached(msg.sender, to, proofHash);
    }

    function updateBalanceCommitment(bytes32 commitment) external {
        balanceCommitments[msg.sender] = commitment;
        emit CommitmentUpdated(msg.sender, commitment);
    }

    function getBalanceCommitment(address account) external view returns (bytes32) {
        return balanceCommitments[account];
    }

    function freeze(address account) external onlyRegulator {
        frozen[account] = true;
        emit Frozen(account, msg.sender);
    }

    function unfreeze(address account) external onlyRegulator {
        frozen[account] = false;
        emit Unfrozen(account, msg.sender);
    }

    function addMinter(address minter) external onlyOwner {
        minters[minter] = true;
        emit MinterAdded(minter);
    }

    function removeMinter(address minter) external onlyOwner {
        minters[minter] = false;
        emit MinterRemoved(minter);
    }

    function addRegulator(address regulator) external onlyOwner {
        regulators[regulator] = true;
        emit RegulatorAdded(regulator);
    }

    function removeRegulator(address regulator) external onlyOwner {
        regulators[regulator] = false;
        emit RegulatorRemoved(regulator);
    }

    function pause() external {
        require(msg.sender == owner || regulators[msg.sender], "Not authorized");
        paused = true;
        emit Paused(msg.sender);
    }

    function unpause() external {
        require(msg.sender == owner || regulators[msg.sender], "Not authorized");
        paused = false;
        emit Unpaused(msg.sender);
    }

    function setVerifier(address _verifier) external onlyOwner {
        verifier = INoirVerifier(_verifier);
    }

    function setVault(address _vault) external onlyOwner {
        require(_vault != address(0), "Vault zero");
        minters[vault] = false;
        vault = _vault;
        minters[_vault] = true;
    }

    function _transfer(address from, address to, uint256 amount) internal {
        require(from != address(0), "Transfer from zero");
        require(to != address(0), "Transfer to zero");
        require(_balances[from] >= amount, "Insufficient balance");
        _balances[from] -= amount;
        _balances[to] += amount;
        emit Transfer(from, to, amount);
    }
}
