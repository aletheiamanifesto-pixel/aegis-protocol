// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title AegisBundleVerifier
 * @notice Registers transaction bundles with Merkle roots and verifies
 *         individual transaction inclusion proofs on-chain.
 * @dev All bundle IDs and transaction leaf hashes must be pre-computed
 *      off-chain by the Python TransactionBundler before submission.
 */
contract AegisBundleVerifier {
    // ─────────────────────────────────────────────
    // Data structures
    // ─────────────────────────────────────────────

    /**
     * @notice On-chain representation of a transaction bundle.
     * @param merkleRoot   Merkle root of the transaction leaf hashes.
     * @param txCount      Number of transactions in the bundle.
     * @param totalAmount  Sum of all transaction amounts in the bundle (wei units).
     * @param timestamp    Block timestamp when the bundle was submitted.
     * @param submitter    Address that submitted the bundle.
     */
    struct Bundle {
        bytes32 merkleRoot;
        uint256 txCount;
        uint256 totalAmount;
        uint256 timestamp;
        address submitter;
    }

    // ─────────────────────────────────────────────
    // State
    // ─────────────────────────────────────────────

    /// @notice Contract owner (set at construction).
    address public owner;

    /// @notice Addresses authorized to submit bundles.
    mapping(address => bool) public authorizedSubmitters;

    /// @notice Whether the contract is paused.
    bool public paused;

    /// @notice Mapping from bundle ID to its on-chain record.
    mapping(bytes32 => Bundle) public bundles;

    /// @notice Guards against duplicate Merkle roots (prevents re-submission).
    mapping(bytes32 => bool) public processedRoots;

    // ─────────────────────────────────────────────
    // Events
    // ─────────────────────────────────────────────

    /**
     * @notice Emitted when a new bundle is successfully registered.
     * @param bundleId    Unique bundle identifier (keccak256 of off-chain UUID).
     * @param merkleRoot  Merkle root of the bundle.
     * @param txCount     Number of transactions in the bundle.
     * @param totalAmount Aggregate amount covered by the bundle.
     * @param submitter   Address of the bundle submitter.
     */
    event BundleSubmitted(
        bytes32 indexed bundleId,
        bytes32 merkleRoot,
        uint256 txCount,
        uint256 totalAmount,
        address indexed submitter
    );

    /**
     * @notice Emitted when a transaction inclusion proof is successfully verified.
     * @param bundleId Bundle that contains the transaction.
     * @param txIndex  Zero-based index of the transaction within the bundle.
     * @param txHash   Leaf hash of the verified transaction.
     */
    event TransactionVerified(
        bytes32 indexed bundleId,
        uint256 txIndex,
        bytes32 txHash
    );

    event SubmitterAdded(address indexed submitter);
    event SubmitterRemoved(address indexed submitter);
    event Paused(address indexed by);
    event Unpaused(address indexed by);

    // ─────────────────────────────────────────────
    // Errors
    // ─────────────────────────────────────────────

    error BundleAlreadyExists(bytes32 bundleId);
    error MerkleRootAlreadyProcessed(bytes32 merkleRoot);
    error BundleNotFound(bytes32 bundleId);
    error InvalidProofLength();

    // ─────────────────────────────────────────────
    // Modifiers
    // ─────────────────────────────────────────────

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    modifier onlyAuthorized() {
        require(authorizedSubmitters[msg.sender], "Not authorized submitter");
        _;
    }

    modifier whenNotPaused() {
        require(!paused, "Contract paused");
        _;
    }

    // ─────────────────────────────────────────────
    // Constructor
    // ─────────────────────────────────────────────

    constructor() {
        owner = msg.sender;
        authorizedSubmitters[msg.sender] = true;
        emit SubmitterAdded(msg.sender);
    }

    // ─────────────────────────────────────────────
    // Admin functions
    // ─────────────────────────────────────────────

    function addSubmitter(address submitter) external onlyOwner {
        require(submitter != address(0), "Zero address");
        require(!authorizedSubmitters[submitter], "Already authorized");
        authorizedSubmitters[submitter] = true;
        emit SubmitterAdded(submitter);
    }

    function removeSubmitter(address submitter) external onlyOwner {
        authorizedSubmitters[submitter] = false;
        emit SubmitterRemoved(submitter);
    }

    function pause() external onlyOwner {
        paused = true;
        emit Paused(msg.sender);
    }

    function unpause() external onlyOwner {
        paused = false;
        emit Unpaused(msg.sender);
    }

    // ─────────────────────────────────────────────
    // External functions
    // ─────────────────────────────────────────────

    /**
     * @notice Register a new transaction bundle on-chain.
     * @dev Reverts if the bundle ID or Merkle root has already been submitted.
     *      Only authorized submitters may call this function.
     * @param bundleId    Unique bundle identifier (bytes32).
     * @param merkleRoot  Merkle root computed off-chain.
     * @param txCount     Number of transactions in the bundle.
     * @param totalAmount Aggregate transaction amount.
     */
    function submitBundle(
        bytes32 bundleId,
        bytes32 merkleRoot,
        uint256 txCount,
        uint256 totalAmount
    ) external whenNotPaused onlyAuthorized {
        if (bundles[bundleId].timestamp != 0) revert BundleAlreadyExists(bundleId);
        if (processedRoots[merkleRoot]) revert MerkleRootAlreadyProcessed(merkleRoot);

        bundles[bundleId] = Bundle({
            merkleRoot: merkleRoot,
            txCount: txCount,
            totalAmount: totalAmount,
            timestamp: block.timestamp,
            submitter: msg.sender
        });
        processedRoots[merkleRoot] = true;

        emit BundleSubmitted(bundleId, merkleRoot, txCount, totalAmount, msg.sender);
    }

    /**
     * @notice Verify that a transaction leaf is included in a registered bundle.
     * @dev Uses sha3_256-compatible canonical (sorted) Merkle verification:
     *      at each step the smaller of the two node values is placed on the left
     *      before hashing, matching the Python MerkleTree._hash_pair convention.
     *      Note: The Python bundler uses sha3_256 for off-chain proofs; on-chain
     *      keccak256 is used here. Cross-verification requires matching hash
     *      functions. proofPositions is accepted for ABI compatibility but
     *      canonical ordering is applied regardless.
     * @param bundleId       Bundle to verify against.
     * @param txLeaf         Leaf hash of the transaction to verify.
     * @param proof          Sibling hashes along the Merkle path.
     * @param proofPositions Accepted for ABI compatibility; canonical ordering
     *                       is always applied (smaller node goes left).
     * @return valid True if the leaf is proven to be in the bundle.
     */
    function verifyTransaction(
        bytes32 bundleId,
        bytes32 txLeaf,
        bytes32[] calldata proof,
        bool[] calldata proofPositions
    ) external view returns (bool valid) {
        if (bundles[bundleId].timestamp == 0) revert BundleNotFound(bundleId);
        if (proof.length != proofPositions.length) revert InvalidProofLength();

        bytes32 computed = txLeaf;
        for (uint256 i = 0; i < proof.length; ) {
            bytes32 sibling = proof[i];
            // Canonical ordering: smaller value goes left
            if (computed <= sibling) {
                computed = keccak256(abi.encodePacked(computed, sibling));
            } else {
                computed = keccak256(abi.encodePacked(sibling, computed));
            }
            unchecked { ++i; }
        }

        valid = (computed == bundles[bundleId].merkleRoot);
    }
}
