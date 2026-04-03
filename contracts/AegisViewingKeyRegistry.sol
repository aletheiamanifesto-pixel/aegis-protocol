// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title AegisViewingKeyRegistry
 * @notice On-chain immutable registry for AEGIS Protocol viewing-key grants and revocations.
 *         Provides an auditable trail of which address was granted what scope of access to
 *         which transaction hash, for how long, and whether that access has been revoked.
 *
 * @dev Emits AccessGranted and AccessRevoked events so off-chain indexers can reconstruct
 *      the full history without storing any sensitive transaction data on-chain.
 */
contract AegisViewingKeyRegistry {

    // -------------------------------------------------------------------------
    // Data structures
    // -------------------------------------------------------------------------

    struct Grant {
        address owner;       // wallet that granted access
        address grantee;     // regulator / inspector address
        bytes32 txHash;      // keccak256 of the transaction reference
        string  scope;       // e.g. "single_tx", "balance_only"
        uint256 grantedAt;
        uint256 expiresAt;   // 0 = no expiry
        bool    active;
    }

    // -------------------------------------------------------------------------
    // State
    // -------------------------------------------------------------------------

    /// @notice Owner of the contract (deployer).
    address public owner;

    /// @notice Emergency pause flag.
    bool public paused;

    /// @notice Primary storage: grantId → Grant.
    mapping(bytes32 => Grant) public grants;

    // -------------------------------------------------------------------------
    // Events
    // -------------------------------------------------------------------------

    event AccessGranted(
        address indexed owner,
        address indexed grantee,
        bytes32 indexed txHash,
        string  scope,
        uint256 expiresAt,
        bytes32 grantId
    );

    event AccessRevoked(
        bytes32 indexed grantId,
        address indexed owner,
        uint256 revokedAt
    );

    event Paused(address indexed by);
    event Unpaused(address indexed by);

    // -------------------------------------------------------------------------
    // Modifiers
    // -------------------------------------------------------------------------

    modifier onlyOwner() {
        require(msg.sender == owner, "Not contract owner");
        _;
    }

    modifier whenNotPaused() {
        require(!paused, "Contract is paused");
        _;
    }

    // -------------------------------------------------------------------------
    // Constructor
    // -------------------------------------------------------------------------

    constructor() {
        owner = msg.sender;
    }

    // -------------------------------------------------------------------------
    // Admin
    // -------------------------------------------------------------------------

    /**
     * @notice Pause all state-changing operations.  Only the contract owner can call this.
     */
    function pause() external onlyOwner {
        paused = true;
        emit Paused(msg.sender);
    }

    /**
     * @notice Unpause operations.
     */
    function unpause() external onlyOwner {
        paused = false;
        emit Unpaused(msg.sender);
    }

    // -------------------------------------------------------------------------
    // Core operations
    // -------------------------------------------------------------------------

    /**
     * @notice Register a new viewing-key grant on-chain.
     *
     * @param grantee   The address that receives access (e.g. a regulatory agency).
     * @param txHash    The transaction hash the grant relates to.
     * @param scope     Human-readable scope string (e.g. "single_tx").
     * @param expiresAt Unix timestamp after which the grant is considered expired.
     *                  Pass 0 for a grant with no on-chain expiry.
     *
     * @return grantId  A unique identifier for this grant, derived from
     *                  keccak256(owner, grantee, txHash, block.timestamp).
     */
    function grantAccess(
        address grantee,
        bytes32 txHash,
        string calldata scope,
        uint256 expiresAt
    )
        external
        whenNotPaused
        returns (bytes32 grantId)
    {
        require(grantee != address(0), "Grantee is zero address");
        require(bytes(scope).length > 0, "Scope must not be empty");

        grantId = keccak256(
            abi.encodePacked(msg.sender, grantee, txHash, block.timestamp)
        );

        // Collision guard (extremely unlikely but defensive)
        require(grants[grantId].grantedAt == 0, "Grant ID collision");

        grants[grantId] = Grant({
            owner:     msg.sender,
            grantee:   grantee,
            txHash:    txHash,
            scope:     scope,
            grantedAt: block.timestamp,
            expiresAt: expiresAt,
            active:    true
        });

        emit AccessGranted(msg.sender, grantee, txHash, scope, expiresAt, grantId);
    }

    /**
     * @notice Revoke an existing grant.
     *
     * @dev Only the original owner of the grant can revoke it.
     *
     * @param grantId  The grant identifier returned by grantAccess().
     */
    function revokeAccess(bytes32 grantId) external whenNotPaused {
        Grant storage g = grants[grantId];
        require(g.grantedAt != 0, "Grant not found");
        require(g.owner == msg.sender, "Not grant owner");
        require(g.active, "Grant already revoked");

        g.active = false;

        emit AccessRevoked(grantId, msg.sender, block.timestamp);
    }

    // -------------------------------------------------------------------------
    // View functions
    // -------------------------------------------------------------------------

    /**
     * @notice Check whether a grant is currently active (not revoked and not expired).
     *
     * @param grantId  The grant identifier.
     * @return         True if the grant exists, has not been revoked, and has not expired.
     */
    function isAccessActive(bytes32 grantId) external view returns (bool) {
        Grant storage g = grants[grantId];
        if (g.grantedAt == 0) return false;
        if (!g.active) return false;
        if (g.expiresAt != 0 && block.timestamp > g.expiresAt) return false;
        return true;
    }

    /**
     * @notice Return the full details of a grant.
     *
     * @param grantId  The grant identifier.
     * @return         The Grant struct.
     */
    function getGrant(bytes32 grantId)
        external
        view
        returns (Grant memory)
    {
        require(grants[grantId].grantedAt != 0, "Grant not found");
        return grants[grantId];
    }
}
