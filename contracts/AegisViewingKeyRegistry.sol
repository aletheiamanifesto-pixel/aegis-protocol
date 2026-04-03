// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title AegisViewingKeyRegistry
 * @notice On-chain, immutable registry for viewing key grants and revocations.
 *
 * Enables the regulatory compliance flow:
 *   1. Owner calls grantAccess() to register a viewing key grant on-chain.
 *   2. An event is emitted providing an auditable, immutable proof of the grant.
 *   3. Owner (or regulator) calls revokeAccess() to revoke the grant.
 *   4. isAccessActive() can be queried to verify whether a grant is still valid.
 */
contract AegisViewingKeyRegistry {

    // -----------------------------------------------------------------------
    // Structs
    // -----------------------------------------------------------------------

    struct Grant {
        address owner;       // wallet that issued the grant
        address grantee;     // recipient (regulatory agency, etc.)
        bytes32 txHash;      // associated transaction hash (0 = not linked to a specific tx)
        string  scope;       // scope string, e.g. "single_tx", "balance_only"
        uint256 grantedAt;   // block.timestamp when granted
        uint256 expiresAt;   // 0 = never expires
        bool    active;      // false when revoked
    }

    // -----------------------------------------------------------------------
    // State
    // -----------------------------------------------------------------------

    address public owner;
    bool    public paused;

    /// @notice Maps a grantId to the corresponding Grant struct.
    mapping(bytes32 => Grant) public grants;

    // -----------------------------------------------------------------------
    // Events
    // -----------------------------------------------------------------------

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

    // -----------------------------------------------------------------------
    // Modifiers
    // -----------------------------------------------------------------------

    modifier onlyOwner() {
        require(msg.sender == owner, "AegisVKR: not owner");
        _;
    }

    modifier whenNotPaused() {
        require(!paused, "AegisVKR: paused");
        _;
    }

    // -----------------------------------------------------------------------
    // Constructor
    // -----------------------------------------------------------------------

    constructor() {
        owner = msg.sender;
    }

    // -----------------------------------------------------------------------
    // Admin
    // -----------------------------------------------------------------------

    /// @notice Pause the contract (owner only).
    function pause() external onlyOwner {
        paused = true;
        emit Paused(msg.sender);
    }

    /// @notice Unpause the contract (owner only).
    function unpause() external onlyOwner {
        paused = false;
        emit Unpaused(msg.sender);
    }

    // -----------------------------------------------------------------------
    // Core functions
    // -----------------------------------------------------------------------

    /**
     * @notice Register a viewing key grant on-chain.
     *
     * The caller is the owner of the wallet granting access.
     *
     * @param grantee   Address that receives the viewing key access.
     * @param txHash    Hash of the transaction this grant is scoped to (0 for generic grant).
     * @param scope     Scope string describing the level of disclosure.
     * @param expiresAt Unix timestamp when the grant expires (0 = no expiry).
     * @return grantId  Unique identifier for this grant.
     */
    function grantAccess(
        address grantee,
        bytes32 txHash,
        string calldata scope,
        uint256 expiresAt
    ) external whenNotPaused returns (bytes32 grantId) {
        require(grantee != address(0), "AegisVKR: grantee is zero address");
        require(bytes(scope).length > 0, "AegisVKR: scope is empty");
        require(
            expiresAt == 0 || expiresAt > block.timestamp,
            "AegisVKR: expiry is in the past"
        );

        // Deterministic grantId from caller + grantee + txHash + block.timestamp
        grantId = keccak256(
            abi.encodePacked(msg.sender, grantee, txHash, block.timestamp)
        );

        // Prevent collision (extremely unlikely but safe to check)
        require(grants[grantId].grantedAt == 0, "AegisVKR: grantId collision");

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
     * @notice Revoke a previously granted access.
     *
     * Only the original grant owner may revoke.
     *
     * @param grantId The identifier of the grant to revoke.
     */
    function revokeAccess(bytes32 grantId) external whenNotPaused {
        Grant storage g = grants[grantId];
        require(g.grantedAt != 0, "AegisVKR: grant does not exist");
        require(g.owner == msg.sender, "AegisVKR: not grant owner");
        require(g.active, "AegisVKR: already revoked");

        g.active = false;

        emit AccessRevoked(grantId, msg.sender, block.timestamp);
    }

    // -----------------------------------------------------------------------
    // View functions
    // -----------------------------------------------------------------------

    /**
     * @notice Check whether a grant is currently active and not expired.
     *
     * @param grantId The identifier of the grant to check.
     * @return True if active and not expired, false otherwise.
     */
    function isAccessActive(bytes32 grantId) external view returns (bool) {
        Grant storage g = grants[grantId];
        if (!g.active) return false;
        if (g.grantedAt == 0) return false;
        if (g.expiresAt != 0 && block.timestamp > g.expiresAt) return false;
        return true;
    }

    /**
     * @notice Return the full details of a grant.
     *
     * @param grantId The identifier of the grant.
     * @return owner_     Wallet that issued the grant.
     * @return grantee_   Recipient of the grant.
     * @return txHash_    Associated transaction hash.
     * @return scope_     Scope string.
     * @return grantedAt_ Timestamp when granted.
     * @return expiresAt_ Timestamp when the grant expires (0 = no expiry).
     * @return active_    Whether the grant is currently active.
     */
    function getGrant(bytes32 grantId)
        external
        view
        returns (
            address owner_,
            address grantee_,
            bytes32 txHash_,
            string memory scope_,
            uint256 grantedAt_,
            uint256 expiresAt_,
            bool    active_
        )
    {
        Grant storage g = grants[grantId];
        require(g.grantedAt != 0, "AegisVKR: grant does not exist");
        return (
            g.owner,
            g.grantee,
            g.txHash,
            g.scope,
            g.grantedAt,
            g.expiresAt,
            g.active
        );
    }
}
