// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// ─── OpenZeppelin v5.x Imports ──────────────────────────────────────────────
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Pausable.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/structs/Checkpoints.sol";

// ─── Local Interface ────────────────────────────────────────────────────────
import "./IComplianceRegistry.sol";

/**
 * @title AegisEURC
 * @author Aegis Protocol – Senior DeFi Architect
 * @notice MiCA-compliant Euro stablecoin backed 1:1 by real-world FIAT reserves.
 *
 * @dev Key design decisions
 * ────────────────────────
 * 1. **Role-Based Access Control (RBAC)**
 *    - `DEFAULT_ADMIN_ROLE`  → Protocol governance (multisig expected).
 *    - `MINTER_ROLE`         → Off-chain oracle that mints upon confirmed FIAT deposit.
 *    - `BURNER_ROLE`         → Off-ramp service that burns tokens on FIAT withdrawal.
 *    - `COMPLIANCE_ROLE`     → AML/CFT officer that can freeze suspicious accounts.
 *    - `SNAPSHOT_ROLE`       → Authorized entity (e.g., regulator) that can take snapshots.
 *
 * 2. **Compliance Hook ("The Filter")**
 *    Overrides `_update` (OZ 5.x standard) to query an external
 *    {IComplianceRegistry}. Both sender and receiver must be verified;
 *    frozen accounts are also blocked. Mints (from == address(0)) and
 *    burns (to == address(0)) only check the non-zero counterpart.
 *
 * 3. **Proof of Reserve (PoR)**
 *    `reserveReportURI` stores the IPFS/HTTPS link to the latest
 *    bank-audited reserve attestation. Only `DEFAULT_ADMIN_ROLE` can update it.
 *
 * 4. **Gas-Efficient Snapshots**
 *    Uses OZ `Checkpoints.Trace224` to checkpoint each account balance
 *    keyed by an incrementing snapshot ID. Regulators can query historical
 *    balances without pausing the contract.
 *
 * 5. **Emergency Freeze**
 *    `COMPLIANCE_ROLE` can freeze individual accounts, blocking all
 *    incoming and outgoing transfers as required by EU banking regulation.
 */
contract AegisEURC is ERC20, ERC20Pausable, AccessControl, ReentrancyGuard {
    using Checkpoints for Checkpoints.Trace224;

    // ─── Roles ──────────────────────────────────────────────────────────────
    bytes32 public constant MINTER_ROLE     = keccak256("MINTER_ROLE");
    bytes32 public constant BURNER_ROLE     = keccak256("BURNER_ROLE");
    bytes32 public constant COMPLIANCE_ROLE = keccak256("COMPLIANCE_ROLE");
    bytes32 public constant SNAPSHOT_ROLE   = keccak256("SNAPSHOT_ROLE");

    // ─── Compliance ─────────────────────────────────────────────────────────
    /// @notice External AML/KYC registry contract.
    IComplianceRegistry public complianceRegistry;

    /// @notice Accounts frozen by the compliance officer.
    mapping(address => bool) public frozenAccounts;

    // ─── Proof of Reserve ───────────────────────────────────────────────────
    /// @notice URI pointing to the latest reserve audit report (IPFS / HTTPS).
    string public reserveReportURI;

    // ─── Snapshot State ─────────────────────────────────────────────────────
    /// @dev Monotonically increasing snapshot counter (starts at 1).
    uint32 private _currentSnapshotId;

    /// @dev Per-account balance checkpoints keyed by snapshot ID.
    mapping(address => Checkpoints.Trace224) private _accountBalanceSnapshots;

    /// @dev Total supply checkpoints keyed by snapshot ID.
    Checkpoints.Trace224 private _totalSupplySnapshots;

    // ─── Events ─────────────────────────────────────────────────────────────
    event AccountFrozen(address indexed account, bool frozen);
    event ComplianceRegistryUpdated(address indexed newRegistry);
    event ReserveReportUpdated(string newURI);
    event Snapshot(uint256 id);

    // ─── Errors ─────────────────────────────────────────────────────────────
    error AccountIsFrozen(address account);
    error AddressNotCompliant(address account);
    error ZeroAddress();
    error InvalidComplianceRegistry();

    // ─── Constructor ────────────────────────────────────────────────────────
    /**
     * @param _complianceRegistry Address of the deployed ComplianceRegistry.
     * @param admin                Address receiving DEFAULT_ADMIN_ROLE (governance multisig).
     */
    constructor(
        address _complianceRegistry,
        address admin
    ) ERC20("Aegis Euro Coin", "aEURC") {
        if (_complianceRegistry == address(0)) revert ZeroAddress();
        if (admin == address(0)) revert ZeroAddress();

        complianceRegistry = IComplianceRegistry(_complianceRegistry);

        // Grant all roles to the initial admin; admin can later delegate.
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(MINTER_ROLE, admin);
        _grantRole(BURNER_ROLE, admin);
        _grantRole(COMPLIANCE_ROLE, admin);
        _grantRole(SNAPSHOT_ROLE, admin);
    }

    // ─── ERC-20 Decimals (EUR uses 6 decimals, like USDC) ───────────────────
    function decimals() public pure override returns (uint8) {
        return 6;
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  MINTING & BURNING
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * @notice Mint EURC after the oracle confirms a FIAT deposit.
     * @param to     Beneficiary address (must be KYC-verified).
     * @param amount Amount of EURC (6 decimals).
     */
    function mint(address to, uint256 amount) external onlyRole(MINTER_ROLE) nonReentrant {
        _mint(to, amount);
    }

    /**
     * @notice Burn EURC to initiate a FIAT off-ramp withdrawal.
     * @param from   Account whose tokens are burned (must be KYC-verified).
     * @param amount Amount of EURC to burn.
     */
    function burn(address from, uint256 amount) external onlyRole(BURNER_ROLE) nonReentrant {
        _burn(from, amount);
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  COMPLIANCE – FREEZE / UNFREEZE
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * @notice Freeze an account suspected of illicit activity (MiCA Art. 45).
     * @param account Target address.
     */
    function freezeAccount(address account) external onlyRole(COMPLIANCE_ROLE) {
        if (account == address(0)) revert ZeroAddress();
        frozenAccounts[account] = true;
        emit AccountFrozen(account, true);
    }

    /**
     * @notice Unfreeze a previously frozen account after investigation.
     * @param account Target address.
     */
    function unfreezeAccount(address account) external onlyRole(COMPLIANCE_ROLE) {
        if (account == address(0)) revert ZeroAddress();
        frozenAccounts[account] = false;
        emit AccountFrozen(account, false);
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  COMPLIANCE – REGISTRY UPDATE
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * @notice Replace the compliance registry (e.g., after a contract upgrade).
     * @param newRegistry Address of the new ComplianceRegistry.
     */
    function setComplianceRegistry(address newRegistry) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (newRegistry == address(0)) revert ZeroAddress();
        // Minimal sanity check: ensure the address contains code.
        uint256 codeSize;
        assembly { codeSize := extcodesize(newRegistry) }
        if (codeSize == 0) revert InvalidComplianceRegistry();

        complianceRegistry = IComplianceRegistry(newRegistry);
        emit ComplianceRegistryUpdated(newRegistry);
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  PROOF OF RESERVE
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * @notice Update the on-chain pointer to the latest reserve audit report.
     * @param newURI IPFS CID or HTTPS URL of the audit attestation.
     */
    function updateReserveReport(string calldata newURI) external onlyRole(DEFAULT_ADMIN_ROLE) {
        reserveReportURI = newURI;
        emit ReserveReportUpdated(newURI);
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  PAUSE / UNPAUSE (circuit breaker)
    // ═══════════════════════════════════════════════════════════════════════

    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  SNAPSHOTS
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * @notice Take a snapshot of all balances and total supply.
     * @dev Increments the snapshot counter; actual balance recording happens
     *      lazily inside `_update`. Only emits the new snapshot ID.
     * @return snapshotId The ID of the newly created snapshot.
     */
    function snapshot() external onlyRole(SNAPSHOT_ROLE) returns (uint256 snapshotId) {
        _currentSnapshotId++;
        snapshotId = _currentSnapshotId;
        emit Snapshot(snapshotId);
    }

    /**
     * @notice Query an account's balance at a past snapshot.
     * @param account    The address to query.
     * @param snapshotId The snapshot ID.
     * @return The balance at `snapshotId`, or 0 if no checkpoint exists.
     */
    function balanceOfAt(address account, uint32 snapshotId) external view returns (uint256) {
        return uint256(_accountBalanceSnapshots[account].upperLookup(snapshotId));
    }

    /**
     * @notice Query the total supply at a past snapshot.
     * @param snapshotId The snapshot ID.
     * @return The total supply at `snapshotId`, or 0 if no checkpoint exists.
     */
    function totalSupplyAt(uint32 snapshotId) external view returns (uint256) {
        return uint256(_totalSupplySnapshots.upperLookup(snapshotId));
    }

    /**
     * @notice Returns the current snapshot ID (0 if no snapshot has been taken).
     */
    function getCurrentSnapshotId() external view returns (uint256) {
        return _currentSnapshotId;
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  INTERNAL – _update (The Filter + Snapshot + Pausable)
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * @dev Core transfer hook (OZ 5.x pattern). Enforces:
     *   1. Pause guard (via ERC20Pausable).
     *   2. Frozen-account guard.
     *   3. ComplianceRegistry verification for both parties.
     *   4. Snapshot checkpoint recording when a snapshot exists.
     *
     * Mint  (from == 0): only checks `to`.
     * Burn  (to   == 0): only checks `from`.
     * Transfer:          checks both `from` and `to`.
     */
    function _update(
        address from,
        address to,
        uint256 value
    ) internal virtual override(ERC20, ERC20Pausable) {
        // ── Frozen-account guard ────────────────────────────────────────
        if (from != address(0) && frozenAccounts[from]) {
            revert AccountIsFrozen(from);
        }
        if (to != address(0) && frozenAccounts[to]) {
            revert AccountIsFrozen(to);
        }

        // ── Compliance verification ("The Filter") ─────────────────────
        if (from != address(0) && !complianceRegistry.isVerified(from)) {
            revert AddressNotCompliant(from);
        }
        if (to != address(0) && !complianceRegistry.isVerified(to)) {
            revert AddressNotCompliant(to);
        }

        // ── Delegate to ERC20Pausable → ERC20 (actual balance mutation) ─
        super._update(from, to, value);

        // ── Snapshot checkpoint recording ───────────────────────────────
        //    Record balances AFTER the transfer so checkpoints reflect the
        //    actual post-transfer state. Only checkpoint when at least one
        //    snapshot has been taken.
        if (_currentSnapshotId > 0) {
            uint32 sid = _currentSnapshotId;
            if (from != address(0)) {
                _accountBalanceSnapshots[from].push(sid, _toUint224(balanceOf(from)));
            }
            if (to != address(0)) {
                _accountBalanceSnapshots[to].push(sid, _toUint224(balanceOf(to)));
            }
            // Update total supply snapshot on mint/burn.
            if (from == address(0) || to == address(0)) {
                _totalSupplySnapshots.push(sid, _toUint224(totalSupply()));
            }
        }
    }

    // ─── Helpers ────────────────────────────────────────────────────────
    function _toUint224(uint256 value) private pure returns (uint224) {
        require(value <= type(uint224).max, "AegisEURC: value exceeds uint224");
        return uint224(value);
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  REQUIRED OVERRIDES (Solidity linearization)
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * @dev ERC-165 introspection combining ERC20 + AccessControl.
     */
    function supportsInterface(bytes4 interfaceId)
        public
        view
        override(AccessControl)
        returns (bool)
    {
        return super.supportsInterface(interfaceId);
    }
}
