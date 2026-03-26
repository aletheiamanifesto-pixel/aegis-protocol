// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// ─────────────────────────────────────────────────────────────────────────────
// OpenZeppelin v5.x imports
// ─────────────────────────────────────────────────────────────────────────────
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Permit.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "./interfaces/IComplianceRegistry.sol";

/**
 * @title AegisEURC
 * @author Aegis Protocol Team
 * @notice Token ERC-20 che rappresenta l'Euro tokenizzato 1:1, conforme al
 *         regolamento MiCA (Markets in Crypto-Assets Regulation) per gli
 *         e-money token (EMT).
 *
 * @dev Architettura di sicurezza:
 *
 *   ┌──────────────────────────────────────────────────────────────────────┐
 *   │                         AegisEURC                                   │
 *   │                                                                      │
 *   │  ERC20  ─► base token logic (name, symbol, decimals, transfers)     │
 *   │  Custom Snapshot ─► fotografie del possesso per audit regolatorio   │
 *   │  ERC20Permit ─► gasless approvals (EIP-2612)                        │
 *   │  AccessControl ─► RBAC per minter, burner, compliance               │
 *   │  Pausable ─► circuit breaker per emergenze                          │
 *   │  ReentrancyGuard ─► protezione contro reentrancy                    │
 *   │                                                                      │
 *   │  Compliance Hook (_update override)                                 │
 *   │    └─► IComplianceRegistry (KYC/AML/Sanctions check)               │
 *   │                                                                      │
 *   │  Proof of Reserve                                                   │
 *   │    └─► reserveReportURI (link on-chain ai report di audit)          │
 *   │                                                                      │
 *   │  Emergency Freeze                                                   │
 *   │    └─► freezeAccount / unfreezeAccount (COMPLIANCE_ROLE)            │
 *   └──────────────────────────────────────────────────────────────────────┘
 *
 *  Ruoli RBAC:
 *    - DEFAULT_ADMIN_ROLE: Gestione ruoli, aggiornamento PoR URI
 *    - MINTER_ROLE:        Oracolo che conferma il deposito FIAT → mint
 *    - BURNER_ROLE:        Prelievo/off-ramp → burn
 *    - COMPLIANCE_ROLE:    Controlli AML, freeze/unfreeze
 *    - SNAPSHOT_ROLE:      Scatto snapshot per audit regolatorio
 *
 *  Nota su Snapshot:
 *    ERC20Snapshot è stato rimosso in OpenZeppelin v5.0. Questo contratto
 *    implementa un meccanismo di snapshot gas-efficient equivalente,
 *    compatibile con la nuova architettura _update di OZ v5.
 *    L'approccio è identico a quello di OZ v4: i saldi vengono registrati
 *    su richiesta (lazy snapshot) solo quando cambiano dopo uno snapshot,
 *    minimizzando i costi di gas durante le operazioni normali.
 */
contract AegisEURC is
    ERC20,
    ERC20Permit,
    AccessControl,
    Pausable,
    ReentrancyGuard
{

    // ─────────────────────────────────────────────────────────────────────
    // Roles
    // ─────────────────────────────────────────────────────────────────────

    /// @notice Ruolo per l'oracolo che conferma il deposito FIAT e autorizza il mint.
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");

    /// @notice Ruolo per il servizio di prelievo/off-ramp che autorizza il burn.
    bytes32 public constant BURNER_ROLE = keccak256("BURNER_ROLE");

    /// @notice Ruolo per gli operatori di conformità AML/KYC.
    bytes32 public constant COMPLIANCE_ROLE = keccak256("COMPLIANCE_ROLE");

    /// @notice Ruolo per gli enti autorizzati a scattare snapshot.
    bytes32 public constant SNAPSHOT_ROLE = keccak256("SNAPSHOT_ROLE");

    // ─────────────────────────────────────────────────────────────────────
    // Snapshot Storage (gas-efficient, equivalent to OZ v4 ERC20Snapshot)
    // ─────────────────────────────────────────────────────────────────────

    /**
     * @dev Struttura per memorizzare le coppie (snapshotId, valore) in modo
     *      ordinato. Utilizza array paralleli per efficienza di storage.
     */
    struct Snapshots {
        uint256[] ids;
        uint256[] values;
    }

    /// @dev Snapshot dei saldi per account.
    mapping(address account => Snapshots) private _accountBalanceSnapshots;

    /// @dev Snapshot della total supply.
    Snapshots private _totalSupplySnapshots;

    /// @dev Contatore incrementale degli snapshot ID.
    uint256 private _currentSnapshotId;

    /// @notice Emesso quando viene creato un nuovo snapshot.
    event Snapshot(uint256 id);

    // ─────────────────────────────────────────────────────────────────────
    // State Variables
    // ─────────────────────────────────────────────────────────────────────

    /// @notice Riferimento al ComplianceRegistry per i controlli KYC/AML.
    IComplianceRegistry public complianceRegistry;

    /// @notice URI del report di audit delle riserve bancarie reali (Proof of Reserve).
    string public reserveReportURI;

    /// @notice Mappa degli account congelati per attività illecite.
    mapping(address account => bool) public frozenAccounts;

    // ─────────────────────────────────────────────────────────────────────
    // Events
    // ─────────────────────────────────────────────────────────────────────

    /// @notice Emesso quando un account viene congelato.
    event AccountFrozen(address indexed account, address indexed by);

    /// @notice Emesso quando un account viene scongelato.
    event AccountUnfrozen(address indexed account, address indexed by);

    /// @notice Emesso quando il report delle riserve viene aggiornato.
    event ReserveReportUpdated(string newURI, address indexed by);

    /// @notice Emesso quando il ComplianceRegistry viene aggiornato.
    event ComplianceRegistryUpdated(
        address indexed oldRegistry,
        address indexed newRegistry,
        address indexed by
    );

    // ─────────────────────────────────────────────────────────────────────
    // Errors
    // ─────────────────────────────────────────────────────────────────────

    /// @notice Trasferimento bloccato: mittente non verificato KYC.
    error SenderNotVerified(address sender);

    /// @notice Trasferimento bloccato: destinatario non verificato KYC.
    error RecipientNotVerified(address recipient);

    /// @notice Trasferimento bloccato: mittente sanzionato.
    error SenderSanctioned(address sender);

    /// @notice Trasferimento bloccato: destinatario sanzionato.
    error RecipientSanctioned(address recipient);

    /// @notice Operazione bloccata: account congelato.
    error AccountIsFrozen(address account);

    /// @notice L'account è già nello stato richiesto (frozen/unfrozen).
    error AccountAlreadyInState(address account, bool frozen);

    /// @notice Indirizzo zero non consentito.
    error ZeroAddressNotAllowed();

    /// @notice URI vuoto non consentito.
    error EmptyURINotAllowed();

    /// @notice Snapshot ID non valido (zero).
    error SnapshotIdIsZero();

    /// @notice Snapshot ID non ancora esistente.
    error SnapshotIdNonexistent(uint256 snapshotId);

    // ─────────────────────────────────────────────────────────────────────
    // Constructor
    // ─────────────────────────────────────────────────────────────────────

    /**
     * @notice Inizializza il token AegisEURC con nome, simbolo e configurazione RBAC.
     * @param _admin Indirizzo dell'amministratore iniziale (riceve DEFAULT_ADMIN_ROLE).
     * @param _complianceRegistry Indirizzo del contratto ComplianceRegistry.
     *
     * @dev Il token utilizza 6 decimali (standard per stablecoin EUR), coerente con
     *      la convenzione di Circle EURC e gli standard di pagamento ISO 4217.
     *      ERC20Permit è inizializzato con il nome del token per EIP-712 domain separator.
     */
    constructor(
        address _admin,
        address _complianceRegistry
    ) ERC20("Aegis Euro Coin", "AEURC") ERC20Permit("Aegis Euro Coin") {
        if (_admin == address(0)) revert ZeroAddressNotAllowed();
        if (_complianceRegistry == address(0)) revert ZeroAddressNotAllowed();

        // Assegna tutti i ruoli all'admin iniziale.
        // In produzione, i ruoli verranno delegati a indirizzi specifici.
        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(MINTER_ROLE, _admin);
        _grantRole(BURNER_ROLE, _admin);
        _grantRole(COMPLIANCE_ROLE, _admin);
        _grantRole(SNAPSHOT_ROLE, _admin);

        complianceRegistry = IComplianceRegistry(_complianceRegistry);
    }

    // ─────────────────────────────────────────────────────────────────────
    // Decimals Override
    // ─────────────────────────────────────────────────────────────────────

    /**
     * @notice Restituisce 6 decimali, standard per stablecoin EUR (ISO 4217).
     * @dev Override necessario per allinearsi allo standard EURC di Circle e
     *      facilitare l'integrazione con exchange e protocolli DeFi.
     */
    function decimals() public pure override returns (uint8) {
        return 6;
    }

    // ─────────────────────────────────────────────────────────────────────
    // Minting (Fiat On-Ramp)
    // ─────────────────────────────────────────────────────────────────────

    /**
     * @notice Crea nuovi token AEURC a seguito della conferma di un deposito FIAT.
     * @param to Indirizzo destinatario dei token mintati.
     * @param amount Quantità di token da mintare (in unità con 6 decimali).
     *
     * @dev Può essere chiamata solo dall'oracolo MINTER_ROLE dopo la conferma
     *      del deposito bancario. Il contratto è protetto da reentrancy e
     *      può essere messo in pausa in caso di emergenza.
     *
     *      Flusso tipico:
     *        1. Utente deposita EUR su conto bancario segregato
     *        2. Oracolo off-chain verifica il deposito
     *        3. Oracolo chiama mint() → token coniati per l'utente
     */
    function mint(
        address to,
        uint256 amount
    ) external onlyRole(MINTER_ROLE) whenNotPaused nonReentrant {
        if (to == address(0)) revert ZeroAddressNotAllowed();
        _mint(to, amount);
    }

    // ─────────────────────────────────────────────────────────────────────
    // Burning (Fiat Off-Ramp)
    // ─────────────────────────────────────────────────────────────────────

    /**
     * @notice Distrugge token AEURC per avviare un prelievo FIAT.
     * @param from Indirizzo dal quale i token vengono bruciati.
     * @param amount Quantità di token da bruciare.
     *
     * @dev Può essere chiamata solo dal servizio BURNER_ROLE.
     *      Il burn avvia il processo di off-ramp: i fondi FIAT equivalenti
     *      vengono trasferiti dal conto bancario segregato al conto dell'utente.
     *
     *      Flusso tipico:
     *        1. Utente richiede prelievo tramite dApp
     *        2. Servizio off-ramp chiama burn() → token distrutti
     *        3. Bonifico SEPA inviato all'utente
     */
    function burn(
        address from,
        uint256 amount
    ) external onlyRole(BURNER_ROLE) whenNotPaused nonReentrant {
        if (from == address(0)) revert ZeroAddressNotAllowed();
        _burn(from, amount);
    }

    // ─────────────────────────────────────────────────────────────────────
    // Proof of Reserve (PoR)
    // ─────────────────────────────────────────────────────────────────────

    /**
     * @notice Aggiorna l'URI del report di audit delle riserve bancarie.
     * @param newURI Nuovo URI (es. IPFS hash o URL del report di audit).
     *
     * @dev Solo l'admin può aggiornare il PoR URI. Questo collega on-chain
     *      i report di audit delle riserve reali, permettendo a chiunque di
     *      verificare la copertura 1:1 dei token in circolazione.
     *
     *      Esempio di URI: "ipfs://QmXyz.../reserve-report-2024-Q4.pdf"
     */
    function updateReserveReport(
        string calldata newURI
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (bytes(newURI).length == 0) revert EmptyURINotAllowed();
        reserveReportURI = newURI;
        emit ReserveReportUpdated(newURI, msg.sender);
    }

    // ─────────────────────────────────────────────────────────────────────
    // Compliance Registry Management
    // ─────────────────────────────────────────────────────────────────────

    /**
     * @notice Aggiorna l'indirizzo del ComplianceRegistry.
     * @param newRegistry Nuovo indirizzo del contratto ComplianceRegistry.
     *
     * @dev Solo l'admin può aggiornare il registry. Permette di migrare
     *      a una nuova versione del registro di conformità senza
     *      ridistribuire il token.
     */
    function updateComplianceRegistry(
        address newRegistry
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (newRegistry == address(0)) revert ZeroAddressNotAllowed();
        address oldRegistry = address(complianceRegistry);
        complianceRegistry = IComplianceRegistry(newRegistry);
        emit ComplianceRegistryUpdated(oldRegistry, newRegistry, msg.sender);
    }

    // ─────────────────────────────────────────────────────────────────────
    // Gas-Efficient Snapshots
    // ─────────────────────────────────────────────────────────────────────

    /**
     * @notice Scatta una "fotografia" del possesso dei token al blocco corrente.
     * @return snapshotId L'ID dello snapshot creato.
     *
     * @dev Utilizzato dagli enti regolatori per audit fiscali e di conformità.
     *      Il meccanismo è gas-efficient (lazy snapshot): non blocca
     *      l'operatività e registra i saldi solo quando cambiano dopo
     *      lo snapshot, minimizzando i costi.
     *
     *      Nota: ERC20Snapshot è stato rimosso in OpenZeppelin v5.0.
     *      Questa implementazione replica lo stesso approccio gas-efficient
     *      dell'originale, adattato all'architettura _update di OZ v5.
     */
    function snapshot()
        external
        onlyRole(SNAPSHOT_ROLE)
        returns (uint256 snapshotId)
    {
        snapshotId = _snapshot();
    }

    /**
     * @notice Restituisce il saldo di un account ad un determinato snapshot.
     * @param account L'indirizzo dell'account.
     * @param snapshotId L'ID dello snapshot da interrogare.
     * @return Il saldo dell'account al momento dello snapshot.
     */
    function balanceOfAt(
        address account,
        uint256 snapshotId
    ) public view returns (uint256) {
        (bool snapshotted, uint256 value) = _valueAt(
            snapshotId,
            _accountBalanceSnapshots[account]
        );
        return snapshotted ? value : balanceOf(account);
    }

    /**
     * @notice Restituisce la total supply ad un determinato snapshot.
     * @param snapshotId L'ID dello snapshot da interrogare.
     * @return La total supply al momento dello snapshot.
     */
    function totalSupplyAt(uint256 snapshotId) public view returns (uint256) {
        (bool snapshotted, uint256 value) = _valueAt(
            snapshotId,
            _totalSupplySnapshots
        );
        return snapshotted ? value : totalSupply();
    }

    /**
     * @notice Restituisce l'ID dello snapshot corrente.
     * @return L'ID dell'ultimo snapshot creato (0 se nessuno snapshot).
     */
    function getCurrentSnapshotId() external view returns (uint256) {
        return _currentSnapshotId;
    }

    // ─────────────────────────────────────────────────────────────────────
    // Emergency Freeze (Normativa bancaria AML)
    // ─────────────────────────────────────────────────────────────────────

    /**
     * @notice Congela un account sospetto, bloccando qualsiasi trasferimento.
     * @param account L'indirizzo da congelare.
     *
     * @dev Richiesto dalle normative bancarie (es. Direttiva UE 2015/849
     *      sulla prevenzione del riciclaggio). Il COMPLIANCE_ROLE può
     *      congelare fondi legati ad attività illecite in attesa di
     *      indagini delle autorità competenti.
     */
    function freezeAccount(
        address account
    ) external onlyRole(COMPLIANCE_ROLE) {
        if (account == address(0)) revert ZeroAddressNotAllowed();
        if (frozenAccounts[account])
            revert AccountAlreadyInState(account, true);
        frozenAccounts[account] = true;
        emit AccountFrozen(account, msg.sender);
    }

    /**
     * @notice Scongela un account precedentemente congelato.
     * @param account L'indirizzo da scongelare.
     *
     * @dev Può essere chiamata solo dal COMPLIANCE_ROLE dopo che le
     *      autorità competenti hanno completato le indagini e
     *      autorizzato lo sblocco dei fondi.
     */
    function unfreezeAccount(
        address account
    ) external onlyRole(COMPLIANCE_ROLE) {
        if (account == address(0)) revert ZeroAddressNotAllowed();
        if (!frozenAccounts[account])
            revert AccountAlreadyInState(account, false);
        frozenAccounts[account] = false;
        emit AccountUnfrozen(account, msg.sender);
    }

    // ─────────────────────────────────────────────────────────────────────
    // Pause / Unpause (Circuit Breaker)
    // ─────────────────────────────────────────────────────────────────────

    /**
     * @notice Mette in pausa tutte le operazioni del token (circuit breaker).
     * @dev Solo l'admin può attivare la pausa. Utilizzato in caso di
     *      emergenza (exploit, bug critici, ordini delle autorità).
     */
    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    /**
     * @notice Riattiva le operazioni del token dopo una pausa.
     */
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    // ─────────────────────────────────────────────────────────────────────
    // Compliance Hook — _update Override (The Filter)
    // ─────────────────────────────────────────────────────────────────────

    /**
     * @notice Override della funzione _update (OpenZeppelin 5.0) per implementare
     *         il filtro di conformità e lo snapshot su ogni trasferimento di token.
     *
     * @param from Indirizzo mittente (address(0) per mint).
     * @param to Indirizzo destinatario (address(0) per burn).
     * @param value Quantità di token trasferiti.
     *
     * @dev Questo è "The Filter" — il cuore della conformità MiCA.
     *      Ogni trasferimento (inclusi mint e burn) passa attraverso _update.
     *
     *      Logica di verifica:
     *        1. Se il contratto è in pausa → revert (whenNotPaused)
     *        2. Se `from` è congelato → revert
     *        3. Se `to` è congelato → revert
     *        4. Se `from` non è address(0) (non è un mint):
     *           - Verifica che `from` sia KYC-verificato
     *           - Verifica che `from` non sia sanzionato
     *        5. Se `to` non è address(0) (non è un burn):
     *           - Verifica che `to` sia KYC-verificato
     *           - Verifica che `to` non sia sanzionato
     *        6. Aggiorna gli snapshot (lazy) prima di modificare i saldi
     *        7. Esegue il trasferimento ERC20 base
     *
     *      Nota: address(0) è escluso dai controlli perché è l'indirizzo
     *      convenzionale usato da ERC-20 per mint (from=0) e burn (to=0).
     *      La sicurezza del mint/burn è garantita dai ruoli MINTER/BURNER.
     */
    function _update(
        address from,
        address to,
        uint256 value
    ) internal override whenNotPaused {
        // ── Freeze check ────────────────────────────────────────────────
        if (from != address(0) && frozenAccounts[from])
            revert AccountIsFrozen(from);
        if (to != address(0) && frozenAccounts[to])
            revert AccountIsFrozen(to);

        // ── KYC / Sanctions check (The Filter) ─────────────────────────
        if (from != address(0)) {
            if (!complianceRegistry.isVerified(from))
                revert SenderNotVerified(from);
            if (complianceRegistry.isSanctioned(from))
                revert SenderSanctioned(from);
        }

        if (to != address(0)) {
            if (!complianceRegistry.isVerified(to))
                revert RecipientNotVerified(to);
            if (complianceRegistry.isSanctioned(to))
                revert RecipientSanctioned(to);
        }

        // ── Snapshot update (lazy, gas-efficient) ───────────────────────
        // Registra i saldi correnti prima della modifica, solo se
        // c'è uno snapshot attivo che non ha ancora registrato questo account.
        if (_currentSnapshotId > 0) {
            if (from != address(0)) {
                _updateSnapshot(
                    _accountBalanceSnapshots[from],
                    balanceOf(from)
                );
            }
            if (to != address(0)) {
                _updateSnapshot(
                    _accountBalanceSnapshots[to],
                    balanceOf(to)
                );
            }
            _updateSnapshot(_totalSupplySnapshots, totalSupply());
        }

        // ── Procedi con il trasferimento ERC20 base ─────────────────────
        super._update(from, to, value);
    }

    // ─────────────────────────────────────────────────────────────────────
    // Snapshot Internal Logic
    // ─────────────────────────────────────────────────────────────────────

    /**
     * @dev Crea un nuovo snapshot e restituisce il suo ID.
     *      Incrementa il contatore e emette l'evento Snapshot.
     */
    function _snapshot() internal returns (uint256) {
        _currentSnapshotId++;
        uint256 currentId = _currentSnapshotId;
        emit Snapshot(currentId);
        return currentId;
    }

    /**
     * @dev Aggiorna lo snapshot per una struttura Snapshots specifica.
     *      Registra il valore corrente solo se non è già stato registrato
     *      per lo snapshot corrente (lazy update).
     *
     * @param snapshots La struttura Snapshots da aggiornare.
     * @param currentValue Il valore corrente da registrare.
     */
    function _updateSnapshot(
        Snapshots storage snapshots,
        uint256 currentValue
    ) private {
        uint256 currentId = _currentSnapshotId;
        if (_lastSnapshotId(snapshots.ids) < currentId) {
            snapshots.ids.push(currentId);
            snapshots.values.push(currentValue);
        }
    }

    /**
     * @dev Restituisce l'ultimo snapshot ID registrato in un array di ID.
     * @param ids Array di snapshot ID.
     * @return L'ultimo ID, o 0 se l'array è vuoto.
     */
    function _lastSnapshotId(
        uint256[] storage ids
    ) private view returns (uint256) {
        if (ids.length == 0) {
            return 0;
        }
        return ids[ids.length - 1];
    }

    /**
     * @dev Cerca il valore associato a uno snapshot ID specifico.
     *      Utilizza binary search (lower bound) per efficienza O(log n).
     *
     *      Semantica: trova la prima entry con id >= snapshotId.
     *        - Se ids[index] == snapshotId: il valore è il saldo registrato
     *          prima del primo trasferimento dopo lo snapshot.
     *        - Se ids[index] > snapshotId: nessun trasferimento è avvenuto
     *          tra snapshotId e ids[index], quindi il saldo registrato è
     *          anche il saldo corretto a snapshotId.
     *        - Se non esiste alcun index: nessun trasferimento è avvenuto
     *          dopo snapshotId, quindi il saldo corrente è corretto.
     *
     * @param snapshotId L'ID dello snapshot da cercare.
     * @param snapshots La struttura Snapshots in cui cercare.
     * @return (found, value) - found è true se il valore è stato trovato
     *         nello storico snapshot. Se false, il chiamante deve usare
     *         il saldo corrente.
     */
    function _valueAt(
        uint256 snapshotId,
        Snapshots storage snapshots
    ) private view returns (bool, uint256) {
        if (snapshotId == 0) revert SnapshotIdIsZero();
        if (snapshotId > _currentSnapshotId)
            revert SnapshotIdNonexistent(snapshotId);

        uint256 len = snapshots.ids.length;
        if (len == 0) {
            return (false, 0);
        }

        // Binary search: trova il primo indice dove ids[index] >= snapshotId
        // (lower bound). Questo ci dà il primo snapshot registrato che copre
        // il nostro target, poiché i valori sono registrati prima dei trasferimenti.
        uint256 low = 0;
        uint256 high = len;

        while (low < high) {
            uint256 mid = low + (high - low) / 2;
            if (snapshots.ids[mid] < snapshotId) {
                low = mid + 1;
            } else {
                high = mid;
            }
        }

        if (low == len) {
            // Nessun snapshot registrato con id >= snapshotId.
            // Il saldo non è cambiato dallo snapshot → usa il saldo corrente.
            return (false, 0);
        } else {
            // Trovato: il valore registrato è il saldo corretto a snapshotId.
            return (true, snapshots.values[low]);
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    // Required Overrides (Solidity linearization)
    // ─────────────────────────────────────────────────────────────────────

    /**
     * @dev Override richiesto da Solidity per ERC20Permit.
     */
    function nonces(
        address owner
    ) public view override(ERC20Permit) returns (uint256) {
        return super.nonces(owner);
    }

    /**
     * @dev Supporta le interfacce ERC-165 per AccessControl e ERC20.
     */
    function supportsInterface(
        bytes4 interfaceId
    ) public view override(AccessControl) returns (bool) {
        return super.supportsInterface(interfaceId);
    }
}
