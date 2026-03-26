// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title IComplianceRegistry
 * @notice Interface per il registro di conformità AML/KYC utilizzato da AegisEURC.
 * @dev Ogni indirizzo deve essere verificato prima di poter inviare o ricevere token.
 *      Questo registro viene gestito da un ente autorizzato (COMPLIANCE_ROLE) ed è
 *      conforme ai requisiti del regolamento MiCA per gli e-money token (EMT).
 *
 *      Il registro deve supportare due query:
 *        - isVerified: l'indirizzo ha completato il KYC ed è autorizzato ad operare.
 *        - isSanctioned: l'indirizzo è presente in una lista di sanzioni (OFAC, EU, ecc.).
 */
interface IComplianceRegistry {
    /**
     * @notice Verifica se un indirizzo ha superato i controlli KYC/AML.
     * @param account L'indirizzo da verificare.
     * @return True se l'indirizzo è verificato e autorizzato, false altrimenti.
     */
    function isVerified(address account) external view returns (bool);

    /**
     * @notice Verifica se un indirizzo è presente in una lista di sanzioni.
     * @param account L'indirizzo da controllare.
     * @return True se l'indirizzo è sanzionato e quindi bloccato, false altrimenti.
     */
    function isSanctioned(address account) external view returns (bool);
}
