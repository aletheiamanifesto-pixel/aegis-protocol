# Proposte — 24/11/2026

Le proposte sono ordinate per impatto sui ricavi. Lo stato indica a che punto è ciascuna.

| # | Proposta | Perché | Sforzo | Stato |
|---|---|---|---|---|
| 1 | **Enforcement piani ProofMint lato server**: la registrazione parte sempre `free`, limiti 5 / 500 prodotti (HTTP 402 oltre il limite), cambio piano solo da admin | Senza questo il piano PRO non si può vendere | S | ✅ **in questa PR** |
| 2 | **Checkout e trial reali**: trial PRO di 14 giorni con scadenza (`trial_ends_at` + migrazione alembic) e pagina di checkout con link di pagamento. Il webhook attiva il piano tramite l'endpoint admin. | La pagina prezzi promette una prova che oggi non esiste | M | Da fare. Serve la scelta del fornitore di pagamento da parte dell'utente. |
| 3 | **Modulo "Battery Passport"**: template dei campi richiesti dal Regolamento batterie per LMT/e-bike e pagina di atterraggio dedicata | Unico obbligo reale a breve (18/02/2027), segmento PMI poco servito | M | Da fare |
| 4 | **Frontend allineato al backend**: usare `plan` e `products_limit` restituiti dall'API invece di `localStorage`; mostrare "richiesta PRO in attesa di attivazione" | Evita che l'utente veda un piano diverso da quello reale | S | Da fare |
| 5 | **GS1 Digital Link + preparazione al Registro DPP UE**: URL risolvibili per GTIN e un'esportazione pronta per la registrazione | Requisito per vendere a chi deve essere conforme. I concorrenti già lo offrono. | M | Da fare |
| 6 | **Import CSV/Shopify** | DPPora e DPPera lo includono anche nei piani base | M | Da fare |
| 7 | **Separare il posizionamento**: README e landing ProofMint distinti da AEGIS | Il cliente DPP non deve vedere stablecoin e ZK | S | Da fare |
| 8 | **AEGIS come livello privacy/compliance sopra EMT esistenti** (EURC/EURe) invece che token proprio: SDK + pilota B2B | Emettere EUR richiede licenza EMI. Il valore sta in ShieldedPool + viewing key. | L | Da valutare |

Nota per la revisione: la #2 tocca il denaro, quindi si prepara il codice ma l'attivazione di qualsiasi account di pagamento la fa l'utente.
