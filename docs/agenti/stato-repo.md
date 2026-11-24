# Stato del repo — revisione del 24/11/2026

Revisione di Claude su `main` @ `7682c8e` (merge PR #48, 19/11/2026).

## Cosa c'è

Il repo contiene due linee di prodotto nello stesso backend FastAPI.

| Area | Contenuto | Stato |
|---|---|---|
| **AEGIS** (stablecoin EUR con privacy) | `contracts/` (AegisEUR, ShieldedPool, Vault, SmartAccount, ViewingKeyRegistry, NoirVerifier), `noir_circuits/`, `routers/` (auth, banking, pool, bridge, compliance, oracle, reporting, settlement, transactions, wallet, viewing_keys_v2) | Tecnicamente ricco, ma **non monetizzabile da solo**: emettere un token EUR richiede un emittente autorizzato (EMI/banca) sotto MiCA. |
| **ProofMint** (SaaS Digital Product Passport) | `proofmint/` (router, models, schemas, ai_engine, gs1_formatter, IPFS, blockchain_service), `contracts/ProofMintRegistry.sol`, `frontend/` Next.js (pricing, register, dashboard) | **È la linea vendibile adesso.** Pagina prezzi già presente: Starter gratis (5 prodotti), PRO 49 €/mese (500 prodotti). |
| Infrastruttura | Dockerfile, docker-compose, Procfile, alembic `migrations/`, CI: `test.yml`, `docker.yml`, `security.yml` | Buona base. CHANGELOG fermo a v0.1.0. |
| Test | 23 file in `tests/` (pytest), test Solidity in `contracts/test` | ProofMint aveva 9 test, nessuno sui piani. |

## Problemi trovati (ordinati per impatto sui ricavi)

1. **Il piano a pagamento non era vendibile.** `register_brand` salvava `plan=payload.plan`: chiunque poteva registrarsi già come `pro`. `create_product` non applicava nessun limite, quindi anche il piano gratis aveva prodotti illimitati. → **Corretto in questa PR.**
2. **Nessun incasso collegato.** Il pulsante "Prova 14 giorni gratis" porta a `/register?plan=pro`, ma non esistono checkout, trial con scadenza o webhook di pagamento.
3. **Limiti duplicati sul frontend.** `frontend/app/dashboard/settings/page.tsx` calcola il limite da `localStorage` (`pro` → 500, altrimenti 5). Ora il backend restituisce `products_limit`: il frontend dovrebbe usare quello.
4. **Allineamento normativo da dimostrare.** Il README dice "ESPR-aligned", ma non c'è ancora la registrazione dei passaporti nel Registro DPP UE (operativo dal 20/07/2026) né GS1 Digital Link come risolutore pubblico.
5. **Due prodotti in un repo.** Chi valuta ProofMint vede codice stablecoin/ZK che non gli serve. A medio termine conviene separarli o almeno separare README e landing.

## Cosa non ho potuto verificare

Nel container mancano le dipendenze Python e l'installazione dei pacchetti è bloccata, quindi i test girano solo in CI su questa PR (`test.yml`). Ho controllato la sintassi con `py_compile`.
