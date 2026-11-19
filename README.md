# 🏛️ AEGIS Protocol

> Math-based decentralized bank: EUR-backed stablecoin with ZK privacy, MiCA compliance, and on-chain reserve proofs.

[![Tests](https://github.com/aletheiamanifesto-pixel/aegis-protocol/actions/workflows/test.yml/badge.svg)](https://github.com/aletheiamanifesto-pixel/aegis-protocol/actions/workflows/test.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Security](https://github.com/aletheiamanifesto-pixel/aegis-protocol/actions/workflows/security.yml/badge.svg)](https://github.com/aletheiamanifesto-pixel/aegis-protocol/actions/workflows/security.yml)

---

## Architecture

```mermaid
flowchart TD
    User([User / dApp]) -->|REST API| API[FastAPI Backend]

    subgraph API [FastAPI Backend]
        A1[auth] --- A2[wallet]
        A2 --- A3[transactions]
        A3 --- A4[compliance]
        A4 --- A5[banking]
        A5 --- A6[viewing-keys]
        A6 --- A7[bridge / oracle / reporting]
    end

    API -->|Web3.py| ETH[(Ethereum / Polygon Amoy)]
    API -->|SQLAlchemy| DB[(PostgreSQL)]

    subgraph Contracts [Smart Contracts]
        C1[AegisEUR.sol\nERC-20 stablecoin]
        C2[AegisVault.sol\nReserve vault]
        C3[NoirVerifier.sol\nZK proof verifier]
        C4[AegisBundleVerifier.sol\nMerkle bundle verifier]
        C5[AegisSmartAccount.sol\nERC-4337 account]
    end

    ETH --- Contracts

    EUR([EUR Bank Deposit]) -->|deposit| C2
    C2 -->|mint| C1
    C1 -->|transferWithProof| C3
    C3 -->|verify| ZK[Noir ZK Circuit]
    C1 -->|burn| C2
    C2 -->|withdraw| EUR

    API -->|Chainlink| Oracle[EUR/USD Oracle]
    API -->|lock + relay| Bridge[Cross-chain Bridge]
```

### Key flows

| Flow | Description |
|------|-------------|
| **Deposit** | EUR Bank → `AegisVault.deposit()` → `AegisEUR.mint()` |
| **Transfer** | `ComplianceEngine` check → `AegisEUR.transfer()` or `transferWithProof()` |
| **ZK proof** | Noir circuit → `NoirVerifier.verifyProof()` on-chain |
| **Withdrawal** | `AegisEUR.burn()` → `AegisVault.withdraw()` → EUR Bank Transfer |
| **Bundling** | `MerkleTree` → `AegisBundleVerifier.submitBundle()` |
| **Oracle** | Chainlink EUR/USD feed → price data |
| **Bridge** | Lock on source chain → mint/release on destination |

---

## Quick Start

### Prerequisites

- Python 3.11+
- Node.js 18+
- PostgreSQL (or use Docker)
- *(Optional)* Nargo CLI for real ZK proof generation

### Run with Docker

```bash
git clone https://github.com/aletheiamanifesto-pixel/aegis-protocol
cd aegis-protocol
cp .env.example .env          # edit with your settings
docker compose up --build
```

API → `http://localhost:8000`  
Swagger docs → `http://localhost:8000/docs`

### Run locally

```bash
pip install -r requirements.txt
npm install
cp .env.example .env          # edit with your settings
uvicorn main_app:app --reload
```

### Run tests

```bash
# Python / FastAPI tests
pytest tests/ -v

# Solidity tests
npx hardhat test
```

---

## Smart Contracts

Target network: **Polygon Amoy** testnet (Chain ID: 80002). **No contract addresses are published
yet**: deploy with `npm run deploy` / `npm run deploy:pool` and record the addresses from
`deployed_addresses.json` here.

| Contract | Description |
|----------|-------------|
| `AegisEUR.sol` | ERC-20 EUR token for the "own EMT" strategy (needs a licensed issuer); balances are public, use `ShieldedPool` for confidentiality |
| `ShieldedPool.sol` | Confidential pool for any ERC-20 (EURC/EURe/AegisEUR): ZK-verified notes, KYC in the proof, graduated disclosure |
| `AegisVault.sol` | Reserve vault with 1:1 EUR backing, multi-sig operations, on-chain audit reports |
| `AegisBundleVerifier.sol` | Merkle tree bundle verification for batched transactions |
| `NoirVerifier.sol` | On-chain ZK proof verifier (Noir / UltraPlonk) |
| `AegisSmartAccount.sol` | ERC-4337 smart account with guardian recovery |

---

## API Endpoints

The API runs on FastAPI with automatic OpenAPI docs at `/docs`.

### Auth
| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/auth/register` | Register a new user |
| `POST` | `/auth/login` | Get JWT access token |

### Wallet
| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/wallet/link/challenge` | One-time message to sign with the wallet key (on the device) |
| `POST` | `/wallet/link` | Link an address by EIP-191 signature (the server never sees keys or mnemonics) |
| `GET`  | `/wallet/balance/{address}` | Get AEGIS-EUR balance |
| `GET`  | `/wallet/transactions/{address}` | List wallet transactions |
| `GET`  | `/wallet/qr/{address}` | QR code PNG for receiving |

### Transactions
| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/transactions/send` | Broadcast an EURC transfer **signed on the device** (sender/recipient/amount read from the signed tx; compliance-checked; 2FA if enabled) |
| `GET`  | `/transactions/{tx_hash}/status` | Transaction status |

### Compliance (MiCA)
| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/compliance/kyc` | Submit KYC data (status → `pending`, never self-verified) |
| `POST` | `/compliance/kyc/{user_id}/decision` | Approve/reject KYC (role `compliance`/`admin`, not on yourself) |
| `POST` | `/compliance/kyc/webhook` | KYC provider result, HMAC-signed (`X-KYC-Signature`, `KYC_WEBHOOK_SECRET`) |
| `GET`  | `/compliance/profile` | Get compliance profile |

### ZK proofs & ShieldedPool
Proofs are generated **on the user's device** (`sdk/aegis-core.mjs` + Noir/bb.js) and verified
**on-chain** by `ShieldedPool`; the server never sees spending secrets or note contents.

| Method | Path | Description |
|--------|------|-------------|
| `GET`  | `/pool/issuer` | KYC issuer public key (register with `ShieldedPool.setIssuer`) and relayer address |
| `POST` | `/pool/credential` | Signed KYC credential for the `spend` circuit (verified customers only; tier/jurisdiction from the verification) |
| `POST` | `/pool/relay` | Relay a proven transaction to `ShieldedPool.transact` (simulated first, recorded in the operator register) |
| `GET`  | `/pool/relays/mine` | The caller's relayed transactions |

### Viewing Keys & regulatory access
| Method   | Path | Who |
|----------|------|-----|
| `POST`   | `/viewing-keys/v2/create`, `/derive` | address owner |
| `POST`   | `/viewing-keys/v2/decrypt` | address owner, or the authority whose approved request the key belongs to |
| `DELETE` | `/viewing-keys/v2/{key_id}/revoke` | address owner |
| `GET`    | `/viewing-keys/v2/{address}/audit` | owner, `compliance`, `admin` |
| `POST`   | `/regulatory/request-access` | role `authority` (requester identity taken from the account) |
| `POST`   | `/regulatory/requests/{id}/approve` · `/deny` · `/revoke` | owner of the address in the request |
| `GET`    | `/regulatory/requests/detail/{id}` | owner, requesting authority, `compliance`, `admin` |

### Accounts & roles
| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/auth/login` | Login (5 failures in 15 min → 429; `totp_code` when 2FA is on) |
| `POST` | `/auth/2fa/setup` · `/enable` · `/disable` | TOTP second factor (RFC 6238, anti-replay) |
| `POST` | `/auth/logout` | Revoke all of the user's tokens |
| `GET`  | `/auth/me` | Current identity and role |
| `POST` | `/admin/users/{id}/role` | Assign `user` / `compliance` / `authority` / `admin` (admin only) |

Every address-based endpoint checks that the address belongs to a wallet of the
authenticated user (linked with `/wallet/link`). Keys are generated and kept on the device;
`wallet_service.py` (scrypt + salt, 12+ character passwords) is for client-side tooling only.
Bootstrap the first admin with `python scripts/create_admin.py <username>`.

### Banking
| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/banking/deposit` | Deposit EUR → mint AEGIS-EUR tokens |
| `POST` | `/banking/withdraw` | Withdraw EUR (requires active 2FA + code). On-chain: the user escrows tokens with `AegisVault.requestWithdrawal`, signers can only burn that escrow after paying (`completeWithdrawal`), or refund; after 7 days the user can take them back |
| `GET`  | `/banking/statement` | Account statement |
| `POST` | `/banking/schedule-payment` | Schedule a one-time future payment |
| `POST` | `/banking/recurring-payment` | Set up recurring payment |
| `GET`  | `/banking/reserve-status` | On-chain reserve ratio (MiCA Art. 36) |

### Advanced
| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/settlement/submit-bundle` | Submit Merkle bundle for on-chain settlement (`compliance`/`admin`) |
| `GET`  | `/api/v1/oracle/eur-usd` | Chainlink EUR/USD price feed |
| `GET`  | `/api/v1/reporting/compliance-report` | MiCA compliance report (`compliance`/`authority`/`admin`) |
| `GET`  | `/api/v1/reporting/reserve-attestation` | On-chain reserve attestation |
| `POST` | `/api/v1/bridge/initiate` | Initiate cross-chain bridge transfer |
| `GET`  | `/api/v1/bridge/status/{request_id}` | Bridge transfer status |

### ProofMint — Digital Product Passport

ProofMint is a self-service module for creating ESPR-aligned Digital Product Passports (DPP), storing payloads on IPFS, and anchoring hashes on-chain (Polygon-compatible).

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/proofmint/brands/register` | Register a brand and issue API key |
| `POST` | `/proofmint/products` | Create a product under a brand |
| `POST` | `/proofmint/dpp/create` | Create DPP (hash + IPFS + on-chain registration) |
| `GET`  | `/proofmint/dpp/{dpp_id}` | Get DPP details |
| `GET`  | `/proofmint/verify/{product_id}` | Public verification endpoint |
| `GET`  | `/proofmint/verify/{product_id}/full` | Regulator-level full verification (viewing key required) |
| `GET`  | `/proofmint/verify/{product_id}/recycler` | Recycler-level materials/hazard/disassembly view (viewing key required) |
| `PUT`  | `/proofmint/dpp/{dpp_id}` | Update DPP (version bump) |
| `DELETE` | `/proofmint/dpp/{dpp_id}` | Revoke/deactivate DPP |
| `GET` | `/proofmint/brands/{brand_id}/products` | List brand products |
| `GET` | `/proofmint/brands/{brand_id}/stats` | Basic analytics (products/scans/compliance) |

Quick start:

```bash
# 1) Register brand
curl -X POST http://localhost:8000/proofmint/brands/register \\
  -H 'Content-Type: application/json' \\
  -d '{"name":"Luxe Atelier","email":"ops@luxe.example","plan":"pro"}'

# 2) Create product (use returned API key)
curl -X POST http://localhost:8000/proofmint/products \\
  -H 'Content-Type: application/json' -H 'X-API-Key: <API_KEY>' \\
  -d '{"product_id":"SKU-001","product_name":"Luxe Serum","category":"skincare"}'

# 3) Create DPP
curl -X POST http://localhost:8000/proofmint/dpp/create \\
  -H 'Content-Type: application/json' -H 'X-API-Key: <API_KEY>' \\
  -d '{"productId":"SKU-001","productName":"Luxe Serum","category":"skincare","materials":["glass"],"origin_country":"IT","certifications":["COSMOS"],"brand_name":"Luxe Atelier"}'

# 4) Verify publicly
curl http://localhost:8000/proofmint/verify/SKU-001

# 5) Verify as regulator (full)
curl http://localhost:8000/proofmint/verify/SKU-001/full \
  -H 'X-Viewing-Key-Scope: regulator'

# 6) Verify as recycler (materials/hazard/disassembly)
curl http://localhost:8000/proofmint/verify/SKU-001/recycler \
  -H 'X-Viewing-Key-Scope: recycler'
```

> Note: `X-Viewing-Key-Scope` is a test/simulation shortcut and requires `PROOFMINT_ALLOW_SCOPE_HEADER=true`.
> In production flows use a real `X-Viewing-Key` issued by the Viewing Keys V2 system.

```mermaid
flowchart LR
    B[Brand] -->|/proofmint/* API| P[ProofMint Router]
    P --> H[SHA-256 DPP Hash]
    P --> I[IPFS Storage]
    P --> C[ProofMintRegistry.sol]
    C --> V[Public Verify Endpoint]
```

#### Compliance

**ESPR coverage (8 areas):**

| Area | Key fields covered in HALA ProofMint |
|------|--------------------------------------|
| 1. Identity | `productId`, `productName`, `category`, `model_variant`, `product_image_url` |
| 2. Economic Operator | `brand_name`, `operator_type`, `operator_address`, `facility_id`, `eori_number` |
| 3. Hazardous Substances | `hazardous_substances`, `reach_compliant`, `rohs_compliant` |
| 4. Environmental | `carbon_footprint_kg`, `carbon_footprint_method`, `energy_consumption_kwh`, `water_consumption_liters` |
| 5. Durability & Repairability | `expected_lifetime_years`, `repair_score`, `spare_parts_available`, `warranty_duration_months`, `maintenance_instructions` |
| 6. Circularity | `recyclability_percent`, `recycled_content_percent`, `recycling_instructions`, `disassembly_instructions`, `reuse_potential` |
| 7. Conformity | `certifications`, `ce_marking`, `conformity_declaration_url`, `test_reports_urls` |
| 8. Customs/Trade | `hs_code`, `cn_code` |

**ProofMint access levels:**

| Access level | Endpoint | Data visibility |
|--------------|----------|-----------------|
| Public | `GET /proofmint/verify/{product_id}` | Public-safe product data only (no hazardous detail, no EORI/facility/operator address, no test reports) |
| Regulator | `GET /proofmint/verify/{product_id}/full` | Full DPP payload |
| Recycler | `GET /proofmint/verify/{product_id}/recycler` | Materials + hazardous + disassembly/circularity subset |

---

## Project Structure

```
aegis-protocol/
├── main_app.py                  # FastAPI app entry point (router wiring)
├── schemas.py                   # Pydantic request/response models
├── routers/                     # FastAPI APIRouter modules
│   ├── auth.py                  # /auth/register, /auth/login + JWT helpers
│   ├── wallet.py                # /wallet/*
│   ├── transactions.py          # /transactions/*
│   ├── compliance.py            # /compliance/*
│   ├── proof.py                 # /proof/*
│   ├── viewing_keys.py          # /viewing-keys/*
│   ├── banking.py               # /banking/*
│   ├── settlement.py            # /api/v1/settlement/*
│   ├── oracle.py                # /api/v1/oracle/*
│   ├── reporting.py             # /api/v1/reporting/*
│   └── bridge.py                # /api/v1/bridge/*
├── compliance_engine.py         # MiCA compliance rules + ZK proof stubs
├── transaction_processor.py     # Web3 / EURC ERC-20 transactions
├── crypto_primitives.py         # Pedersen, MiMC, Merkle, viewing keys
├── wallet_service.py            # HD wallet creation, import, QR codes
├── banking_operations.py        # Deposit, withdraw, statements, payments
├── noir_bridge.py               # Python → Noir proof system bridge
├── db.py / db_models.py         # SQLAlchemy ORM (PostgreSQL)
├── security.py                  # Auth: roles, address ownership, login lockout
├── migrations/                  # Alembic migrations (alembic upgrade head)
├── proofmint/                   # DPP SaaS module (router, models, AI, IPFS, GS1)
├── bundler/                     # Transaction bundler + Merkle tree
├── bridge/                      # Cross-chain bridge manager
├── settlement/                  # On-chain settlement service
├── oracle/                      # Chainlink price feed integration
├── reporting/                   # ESMA reporter + reserve attestation
├── viewing_keys/                # Extended viewing key lifecycle
├── contracts/                   # Solidity smart contracts
│   ├── AegisEUR.sol
│   ├── AegisVault.sol
│   ├── AegisBundleVerifier.sol
│   ├── NoirVerifier.sol         # adapter → real bb-generated UltraHonk verifier
│   ├── ShieldedPool.sol         # confidential pool for EURC/EURe (notes, nullifiers, disclosure)
│   ├── lib/Poseidon2.sol        # Poseidon2 BN254, identical to Noir/Barretenberg
│   └── ProofMintRegistry.sol
├── noir_circuits/               # Noir 1.0 workspace
│   ├── aegis_lib/               # shared primitives (Poseidon2, notes, Merkle, KYC credential, encryption)
│   ├── spend/                   # join-split 2→2 + KYC + graduated disclosure
│   ├── balance_proof/
│   ├── compliance_proof/
│   └── test/                    # end-to-end circuit tests (node --test)
├── sdk/aegis.mjs                # off-chain helpers on bb.js (tree, credentials, auditor decryption)
├── sdk/aegis-core.mjs           # same crypto in pure JS (browser/phone): Poseidon2, Grumpkin, t-of-n decryption
├── disclosure_ai/               # Claude extracts authority requests → deterministic policy engine
├── app/demo/                    # mobile web demo (wallet, on-chain view, graduated disclosure)
├── tests/                       # pytest test suite
├── docker-compose.yml
├── Dockerfile
└── requirements.txt
```

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| **Backend** | FastAPI + SQLAlchemy + PostgreSQL |
| **Smart Contracts** | Solidity 0.8.20 + Hardhat |
| **ZK Proofs** | Noir circuits + Python bridge |
| **Blockchain** | Web3.py + eth-account (Polygon Amoy) |
| **Auth** | JWT (python-jose) + bcrypt (passlib) |
| **Privacy** | Poseidon2 note commitments + nullifiers + graduated (L0–L4) verifiable disclosure |
| **Oracle** | Chainlink EUR/USD price feed |

---

## MiCA Compliance

| Requirement | Implementation |
|-------------|---------------|
| 1:1 EUR reserve backing | `AegisVault.sol` + `/banking/reserve-status` |
| KYC for transfers > 1 000 EUR | `ComplianceEngine.check_transaction()` |
| ZK proof for every pool transaction | `noir_circuits/spend`, proven client-side, verified on-chain |
| Account freeze / unfreeze | `AegisEUR.freeze()` (REGULATOR_ROLE) |
| Transaction velocity limits | In-memory velocity tracker (5 tx/min) |
| ESMA reporting | `/api/v1/reporting/compliance-report` |
| Selective disclosure (auditors) | Zcash-style viewing keys |
| On-chain reserve attestation | `AegisVault.attestReserve()` by an independent attestor (optionally caps minting) |
| Multi-sig mint/burn | `AegisVault`: N distinct signer approvals per operation, no replay of bank refs |

---

## ZK Circuits (Noir)

| Circuit | Proves |
|---------|--------|
| `spend` | Shielded join-split (deposit / private transfer / withdrawal): note ownership via Merkle membership, nullifiers, value conservation, issuer-signed KYC credential (expiry, jurisdiction, tier limit) and verifiable encryption of a TAX (L2) and AML (L3) disclosure payload to threshold auditor keys |
| `balance_proof` | Balance ≥ threshold for a binding Poseidon2 commitment |
| `compliance_proof` | Valid KYC credential with tier ≥ min, without revealing identity (scoped nullifier) |

All hashes are Poseidon2 (same sponge as Barretenberg), signatures ECDSA-secp256k1,
encryption ECDH on Grumpkin. See [docs/DISCLOSURE_GRADUATA.md](docs/DISCLOSURE_GRADUATA.md).

```bash
npm run test:circuits      # executes the circuits with valid and malicious witnesses
npm run build:circuits     # ACIR + VK + Solidity UltraHonk verifiers (needs internet for the CRS)
npx hardhat test           # contracts, including ShieldedPool ↔ SDK tree consistency
```

Mobile demo: `npm run app` and open http://localhost:8080 on the phone (same Wi-Fi: use the
computer's IP). The page runs the real SDK crypto; the chain and the ZK proof are simulated in-page.

Mock proofs are accepted by the Python backend only with `AEGIS_ALLOW_MOCK_PROOFS=1`
(set automatically in the test suite). `NoirVerifier` dev mode only works on the local chain.

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | `postgresql://aegis:aegis@localhost:5432/aegis_db` | PostgreSQL connection URL |
| `SECRET_KEY` | `change-me` | JWT signing secret |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `60` | JWT token lifetime |
| `CORS_ORIGINS` | `http://localhost:3000` | Comma-separated allowed origins |
| `RPC_URL` | — | Blockchain RPC endpoint |
| `CHAIN_ID` | `80002` | Polygon Amoy |
| `EURC_TOKEN_ADDRESS` | — | AEGIS-EUR contract address |
| `AEGIS_CONTRACT_ADDRESS` | — | AegisSmartAccount address |

---

## Contributing

1. Fork the repository and create a feature branch.
2. Install dev dependencies: `pip install -r requirements-dev.txt`
3. Run tests before and after your changes: `pytest tests/ -v`
4. Open a pull request with a clear description of the change.

Good first issues are labelled `good-first-issue`. Feel free to open an issue to discuss larger changes before starting work.

---

## License

MIT — see [LICENSE](LICENSE)
