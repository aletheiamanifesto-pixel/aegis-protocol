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

Deployed on **Polygon Amoy** testnet (Chain ID: 80002).

| Contract | Description |
|----------|-------------|
| `AegisEUR.sol` | ERC-20 EUR stablecoin with ZK proof transfers, Pedersen commitments, MiCA freeze/unfreeze |
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
| `POST` | `/wallet/create` | Create a new HD wallet |
| `POST` | `/wallet/import` | Import from mnemonic or private key |
| `GET`  | `/wallet/balance/{address}` | Get AEGIS-EUR balance |
| `GET`  | `/wallet/transactions/{address}` | List wallet transactions |
| `GET`  | `/wallet/qr/{address}` | QR code PNG for receiving |

### Transactions
| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/transactions/send` | Send AEGIS-EUR (compliance-checked) |
| `GET`  | `/transactions/{tx_hash}/status` | Transaction status |

### Compliance (MiCA)
| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/compliance/kyc` | Submit KYC data |
| `GET`  | `/compliance/profile` | Get compliance profile |
| `POST` | `/compliance/proof/generate` | Generate ZK proof stub |

### ZK Proofs
| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/proof/generate` | Generate ZK proof |
| `POST` | `/proof/verify` | Verify ZK proof hash |

### Viewing Keys (Selective Disclosure)
| Method   | Path | Description |
|----------|------|-------------|
| `POST`   | `/viewing-keys/create` | Create self-grant viewing key |
| `POST`   | `/viewing-keys/grant` | Grant access to third party |
| `POST`   | `/viewing-keys/{id}/redeem` | Redeem a viewing key |
| `DELETE` | `/viewing-keys/{id}/revoke` | Revoke a viewing key |
| `GET`    | `/viewing-keys/{owner}/active` | List active keys |

### Banking
| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/banking/deposit` | Deposit EUR → mint AEGIS-EUR tokens |
| `POST` | `/banking/withdraw` | Burn tokens → withdraw EUR via IBAN |
| `GET`  | `/banking/statement` | Account statement |
| `POST` | `/banking/schedule-payment` | Schedule a one-time future payment |
| `POST` | `/banking/recurring-payment` | Set up recurring payment |
| `GET`  | `/banking/reserve-status` | On-chain reserve ratio (MiCA Art. 36) |

### Advanced
| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/settlement/submit-bundle` | Submit Merkle bundle for on-chain settlement |
| `GET`  | `/api/v1/oracle/eur-usd` | Chainlink EUR/USD price feed |
| `GET`  | `/api/v1/reporting/compliance-report` | MiCA compliance report |
| `GET`  | `/api/v1/reporting/reserve-attestation` | On-chain reserve attestation |
| `POST` | `/api/v1/bridge/initiate` | Initiate cross-chain bridge transfer |
| `GET`  | `/api/v1/bridge/status/{request_id}` | Bridge transfer status |

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
├── viewing_keys_service.py      # Selective disclosure (Zcash-style)
├── noir_bridge.py               # Python → Noir proof system bridge
├── db.py / db_models.py         # SQLAlchemy ORM (PostgreSQL)
├── models.py                    # Domain models (ScopeType, etc.)
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
│   └── NoirVerifier.sol
├── noir_circuits/               # Noir ZK circuits
│   ├── balance_proof/
│   ├── transfer_proof/
│   └── compliance_proof/
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
| **Privacy** | Pedersen commitments + viewing keys + regulatory escrow |
| **Oracle** | Chainlink EUR/USD price feed |

---

## MiCA Compliance

| Requirement | Implementation |
|-------------|---------------|
| 1:1 EUR reserve backing | `AegisVault.sol` + `/banking/reserve-status` |
| KYC for transfers > 1 000 EUR | `ComplianceEngine.check_transaction()` |
| ZK proof for large transfers | Noir circuits + `/compliance/proof/generate` |
| Account freeze / unfreeze | `AegisEUR.freeze()` (REGULATOR_ROLE) |
| Transaction velocity limits | In-memory velocity tracker (5 tx/min) |
| ESMA reporting | `/api/v1/reporting/compliance-report` |
| Selective disclosure (auditors) | Zcash-style viewing keys |
| On-chain reserve attestation | `AegisVault.proveReserve()` + `/api/v1/reporting/reserve-attestation` |

---

## ZK Circuits (Noir)

| Circuit | Proves |
|---------|--------|
| `balance_proof` | Balance ≥ threshold without revealing exact balance |
| `transfer_proof` | Valid transfer with sufficient funds |
| `compliance_proof` | KYC verified without revealing identity |

```bash
cd noir_circuits/balance_proof
nargo compile
nargo prove
nargo verify
```

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
