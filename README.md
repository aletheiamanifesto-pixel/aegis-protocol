# AEGIS Protocol

**A math-based decentralized bank** with blockchain, EUR token, wallet, and payment system.

AEGIS Protocol implements MiCA-compliant EUR tokenization using zero-knowledge proofs (Noir), ERC-4337 smart accounts, and a privacy-preserving compliance engine.

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    FastAPI REST API                      │
│  auth / wallet / transactions / compliance / banking     │
└─────────────┬───────────────────────────┬───────────────┘
              │                           │
    ┌─────────▼──────────┐    ┌───────────▼──────────────┐
    │  Compliance Engine  │    │   Transaction Processor   │
    │  (MiCA rules, ZK)  │    │   (Web3 / EURC ERC-20)   │
    └─────────────────────┘    └──────────────────────────┘
              │                           │
    ┌─────────▼──────────┐    ┌───────────▼──────────────┐
    │  Crypto Primitives  │    │     Smart Contracts       │
    │  Pedersen/MiMC/     │    │  AegisSmartAccount (4337) │
    │  Merkle/ViewingKeys │    │  AegisEUR (ERC-20)        │
    └─────────────────────┘    │  AegisVault (Reserve)     │
                               │  NoirVerifier (ZK)        │
                               └──────────────────────────┘
```

### Key Components

| File | Description |
|------|-------------|
| `main_app.py` | FastAPI application with all REST endpoints |
| `compliance_engine.py` | MiCA compliance rules, ZK proof generation |
| `transaction_processor.py` | Web3 EURC transactions (Polygon Amoy) |
| `crypto_primitives.py` | Pedersen commitments, MiMC hash, Merkle tree |
| `viewing_keys_service.py` | Selective disclosure of wallet data |
| `wallet_service.py` | Wallet creation, import, QR codes |
| `banking_operations.py` | Deposit, withdraw, statements, scheduled payments |
| `noir_bridge.py` | Python → Noir proof system bridge |
| `db.py` / `db_models.py` | SQLAlchemy ORM (PostgreSQL) |
| `models.py` | Pydantic schemas |
| `contracts/AegisEUR.sol` | EUR-pegged ERC-20 with ZK proof support |
| `contracts/AegisVault.sol` | Reserve vault with 1:1 backing proof |
| `contracts/NoirVerifier.sol` | UltraPlonk proof verifier (stub) |
| `AegisSmartAccount.sol` | ERC-4337 smart account with guardian recovery |
| `noir_circuits/` | Noir ZK circuits: balance, transfer, compliance |

---

## Quickstart

### Prerequisites

- Docker & Docker Compose
- Python 3.12+
- (Optional) Nargo CLI for real ZK proofs

### 1. Clone and configure

```bash
git clone https://github.com/your-org/aegis-protocol
cd aegis-protocol
cp .env.example .env
# Edit .env with your RPC URL and keys
```

### 2. Start with Docker Compose

```bash
docker compose up --build
```

API available at: **http://localhost:8000**

Swagger docs: **http://localhost:8000/docs**

### 3. Run locally (dev mode)

```bash
pip install -r requirements.txt
uvicorn main_app:app --reload
```

---

## API Reference

### Authentication

```http
POST /auth/register
Content-Type: application/json

{"username": "alice", "email": "alice@example.com", "password": "secret"}
```

```http
POST /auth/login
Content-Type: application/json

{"username": "alice", "password": "secret"}
```

### Wallet

```http
POST /wallet/create          # Create new wallet
POST /wallet/import          # Import from mnemonic or private key
GET  /wallet/balance/{addr}  # Get AEGIS EUR balance
GET  /wallet/transactions/{addr}
GET  /wallet/qr/{addr}       # QR code PNG for receiving
```

### Transactions

```http
POST /transactions/send
GET  /transactions/{tx_hash}/status
```

### Compliance (MiCA)

```http
POST /compliance/kyc                # Submit KYC data
GET  /compliance/profile            # Get compliance profile
POST /compliance/proof/generate     # Generate ZK proof stub
```

### Viewing Keys (Selective Disclosure)

```http
POST   /viewing-keys/create          # Create self-grant key
POST   /viewing-keys/grant           # Grant to third party
POST   /viewing-keys/{id}/redeem     # Redeem key
DELETE /viewing-keys/{id}/revoke     # Revoke key
GET    /viewing-keys/{owner}/active  # List active keys
```

### Banking

```http
POST /banking/deposit           # Deposit EUR → mint AEGIS EUR
POST /banking/withdraw          # Burn AEGIS EUR → EUR via IBAN
GET  /banking/statement         # Account statement
POST /banking/schedule-payment  # One-time future payment
POST /banking/recurring-payment # Recurring payment setup
GET  /banking/reserve-status    # Reserve ratio (MiCA Article 36)
```

### ZK Proofs

```http
POST /proof/generate   # Generate ZK proof
POST /proof/verify     # Verify ZK proof hash
```

---

## MiCA Compliance

| Rule | Implementation |
|------|---------------|
| 1:1 EUR backing | `AegisVault.sol` + `get_reserve_status()` |
| KYC for > 1000 EUR | `ComplianceEngine.check_transaction()` |
| ZK proof for large transfers | `compliance/proof/generate` + Noir circuits |
| Account freeze/unfreeze | `AegisEUR.freeze()` (REGULATOR_ROLE) |
| Transaction velocity limit | In-memory velocity tracker (5 tx/min) |
| Audit trail | `AuditLog` DB model + `audit_logs` |

---

## Smart Contracts

Deployed on **Polygon Amoy** testnet (Chain ID: 80002).

| Contract | Description |
|----------|-------------|
| `AegisSmartAccount` | ERC-4337 account with guardian recovery |
| `AegisEUR` | EUR-pegged ERC-20 (6 decimals) |
| `AegisVault` | Multi-sig reserve vault |
| `NoirVerifier` | ZK proof verifier (stub → replace with nargo codegen-verifier) |

---

## ZK Circuits (Noir)

| Circuit | Proves |
|---------|--------|
| `balance_proof` | Balance ≥ threshold (without revealing balance) |
| `transfer_proof` | Valid transfer with sufficient funds |
| `compliance_proof` | KYC verified without revealing identity |

Run with Nargo:
```bash
cd noir_circuits/balance_proof
nargo compile
nargo prove
nargo verify
```

---

## Development

### Run tests

```bash
pytest tests/ -v
```

### Run with coverage

```bash
pytest tests/ --cov=. --cov-report=term-missing
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | `postgresql://aegis:aegis@localhost:5432/aegis_db` | PostgreSQL URL |
| `SECRET_KEY` | `change-me` | JWT signing key |
| `RPC_URL` | Polygon Amoy | Blockchain RPC endpoint |
| `EURC_TOKEN_ADDRESS` | - | AEGIS EUR contract address |
| `AEGIS_CONTRACT_ADDRESS` | - | AegisSmartAccount address |
| `CHAIN_ID` | `80002` | Polygon Amoy |

---

## License

MIT License - see [LICENSE](LICENSE)
