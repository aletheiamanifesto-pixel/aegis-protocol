#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
main_app.py - FastAPI application for AEGIS Protocol
"""

import hashlib
import os
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY", "change-me-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))
CORS_ORIGINS = os.getenv("CORS_ORIGINS", "http://localhost:3000").split(",")

# Optional service imports with graceful fallback
try:
    from viewing_keys_service import (
        create_viewing_key,
        grant_access,
        redeem_viewing_key,
        revoke_viewing_key,
        get_active_keys,
        ViewingKeyError,
    )
    _vk_available = True
except ImportError:
    _vk_available = False

try:
    from wallet_service import (
        create_wallet as _create_wallet,
        import_wallet as _import_wallet,
        get_balance as _get_balance,
        generate_receive_qr,
        WalletError,
    )
    _ws_available = True
except ImportError:
    _ws_available = False

try:
    from banking_operations import (
        deposit_eur,
        withdraw_eur,
        get_account_statement,
        schedule_payment,
        recurring_payment,
        get_reserve_status,
        BankingError,
    )
    _bo_available = True
except ImportError:
    _bo_available = False

try:
    from compliance_engine import ComplianceEngine
    _ce_available = True
except ImportError:
    _ce_available = False

try:
    from transaction_processor import TransactionProcessor
    _tp_available = True
except ImportError:
    _tp_available = False

try:
    from db import get_db, init_db
    import db_models
    _db_available = True
except ImportError:
    _db_available = False

    def get_db():
        yield None

try:
    from settlement import OnChainSettler, SettlementConfig, SettlementResult
    _settlement_available = True
except ImportError:
    _settlement_available = False

try:
    from oracle import ChainlinkPriceFeed, OracleConfig
    _oracle_available = True
except ImportError:
    _oracle_available = False

try:
    from reporting import ESMAReporter, ReserveAttestor
    _reporting_available = True
except ImportError:
    _reporting_available = False

try:
    from bridge import BridgeManager, BridgeRequest, BridgeConfig, BridgeError
    _bridge_available = True
except ImportError:
    _bridge_available = False

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

app = FastAPI(
    title="AEGIS Protocol API",
    description="Math-based decentralized bank with EUR token, wallet and payment system",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


@app.on_event("startup")
def startup():
    if _db_available:
        try:
            init_db()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------

def _hash_password(password: str) -> str:
    return pwd_context.hash(password)


def _verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def _create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode["exp"] = expire
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def _get_current_user(request: Request, db: Session = Depends(get_db)) -> Dict:
    token = request.headers.get("Authorization", "").removeprefix("Bearer ").strip()
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid token")
        return {"user_id": user_id, "username": payload.get("username", "")}
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


# ---------------------------------------------------------------------------
# Request / Response schemas
# ---------------------------------------------------------------------------

class RegisterRequest(BaseModel):
    username: str
    email: str
    password: str


class LoginRequest(BaseModel):
    username: str
    password: str


class WalletCreateRequest(BaseModel):
    password: str


class WalletImportRequest(BaseModel):
    mnemonic_or_private_key: str
    password: str


class SendTransactionRequest(BaseModel):
    from_address: str
    to_address: str
    amount: float
    encrypted_key: str
    password: str
    proof_hash: Optional[str] = None


class KYCRequest(BaseModel):
    full_name: str
    date_of_birth: str
    country: str
    id_document_hash: str


class ProofGenerateRequest(BaseModel):
    sender: str
    amount: float
    purpose: str = "transfer"


class ProofVerifyRequest(BaseModel):
    proof_hash: str
    sender: str
    amount: float


class ViewingKeyCreateRequest(BaseModel):
    owner_address: str
    scope: str = "balance_only"
    duration_days: int = 30


class ViewingKeyGrantRequest(BaseModel):
    owner_address: str
    grantee: str
    scope: str = "balance_only"
    duration_days: int = 30


class ViewingKeyRedeemRequest(BaseModel):
    grantee: str


class DepositRequest(BaseModel):
    amount: float
    wallet_address: str


class WithdrawRequest(BaseModel):
    amount: float
    wallet_address: str
    iban: str


class SchedulePaymentRequest(BaseModel):
    from_address: str
    to_address: str
    amount: float
    scheduled_at: datetime


class RecurringPaymentRequest(BaseModel):
    from_address: str
    to_address: str
    amount: float
    frequency: str
    start_date: Optional[datetime] = None


class SubmitBundleRequest(BaseModel):
    bundle_id: str
    merkle_root: str
    tx_count: int = 0


class ComplianceReportRequest(BaseModel):
    period_start: datetime
    period_end: datetime


class BridgeInitiateRequest(BaseModel):
    source_chain: str
    dest_chain: str
    token_address: str
    amount: float
    recipient: str
    sender: str


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

@app.get("/health")
def health():
    return {
        "status": "ok",
        "version": "0.1.0",
        "services": {
            "database": _db_available,
            "compliance_engine": _ce_available,
            "transaction_processor": _tp_available,
            "wallet_service": _ws_available,
            "banking_operations": _bo_available,
            "viewing_keys": _vk_available,
            "settlement": _settlement_available,
            "oracle": _oracle_available,
            "reporting": _reporting_available,
            "bridge": _bridge_available,
        },
    }


# ---------------------------------------------------------------------------
# Auth endpoints
# ---------------------------------------------------------------------------

@app.post("/auth/register", status_code=201)
def register(req: RegisterRequest, db: Session = Depends(get_db)):
    if not _db_available or db is None:
        # Minimal in-memory response for dev mode
        return {"message": "User registered (dev mode)", "username": req.username}

    existing = db.query(db_models.User).filter(
        (db_models.User.username == req.username) | (db_models.User.email == req.email)
    ).first()
    if existing:
        raise HTTPException(status_code=400, detail="Username or email already registered")

    user = db_models.User(
        username=req.username,
        email=req.email,
        hashed_password=_hash_password(req.password),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return {"message": "User registered successfully", "user_id": user.id, "username": user.username}


@app.post("/auth/login")
def login(req: LoginRequest, db: Session = Depends(get_db)):
    if not _db_available or db is None:
        token = _create_access_token({"sub": req.username, "username": req.username})
        return {"access_token": token, "token_type": "bearer"}

    user = db.query(db_models.User).filter(db_models.User.username == req.username).first()
    if not user or not _verify_password(req.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = _create_access_token({"sub": str(user.id), "username": user.username})
    return {"access_token": token, "token_type": "bearer"}


# ---------------------------------------------------------------------------
# Wallet endpoints
# ---------------------------------------------------------------------------

@app.post("/wallet/create")
def wallet_create(req: WalletCreateRequest, current_user: Dict = Depends(_get_current_user)):
    if not _ws_available:
        raise HTTPException(status_code=503, detail="Wallet service not available")
    result = _create_wallet(req.password)
    return result


@app.post("/wallet/import")
def wallet_import(req: WalletImportRequest, current_user: Dict = Depends(_get_current_user)):
    if not _ws_available:
        raise HTTPException(status_code=503, detail="Wallet service not available")
    result = _import_wallet(req.mnemonic_or_private_key, req.password)
    return result


@app.get("/wallet/balance/{address}")
def wallet_balance(address: str, current_user: Dict = Depends(_get_current_user)):
    if not _ws_available:
        raise HTTPException(status_code=503, detail="Wallet service not available")
    balance = _get_balance(address)
    return {"address": address, "balance": balance, "currency": "AEGIS-EUR"}


@app.get("/wallet/transactions/{address}")
def wallet_transactions(address: str, limit: int = 50, current_user: Dict = Depends(_get_current_user), db: Session = Depends(get_db)):
    if not _db_available or db is None:
        return {"address": address, "transactions": []}
    txns = (
        db.query(db_models.Transaction)
        .filter(db_models.Transaction.sender_address == address)
        .limit(limit)
        .all()
    )
    return {
        "address": address,
        "transactions": [
            {
                "tx_hash": t.tx_hash,
                "amount": t.amount,
                "recipient": t.recipient_address,
                "status": t.status,
                "created_at": t.created_at.isoformat(),
            }
            for t in txns
        ],
    }


@app.get("/wallet/qr/{address}")
def wallet_qr(address: str, current_user: Dict = Depends(_get_current_user)):
    if not _ws_available:
        raise HTTPException(status_code=503, detail="Wallet service not available")
    png_bytes = generate_receive_qr(address)
    return Response(content=png_bytes, media_type="image/png")


# ---------------------------------------------------------------------------
# Transaction endpoints
# ---------------------------------------------------------------------------

@app.post("/transactions/send")
def transactions_send(req: SendTransactionRequest, current_user: Dict = Depends(_get_current_user), db: Session = Depends(get_db)):
    if not _tp_available:
        raise HTTPException(status_code=503, detail="Transaction processor not available")

    if _ce_available:
        engine = ComplianceEngine()
        kyc_verified = False
        daily_limit = 10000.0
        single_tx_limit = 5000.0
        if _db_available and db is not None:
            profile = db.query(db_models.ComplianceProfile).filter(
                db_models.ComplianceProfile.user_id == int(current_user["user_id"])
            ).first()
            if profile:
                kyc_verified = profile.kyc_verified
                daily_limit = profile.daily_limit
                single_tx_limit = profile.single_tx_limit
        result = engine.check_transaction(
            req.from_address, req.amount,
            kyc_verified=kyc_verified,
            daily_limit=daily_limit,
            single_tx_limit=single_tx_limit,
        )
        if not result.approved:
            raise HTTPException(status_code=400, detail=result.message)

    tp = TransactionProcessor()
    tx_result = tp.send_eurc(req.encrypted_key, req.to_address, req.amount, req.proof_hash)

    if _db_available and db is not None:
        txn = db_models.Transaction(
            tx_hash=tx_result.get("tx_hash", ""),
            sender_address=req.from_address,
            recipient_address=req.to_address,
            amount=req.amount,
            status=tx_result.get("status", "pending"),
            proof_hash=req.proof_hash,
        )
        db.add(txn)
        db.commit()

    return tx_result


@app.get("/transactions/{tx_hash}/status")
def transaction_status(tx_hash: str, current_user: Dict = Depends(_get_current_user)):
    if not _tp_available:
        raise HTTPException(status_code=503, detail="Transaction processor not available")
    tp = TransactionProcessor()
    return tp.get_transaction_status(tx_hash)


# ---------------------------------------------------------------------------
# Compliance endpoints
# ---------------------------------------------------------------------------

@app.post("/compliance/kyc")
def compliance_kyc(req: KYCRequest, current_user: Dict = Depends(_get_current_user), db: Session = Depends(get_db)):
    user_id = current_user["user_id"]

    if _db_available and db is not None:
        profile = db.query(db_models.ComplianceProfile).filter(
            db_models.ComplianceProfile.user_id == int(user_id)
        ).first()
        if not profile:
            profile = db_models.ComplianceProfile(user_id=int(user_id))
            db.add(profile)

        profile.kyc_verified = True
        profile.last_kyc_at = datetime.utcnow()
        db.commit()

    return {
        "user_id": user_id,
        "kyc_verified": True,
        "verified_at": datetime.utcnow().isoformat(),
        "message": "KYC verification completed",
    }


@app.get("/compliance/profile")
def compliance_profile(current_user: Dict = Depends(_get_current_user), db: Session = Depends(get_db)):
    user_id = current_user["user_id"]

    if _db_available and db is not None:
        profile = db.query(db_models.ComplianceProfile).filter(
            db_models.ComplianceProfile.user_id == int(user_id)
        ).first()
        if profile:
            return {
                "user_id": user_id,
                "kyc_verified": profile.kyc_verified,
                "aml_screened": profile.aml_screened,
                "daily_limit": profile.daily_limit,
                "single_tx_limit": profile.single_tx_limit,
                "risk_level": profile.risk_level,
            }

    return {
        "user_id": user_id,
        "kyc_verified": False,
        "aml_screened": False,
        "daily_limit": 10000.0,
        "single_tx_limit": 5000.0,
        "risk_level": "low",
    }


@app.post("/compliance/proof/generate")
def compliance_proof_generate(req: ProofGenerateRequest, current_user: Dict = Depends(_get_current_user)):
    if not _ce_available:
        raise HTTPException(status_code=503, detail="Compliance engine not available")
    engine = ComplianceEngine()
    proof = engine.generate_zk_proof_stub(req.sender, req.amount, req.purpose)
    return {
        "proof_hash": proof.proof_hash,
        "public_inputs": proof.public_inputs,
        "valid_until": proof.valid_until,
        "generated_at": proof.generated_at,
    }


# ---------------------------------------------------------------------------
# Proof endpoints
# ---------------------------------------------------------------------------

@app.post("/proof/generate")
def proof_generate(req: ProofGenerateRequest, current_user: Dict = Depends(_get_current_user)):
    if not _ce_available:
        raise HTTPException(status_code=503, detail="Compliance engine not available")
    engine = ComplianceEngine()
    proof = engine.generate_zk_proof_stub(req.sender, req.amount, req.purpose)
    return {
        "proof_hash": proof.proof_hash,
        "public_inputs": proof.public_inputs,
        "valid_until": proof.valid_until,
        "generated_at": proof.generated_at,
    }


@app.post("/proof/verify")
def proof_verify(req: ProofVerifyRequest, current_user: Dict = Depends(_get_current_user)):
    # Stub verification: check proof_hash format
    is_valid = req.proof_hash.startswith("0x") and len(req.proof_hash) == 66
    return {
        "proof_hash": req.proof_hash,
        "valid": is_valid,
        "verified_at": datetime.utcnow().isoformat(),
    }


# ---------------------------------------------------------------------------
# Viewing keys endpoints
# ---------------------------------------------------------------------------

@app.post("/viewing-keys/create")
def viewing_keys_create(req: ViewingKeyCreateRequest, current_user: Dict = Depends(_get_current_user)):
    if not _vk_available:
        raise HTTPException(status_code=503, detail="Viewing keys service not available")
    from models import ScopeType
    try:
        scope = ScopeType(req.scope)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid scope: {req.scope}")
    perm = create_viewing_key(req.owner_address, scope, req.duration_days)
    return perm.dict()


@app.post("/viewing-keys/grant")
def viewing_keys_grant(req: ViewingKeyGrantRequest, current_user: Dict = Depends(_get_current_user)):
    if not _vk_available:
        raise HTTPException(status_code=503, detail="Viewing keys service not available")
    from models import ScopeType
    try:
        scope = ScopeType(req.scope)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid scope: {req.scope}")
    perm = grant_access(req.owner_address, req.grantee, scope, req.duration_days)
    return perm.dict()


@app.post("/viewing-keys/{key_id}/redeem")
def viewing_keys_redeem(key_id: str, req: ViewingKeyRedeemRequest, request: Request, current_user: Dict = Depends(_get_current_user)):
    if not _vk_available:
        raise HTTPException(status_code=503, detail="Viewing keys service not available")
    try:
        ip = request.client.host if request.client else None
        result = redeem_viewing_key(key_id, req.grantee, ip)
        return result
    except ViewingKeyError as e:
        raise HTTPException(status_code=403, detail=str(e))


@app.delete("/viewing-keys/{key_id}/revoke")
def viewing_keys_revoke(key_id: str, current_user: Dict = Depends(_get_current_user)):
    if not _vk_available:
        raise HTTPException(status_code=503, detail="Viewing keys service not available")
    try:
        revoke_viewing_key(key_id, revoker=current_user["user_id"])
        return {"message": "Viewing key revoked", "key_id": key_id}
    except ViewingKeyError as e:
        raise HTTPException(status_code=404, detail=str(e))


@app.get("/viewing-keys/{owner}/active")
def viewing_keys_active(owner: str, current_user: Dict = Depends(_get_current_user)):
    if not _vk_available:
        raise HTTPException(status_code=503, detail="Viewing keys service not available")
    keys = get_active_keys(owner)
    return {"owner": owner, "active_keys": [k.dict() for k in keys]}


# ---------------------------------------------------------------------------
# Banking endpoints
# ---------------------------------------------------------------------------

@app.post("/banking/deposit")
def banking_deposit(req: DepositRequest, current_user: Dict = Depends(_get_current_user)):
    if not _bo_available:
        raise HTTPException(status_code=503, detail="Banking operations not available")
    try:
        result = deposit_eur(current_user["user_id"], req.amount, req.wallet_address)
        return result
    except BankingError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/banking/withdraw")
def banking_withdraw(req: WithdrawRequest, current_user: Dict = Depends(_get_current_user)):
    if not _bo_available:
        raise HTTPException(status_code=503, detail="Banking operations not available")
    try:
        result = withdraw_eur(current_user["user_id"], req.amount, req.wallet_address, req.iban)
        return result
    except BankingError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/banking/statement")
def banking_statement(
    from_date: Optional[str] = None,
    to_date: Optional[str] = None,
    current_user: Dict = Depends(_get_current_user),
    db: Session = Depends(get_db),
):
    if not _bo_available:
        raise HTTPException(status_code=503, detail="Banking operations not available")

    now = datetime.utcnow()
    fd = datetime.fromisoformat(from_date) if from_date else now - timedelta(days=30)
    td = datetime.fromisoformat(to_date) if to_date else now

    try:
        result = get_account_statement(current_user["user_id"], fd, td)
        return result
    except BankingError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/banking/schedule-payment")
def banking_schedule_payment(req: SchedulePaymentRequest, current_user: Dict = Depends(_get_current_user)):
    if not _bo_available:
        raise HTTPException(status_code=503, detail="Banking operations not available")
    try:
        result = schedule_payment(
            current_user["user_id"], req.from_address, req.to_address, req.amount, req.scheduled_at
        )
        return result
    except BankingError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/banking/recurring-payment")
def banking_recurring_payment(req: RecurringPaymentRequest, current_user: Dict = Depends(_get_current_user)):
    if not _bo_available:
        raise HTTPException(status_code=503, detail="Banking operations not available")
    try:
        result = recurring_payment(
            current_user["user_id"],
            req.from_address,
            req.to_address,
            req.amount,
            req.frequency,
            req.start_date,
        )
        return result
    except BankingError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/banking/reserve-status")
def banking_reserve_status():
    if not _bo_available:
        raise HTTPException(status_code=503, detail="Banking operations not available")
    return get_reserve_status()


# ---------------------------------------------------------------------------
# Settlement endpoints
# ---------------------------------------------------------------------------

@app.post("/api/v1/settlement/submit-bundle")
def settlement_submit_bundle(req: SubmitBundleRequest, current_user: Dict = Depends(_get_current_user)):
    """Trigger on-chain settlement for a bundle identified by its Merkle root."""
    if not _settlement_available:
        raise HTTPException(status_code=503, detail="Settlement service not available")

    # Build a minimal bundle-like object from the request fields using a dataclass
    # to avoid class-level attribute sharing under concurrent requests.
    from dataclasses import make_dataclass

    _BundleProxy = make_dataclass(
        "_BundleProxy",
        [("bundle_id", str), ("merkle_root", str), ("transactions", list)],
    )
    proxy = _BundleProxy(
        bundle_id=req.bundle_id,
        merkle_root=req.merkle_root,
        transactions=[{}] * req.tx_count,
    )

    settler = OnChainSettler()
    result = settler.settle(proxy)
    return {
        "bundle_id": result.bundle_id,
        "tx_hash": result.tx_hash,
        "block_number": result.block_number,
        "gas_used": result.gas_used,
        "status": result.status,
        "error": result.error,
    }


# ---------------------------------------------------------------------------
# Oracle endpoints
# ---------------------------------------------------------------------------

@app.get("/api/v1/oracle/eur-usd")
def oracle_eur_usd(current_user: Dict = Depends(_get_current_user)):
    """Get the current EUR/USD price from the Chainlink price feed."""
    if not _oracle_available:
        raise HTTPException(status_code=503, detail="Oracle service not available")
    feed = ChainlinkPriceFeed()
    data = feed.get_eur_usd_price()
    return {
        "price": data.price,
        "decimals": data.decimals,
        "updated_at": data.updated_at,
        "round_id": data.round_id,
        "is_stale": data.is_stale,
    }


# ---------------------------------------------------------------------------
# Reporting endpoints
# ---------------------------------------------------------------------------

@app.get("/api/v1/reporting/compliance-report")
def reporting_compliance_report(
    period_start: Optional[str] = None,
    period_end: Optional[str] = None,
    current_user: Dict = Depends(_get_current_user),
):
    """Generate a MiCA compliance report for the given time period."""
    if not _reporting_available:
        raise HTTPException(status_code=503, detail="Reporting service not available")

    now = datetime.utcnow()
    try:
        start = datetime.fromisoformat(period_start) if period_start else now - timedelta(days=30)
        end = datetime.fromisoformat(period_end) if period_end else now
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid date format: {exc}")

    reporter = ESMAReporter()
    report = reporter.generate_report(start, end)
    return {
        "report_id": report.report_id,
        "period_start": report.period_start,
        "period_end": report.period_end,
        "generated_at": report.generated_at,
        "total_transactions": report.total_transactions,
        "total_volume_eur": report.total_volume_eur,
        "reserve_ratio": report.reserve_ratio,
        "zk_proofs_generated": report.zk_proofs_generated,
        "velocity_limit_breaches": report.velocity_limit_breaches,
        "compliance_rejections": report.compliance_rejections,
        "report_hash": report.report_hash,
    }


@app.get("/api/v1/reporting/reserve-attestation")
def reporting_reserve_attestation(current_user: Dict = Depends(_get_current_user)):
    """Get the current on-chain reserve attestation."""
    if not _reporting_available:
        raise HTTPException(status_code=503, detail="Reporting service not available")

    attestor = ReserveAttestor()
    attestation = attestor.attest()
    return {
        "ratio": attestation.ratio,
        "is_fully_backed": attestation.is_fully_backed,
        "on_chain_data": attestation.on_chain_data,
        "timestamp": attestation.timestamp,
        "attestation_hash": attestation.attestation_hash,
    }


# ---------------------------------------------------------------------------
# Bridge endpoints
# ---------------------------------------------------------------------------

@app.post("/api/v1/bridge/initiate")
def bridge_initiate(req: BridgeInitiateRequest, current_user: Dict = Depends(_get_current_user)):
    """Initiate a cross-chain bridge transfer."""
    if not _bridge_available:
        raise HTTPException(status_code=503, detail="Bridge service not available")

    compliance_engine = None
    if _ce_available:
        compliance_engine = ComplianceEngine()

    manager = BridgeManager(compliance_engine=compliance_engine)
    bridge_req = BridgeRequest(
        source_chain=req.source_chain,
        dest_chain=req.dest_chain,
        token_address=req.token_address,
        amount=req.amount,
        recipient=req.recipient,
        sender=req.sender,
    )
    try:
        result = manager.initiate_bridge(bridge_req)
    except BridgeError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    return {
        "request_id": result.request_id,
        "status": result.status,
        "source_tx_hash": result.source_tx_hash,
        "dest_tx_hash": result.dest_tx_hash,
        "estimated_time": result.estimated_time,
        "error": result.error,
    }


@app.get("/api/v1/bridge/status/{request_id}")
def bridge_status(request_id: str, current_user: Dict = Depends(_get_current_user)):
    """Check the status of a pending bridge transfer."""
    if not _bridge_available:
        raise HTTPException(status_code=503, detail="Bridge service not available")

    # NOTE: In a production deployment, the BridgeManager would be a long-lived
    # singleton (e.g. stored in app.state) so request history is preserved.
    # This stub returns a not-found response for unknown IDs since each request
    # creates a fresh manager instance.
    raise HTTPException(
        status_code=404,
        detail=(
            f"Bridge request '{request_id}' not found. "
            "Use a persistent BridgeManager instance to query status."
        ),
    )
