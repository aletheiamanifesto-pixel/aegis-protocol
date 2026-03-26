#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
main_app.py - AEGIS Protocol REST API

Endpoints:
  /health          – service health
  /auth            – login / logout
  /wallet          – create, import, balance, transactions
  /transactions    – send, status, confirm
  /compliance      – KYC, profile, ZK proof generation
"""

import os
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from cryptography.fernet import Fernet
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, Field
from sqlalchemy.exc import OperationalError, SQLAlchemyError
from sqlalchemy.orm import Session

from db import get_db, init_db
from db_models import AuditLog, ComplianceProfile, Transaction, User, Wallet
from compliance_engine import ComplianceEngine
from transaction_processor import TransactionProcessor

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="AEGIS Wallet API",
    description="MiCA-compliant smart wallet with ZK proofs",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ORIGINS", "*").split(","),
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------

SECRET_KEY = os.getenv("SECRET_KEY", "change-me-in-production-aegis-secret-key-32bytes")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))

# Derive a 32-byte Fernet key from SECRET_KEY for private-key encryption at rest.
# Production: replace with a proper KMS (e.g. AWS KMS / HashiCorp Vault).
import base64, hashlib as _hl
_fernet_raw = base64.urlsafe_b64encode(_hl.sha256(SECRET_KEY.encode()).digest())
_fernet = Fernet(_fernet_raw)


def _encrypt_private_key(plain_hex: str) -> str:
    return _fernet.encrypt(plain_hex.encode()).decode()


def _decrypt_private_key(token: str) -> str:
    return _fernet.decrypt(token.encode()).decode()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

compliance_engine = ComplianceEngine()
tx_processor = TransactionProcessor()


def _hash_password(plain: str) -> str:
    return pwd_context.hash(plain)


def _verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def _create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=15))
    to_encode["exp"] = expire
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def _get_current_user(
    token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)
) -> User:
    credentials_exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exc
    except JWTError:
        raise credentials_exc
    user = db.query(User).filter(User.id == user_id).first()
    if user is None or not user.is_active:
        raise credentials_exc
    return user


def _log_action(
    db: Session,
    action: str,
    user_id: Optional[str] = None,
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    details: Optional[Dict] = None,
    ip: Optional[str] = None,
) -> None:
    entry = AuditLog(
        user_id=user_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        ip_address=ip,
        details=details or {},
    )
    db.add(entry)
    db.commit()


# ---------------------------------------------------------------------------
# Pydantic request / response schemas
# ---------------------------------------------------------------------------


class RegisterRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=64)
    email: str
    password: str = Field(..., min_length=8)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class WalletCreateRequest(BaseModel):
    label: Optional[str] = None


class WalletImportRequest(BaseModel):
    private_key: str = Field(..., description="Hex private key (with or without 0x prefix)")
    label: Optional[str] = None


class SendTransactionRequest(BaseModel):
    sender_address: str
    recipient_address: str
    amount: float = Field(..., gt=0)
    proof_hash: Optional[str] = None


class KYCRequest(BaseModel):
    document_hash: str = Field(..., description="SHA-256 hash of KYC document")


class ZKProofRequest(BaseModel):
    amount: float = Field(..., gt=0)
    purpose: str = Field(default="kyc")


# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------


@app.on_event("startup")
async def startup_event() -> None:
    try:
        init_db()
        logger.info("Database tables initialised")
    except (OperationalError, SQLAlchemyError) as exc:
        logger.warning("DB init skipped (no DB available): %s", exc)


# ---------------------------------------------------------------------------
# /health
# ---------------------------------------------------------------------------


@app.get("/health", tags=["health"])
def health() -> Dict[str, Any]:
    return {"status": "ok", "version": "1.0.0", "timestamp": datetime.now(timezone.utc).isoformat()}


# ---------------------------------------------------------------------------
# /auth
# ---------------------------------------------------------------------------


@app.post("/auth/register", tags=["auth"], response_model=TokenResponse)
def register(req: RegisterRequest, request: Request, db: Session = Depends(get_db)):
    if db.query(User).filter(User.username == req.username).first():
        raise HTTPException(status_code=400, detail="Username already taken")
    if db.query(User).filter(User.email == req.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")

    user = User(
        username=req.username,
        email=req.email,
        hashed_password=_hash_password(req.password),
    )
    db.add(user)
    db.flush()

    # create default compliance profile
    profile = ComplianceProfile(user_id=user.id)
    db.add(profile)
    db.commit()
    db.refresh(user)

    _log_action(db, "register", user_id=user.id, ip=request.client.host if request.client else None)
    token = _create_access_token({"sub": user.id}, timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    return TokenResponse(access_token=token)


@app.post("/auth/login", tags=["auth"], response_model=TokenResponse)
def login(
    form: OAuth2PasswordRequestForm = Depends(),
    request: Request = None,
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.username == form.username).first()
    if not user or not _verify_password(form.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
        )
    _log_action(db, "login", user_id=user.id, ip=request.client.host if request and request.client else None)
    token = _create_access_token({"sub": user.id}, timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    return TokenResponse(access_token=token)


@app.post("/auth/logout", tags=["auth"])
def logout(current_user: User = Depends(_get_current_user), db: Session = Depends(get_db)):
    _log_action(db, "logout", user_id=current_user.id)
    return {"status": "logged out"}


# ---------------------------------------------------------------------------
# /wallet
# ---------------------------------------------------------------------------


@app.post("/wallet/create", tags=["wallet"])
def create_wallet(
    req: WalletCreateRequest,
    current_user: User = Depends(_get_current_user),
    db: Session = Depends(get_db),
):
    key_data = tx_processor.create_wallet()
    wallet = Wallet(
        user_id=current_user.id,
        address=key_data["address"],
        encrypted_key=_encrypt_private_key(key_data["private_key"]),
    )
    db.add(wallet)
    db.commit()
    db.refresh(wallet)
    _log_action(db, "wallet_create", user_id=current_user.id, resource_type="wallet", resource_id=wallet.id)
    return {
        "id": wallet.id,
        "address": wallet.address,
        "created_at": wallet.created_at.isoformat(),
    }


@app.post("/wallet/import", tags=["wallet"])
def import_wallet(
    req: WalletImportRequest,
    current_user: User = Depends(_get_current_user),
    db: Session = Depends(get_db),
):
    private_key = req.private_key if req.private_key.startswith("0x") else "0x" + req.private_key
    try:
        key_data = tx_processor.import_wallet(private_key)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Invalid private key: {exc}")

    existing = db.query(Wallet).filter(Wallet.address == key_data["address"]).first()
    if existing:
        raise HTTPException(status_code=400, detail="Wallet already exists")

    wallet = Wallet(
        user_id=current_user.id,
        address=key_data["address"],
        encrypted_key=_encrypt_private_key(private_key),
    )
    db.add(wallet)
    db.commit()
    db.refresh(wallet)
    _log_action(db, "wallet_import", user_id=current_user.id, resource_type="wallet", resource_id=wallet.id)
    return {"id": wallet.id, "address": wallet.address}


@app.get("/wallet/{address}/balance", tags=["wallet"])
def get_balance(
    address: str,
    current_user: User = Depends(_get_current_user),
    db: Session = Depends(get_db),
):
    wallet = db.query(Wallet).filter(Wallet.address == address).first()
    if not wallet:
        raise HTTPException(status_code=404, detail="Wallet not found")
    if wallet.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not your wallet")

    try:
        on_chain_balance = tx_processor.get_balance(address)
        wallet.balance_eurc = on_chain_balance
        db.commit()
    except (ConnectionError, OSError, ValueError) as exc:
        logger.warning("Could not fetch on-chain balance for %s: %s", address, exc)
        on_chain_balance = wallet.balance_eurc  # use cached value

    return {"address": address, "balance_eurc": on_chain_balance, "is_frozen": wallet.is_frozen}


@app.get("/wallet/{address}/transactions", tags=["wallet"])
def get_transactions(
    address: str,
    limit: int = 20,
    offset: int = 0,
    current_user: User = Depends(_get_current_user),
    db: Session = Depends(get_db),
):
    wallet = db.query(Wallet).filter(Wallet.address == address).first()
    if not wallet:
        raise HTTPException(status_code=404, detail="Wallet not found")
    if wallet.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not your wallet")

    txs = (
        db.query(Transaction)
        .filter(Transaction.sender_address == address)
        .order_by(Transaction.created_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    return [
        {
            "id": t.id,
            "tx_hash": t.tx_hash,
            "recipient": t.recipient_address,
            "amount": t.amount,
            "status": t.status,
            "created_at": t.created_at.isoformat(),
        }
        for t in txs
    ]


# ---------------------------------------------------------------------------
# /transactions
# ---------------------------------------------------------------------------


@app.post("/transactions/send", tags=["transactions"])
def send_transaction(
    req: SendTransactionRequest,
    current_user: User = Depends(_get_current_user),
    db: Session = Depends(get_db),
):
    # Verify sender wallet belongs to current user
    wallet = db.query(Wallet).filter(Wallet.address == req.sender_address).first()
    if not wallet or wallet.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Sender wallet not found or not yours")
    if wallet.is_frozen:
        raise HTTPException(status_code=403, detail="Wallet is frozen")

    # Compliance check
    profile = db.query(ComplianceProfile).filter(ComplianceProfile.user_id == current_user.id).first()
    daily_spent = (
        db.query(Transaction)
        .filter(
            Transaction.sender_address == req.sender_address,
            Transaction.status.in_(["confirmed", "pending"]),
            Transaction.created_at >= datetime.now(timezone.utc) - timedelta(days=1),
        )
        .with_entities(Transaction.amount)
        .all()
    )
    total_daily = sum(r.amount for r in daily_spent)

    result = compliance_engine.check_transaction(
        sender=req.sender_address,
        amount=req.amount,
        kyc_verified=profile.kyc_verified if profile else False,
        daily_spent=total_daily,
        daily_limit=profile.daily_limit if profile else 1000.0,
        single_tx_limit=profile.single_tx_limit if profile else 500.0,
    )

    if not result.approved:
        raise HTTPException(
            status_code=400,
            detail={
                "message": result.message,
                "requires_zk_proof": result.requires_zk_proof,
                "flags": result.flags,
            },
        )

    # Create pending transaction record
    tx_record = Transaction(
        sender_address=req.sender_address,
        recipient_address=req.recipient_address,
        amount=req.amount,
        proof_hash=req.proof_hash,
        requires_zk_proof=result.requires_zk_proof,
        status="pending",
    )
    db.add(tx_record)
    db.commit()
    db.refresh(tx_record)

    # Attempt on-chain send
    try:
        decrypted_key = _decrypt_private_key(wallet.encrypted_key)
        on_chain = tx_processor.send_eurc(
            sender_private_key=decrypted_key,
            recipient=req.recipient_address,
            amount_eur=req.amount,
            proof_hash=req.proof_hash,
        )
        tx_record.tx_hash = on_chain["tx_hash"]
        tx_record.status = on_chain["status"]
        tx_record.block_number = on_chain.get("block_number")
        tx_record.gas_used = on_chain.get("gas_used")
        if on_chain["status"] == "confirmed":
            tx_record.confirmed_at = datetime.now(timezone.utc)
    except (ConnectionError, OSError, ValueError) as exc:
        logger.warning("On-chain send failed, keeping as pending: %s", exc)

    db.commit()
    _log_action(
        db,
        "transaction_send",
        user_id=current_user.id,
        resource_type="transaction",
        resource_id=tx_record.id,
        details={"amount": req.amount, "recipient": req.recipient_address},
    )
    return {
        "id": tx_record.id,
        "tx_hash": tx_record.tx_hash,
        "status": tx_record.status,
        "requires_zk_proof": result.requires_zk_proof,
        "compliance_flags": result.flags,
    }


@app.get("/transactions/{tx_id}/status", tags=["transactions"])
def get_transaction_status(
    tx_id: str,
    current_user: User = Depends(_get_current_user),
    db: Session = Depends(get_db),
):
    tx = db.query(Transaction).filter(Transaction.id == tx_id).first()
    if not tx:
        raise HTTPException(status_code=404, detail="Transaction not found")

    # Refresh from chain if we have a hash and it is still pending
    if tx.tx_hash and tx.status == "pending":
        try:
            on_chain = tx_processor.get_transaction_status(tx.tx_hash)
            if on_chain["status"] != "pending":
                tx.status = on_chain["status"]
                tx.block_number = on_chain.get("block_number")
                if tx.status == "confirmed":
                    tx.confirmed_at = datetime.now(timezone.utc)
                db.commit()
        except (ConnectionError, OSError, ValueError) as exc:
            logger.warning("Could not refresh tx status for %s: %s", tx.tx_hash, exc)

    return {
        "id": tx.id,
        "tx_hash": tx.tx_hash,
        "status": tx.status,
        "block_number": tx.block_number,
        "created_at": tx.created_at.isoformat(),
        "confirmed_at": tx.confirmed_at.isoformat() if tx.confirmed_at else None,
    }


@app.post("/transactions/{tx_id}/confirm", tags=["transactions"])
def confirm_transaction(
    tx_id: str,
    current_user: User = Depends(_get_current_user),
    db: Session = Depends(get_db),
):
    tx = db.query(Transaction).filter(Transaction.id == tx_id).first()
    if not tx:
        raise HTTPException(status_code=404, detail="Transaction not found")
    if tx.status not in ("pending",):
        raise HTTPException(status_code=400, detail=f"Cannot confirm a transaction with status '{tx.status}'")
    tx.status = "confirmed"
    tx.confirmed_at = datetime.now(timezone.utc)
    db.commit()
    return {"id": tx.id, "status": tx.status}


# ---------------------------------------------------------------------------
# /compliance
# ---------------------------------------------------------------------------


@app.post("/compliance/kyc", tags=["compliance"])
def submit_kyc(
    req: KYCRequest,
    current_user: User = Depends(_get_current_user),
    db: Session = Depends(get_db),
):
    result = compliance_engine.verify_kyc(current_user.id, req.document_hash)
    profile = db.query(ComplianceProfile).filter(ComplianceProfile.user_id == current_user.id).first()
    if not profile:
        profile = ComplianceProfile(user_id=current_user.id)
        db.add(profile)

    if result.approved:
        profile.kyc_verified = True
        profile.aml_screened = True
        profile.last_kyc_at = datetime.now(timezone.utc)
        profile.last_risk_assessment = datetime.now(timezone.utc)
    db.commit()
    _log_action(db, "kyc_submit", user_id=current_user.id, details={"approved": result.approved})
    return {"approved": result.approved, "message": result.message}


@app.get("/compliance/profile/{user_id}", tags=["compliance"])
def get_compliance_profile(
    user_id: str,
    current_user: User = Depends(_get_current_user),
    db: Session = Depends(get_db),
):
    if user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Access denied")
    profile = db.query(ComplianceProfile).filter(ComplianceProfile.user_id == user_id).first()
    if not profile:
        raise HTTPException(status_code=404, detail="Compliance profile not found")
    return {
        "user_id": profile.user_id,
        "kyc_verified": profile.kyc_verified,
        "aml_screened": profile.aml_screened,
        "daily_limit": profile.daily_limit,
        "single_tx_limit": profile.single_tx_limit,
        "risk_level": profile.risk_level,
        "last_kyc_at": profile.last_kyc_at.isoformat() if profile.last_kyc_at else None,
        "last_risk_assessment": profile.last_risk_assessment.isoformat()
        if profile.last_risk_assessment
        else None,
    }


@app.post("/compliance/proof/generate", tags=["compliance"])
def generate_zk_proof(
    req: ZKProofRequest,
    current_user: User = Depends(_get_current_user),
    db: Session = Depends(get_db),
):
    proof = compliance_engine.generate_zk_proof(
        user_id=current_user.id,
        amount=req.amount,
        purpose=req.purpose,
    )
    # Persist proof hash on compliance profile
    profile = db.query(ComplianceProfile).filter(ComplianceProfile.user_id == current_user.id).first()
    if profile:
        profile.zk_proof_hash = proof.proof_hash
        db.commit()

    _log_action(
        db,
        "zk_proof_generate",
        user_id=current_user.id,
        details={"amount": req.amount, "purpose": req.purpose, "proof_hash": proof.proof_hash},
    )
    return {
        "proof_hash": proof.proof_hash,
        "public_inputs": proof.public_inputs,
        "valid_until": proof.valid_until,
        "generated_at": proof.generated_at,
    }

