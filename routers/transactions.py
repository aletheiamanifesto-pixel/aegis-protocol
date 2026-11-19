#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
routers/transactions.py - Transaction endpoints for AEGIS Protocol.
"""

from typing import Dict

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from routers.auth import _get_current_user
from security import require_owner, require_second_factor
from schemas import SendTransactionRequest

try:
    from db import get_db
    import db_models
    _db_available = True
except ImportError:
    _db_available = False

    def get_db():
        yield None

try:
    from compliance_engine import ComplianceEngine
    _ce_available = True
except ImportError:
    _ce_available = False

try:
    from transaction_processor import TransactionError, TransactionProcessor
    _tp_available = True
except ImportError:
    _tp_available = False

router = APIRouter(tags=["transactions"])


@router.post("/transactions/send")
def transactions_send(
    req: SendTransactionRequest,
    current_user: Dict = Depends(_get_current_user),
    db: Session = Depends(get_db),
):
    """Broadcast an EURC transfer ALREADY SIGNED on the device.

    Sender, recipient and amount are read from the signed transaction (not from fields that could
    disagree with it); the private key never leaves the user's device.
    """
    if not _tp_available:
        raise HTTPException(status_code=503, detail="Transaction processor not available")
    tp = TransactionProcessor()
    try:
        tx = tp.decode_signed_transfer(req.signed_tx)
    except TransactionError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    # The signer must be a wallet of the authenticated user; 2FA if enabled.
    require_owner(db, current_user, tx["sender"])
    require_second_factor(db, current_user, req.totp_code, mandatory=False)

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
            tx["sender"],
            tx["amount"],
            kyc_verified=kyc_verified,
            daily_limit=daily_limit,
            single_tx_limit=single_tx_limit,
        )
        if not result.approved:
            raise HTTPException(status_code=400, detail=result.message)

    tx_result = tp.broadcast_signed(tx["raw"])
    tx_result.update({"sender": tx["sender"], "recipient": tx["recipient"], "amount": tx["amount"]})

    if _db_available and db is not None:
        db.add(db_models.Transaction(
            tx_hash=tx_result["tx_hash"],
            sender_address=tx["sender"],
            recipient_address=tx["recipient"],
            amount=tx["amount"],
            status=tx_result.get("status", "pending"),
            proof_hash=req.proof_hash,
        ))
        db.commit()

    return tx_result


@router.get("/transactions/{tx_hash}/status")
def transaction_status(tx_hash: str, current_user: Dict = Depends(_get_current_user)):
    if not _tp_available:
        raise HTTPException(status_code=503, detail="Transaction processor not available")
    tp = TransactionProcessor()
    return tp.get_transaction_status(tx_hash)
