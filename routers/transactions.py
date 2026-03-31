#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
routers/transactions.py - Transaction endpoints for AEGIS Protocol.
"""

from typing import Dict

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from routers.auth import _get_current_user
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
    from transaction_processor import TransactionProcessor
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
            req.from_address,
            req.amount,
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


@router.get("/transactions/{tx_hash}/status")
def transaction_status(tx_hash: str, current_user: Dict = Depends(_get_current_user)):
    if not _tp_available:
        raise HTTPException(status_code=503, detail="Transaction processor not available")
    tp = TransactionProcessor()
    return tp.get_transaction_status(tx_hash)
