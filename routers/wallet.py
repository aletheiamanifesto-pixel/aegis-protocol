#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
routers/wallet.py - Wallet endpoints for AEGIS Protocol.
"""

from typing import Dict

from fastapi import APIRouter, Depends
from fastapi.responses import Response
from sqlalchemy.orm import Session

from routers.auth import _get_current_user
from schemas import WalletCreateRequest, WalletImportRequest

try:
    from db import get_db
    import db_models
    _db_available = True
except ImportError:
    _db_available = False

    def get_db():
        yield None

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

from fastapi import HTTPException

router = APIRouter(tags=["wallet"])


@router.post("/wallet/create")
def wallet_create(req: WalletCreateRequest, current_user: Dict = Depends(_get_current_user)):
    if not _ws_available:
        raise HTTPException(status_code=503, detail="Wallet service not available")
    result = _create_wallet(req.password)
    return result


@router.post("/wallet/import")
def wallet_import(req: WalletImportRequest, current_user: Dict = Depends(_get_current_user)):
    if not _ws_available:
        raise HTTPException(status_code=503, detail="Wallet service not available")
    result = _import_wallet(req.mnemonic_or_private_key, req.password)
    return result


@router.get("/wallet/balance/{address}")
def wallet_balance(address: str, current_user: Dict = Depends(_get_current_user)):
    if not _ws_available:
        raise HTTPException(status_code=503, detail="Wallet service not available")
    balance = _get_balance(address)
    return {"address": address, "balance": balance, "currency": "AEGIS-EUR"}


@router.get("/wallet/transactions/{address}")
def wallet_transactions(
    address: str,
    limit: int = 50,
    current_user: Dict = Depends(_get_current_user),
    db: Session = Depends(get_db),
):
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


@router.get("/wallet/qr/{address}")
def wallet_qr(address: str, current_user: Dict = Depends(_get_current_user)):
    if not _ws_available:
        raise HTTPException(status_code=503, detail="Wallet service not available")
    png_bytes = generate_receive_qr(address)
    return Response(content=png_bytes, media_type="image/png")
