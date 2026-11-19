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
from security import require_owner
from schemas import WalletLinkRequest

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
        get_balance as _get_balance,
        generate_receive_qr,
        WalletError,
    )
    _ws_available = True
except ImportError:
    _ws_available = False

from fastapi import HTTPException

router = APIRouter(tags=["wallet"])


LINK_MESSAGE = "AEGIS: link this address to account {user_id}. Nonce: {nonce}"


@router.post("/wallet/link/challenge")
def wallet_link_challenge(current_user: Dict = Depends(_get_current_user), db: Session = Depends(get_db)):
    """Message to sign ON THE DEVICE with the wallet key (valid 10 minutes, single use).

    The server never sees private keys or mnemonics: the wallet is created and kept in the app.
    """
    import secrets
    from datetime import datetime, timedelta

    nonce = secrets.token_hex(16)
    db.add(db_models.WalletLinkChallenge(user_id=int(current_user["user_id"]), nonce=nonce,
                                         expires_at=datetime.utcnow() + timedelta(minutes=10)))
    db.commit()
    return {"nonce": nonce, "message": LINK_MESSAGE.format(user_id=current_user["user_id"], nonce=nonce)}


@router.post("/wallet/link")
def wallet_link(req: WalletLinkRequest, current_user: Dict = Depends(_get_current_user), db: Session = Depends(get_db)):
    """Link an address to the account by proving control of it with an EIP-191 signature."""
    from datetime import datetime

    from eth_account import Account
    from eth_account.messages import encode_defunct

    uid = int(current_user["user_id"])
    ch = db.query(db_models.WalletLinkChallenge).filter_by(nonce=req.nonce, user_id=uid, used=False).first()
    if ch is None or ch.expires_at < datetime.utcnow():
        raise HTTPException(status_code=400, detail="Challenge missing, already used or expired")
    ch.used = True
    db.commit()
    message = LINK_MESSAGE.format(user_id=uid, nonce=req.nonce)
    try:
        signer = Account.recover_message(encode_defunct(text=message), signature=req.signature)
    except Exception:  # noqa: BLE001 - malformed signature
        raise HTTPException(status_code=400, detail="Invalid signature")
    if signer.lower() != req.address.lower():
        raise HTTPException(status_code=403, detail="The signature does not come from this address")
    existing = db.query(db_models.Wallet).filter(db_models.Wallet.address == signer).first()
    if existing is not None:
        if existing.user_id != uid:
            raise HTTPException(status_code=409, detail="Address already linked to another account")
        return {"address": signer, "linked": True}
    db.add(db_models.Wallet(user_id=uid, address=signer, encrypted_key=None))
    db.commit()
    return {"address": signer, "linked": True}


@router.get("/wallet/mine")
def wallet_mine(current_user: Dict = Depends(_get_current_user), db: Session = Depends(get_db)):
    if not _db_available or db is None:
        return {"wallets": []}
    rows = db.query(db_models.Wallet).filter(db_models.Wallet.user_id == int(current_user["user_id"])).all()
    return {"wallets": [{"address": w.address, "created_at": w.created_at.isoformat()} for w in rows]}


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
    # The history linked to the account is private: owner only (or compliance).
    require_owner(db, current_user, address, also_roles=("compliance", "admin"))
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
