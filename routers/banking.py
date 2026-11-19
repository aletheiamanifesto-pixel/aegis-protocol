#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
routers/banking.py - EUR operations. State in the database, amounts in Decimal, idempotent with
the `Idempotency-Key` header. Deposits complete ONLY on the bank's confirmation.
"""

import hashlib
import hmac
import os
from datetime import datetime, timedelta
from typing import Dict, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

import banking_operations as bo
from routers.auth import _get_current_user
from schemas import DepositRequest, Money, RecurringPaymentRequest, SchedulePaymentRequest, WithdrawRequest
from security import get_db, require_owner, require_roles, require_second_factor

router = APIRouter(tags=["banking"])


def _bad(e: Exception):
    raise HTTPException(status_code=400, detail=str(e))


@router.post("/banking/deposit", status_code=201)
def banking_deposit(req: DepositRequest, current_user: Dict = Depends(_get_current_user), db: Session = Depends(get_db),
                    idempotency_key: Optional[str] = Header(default=None, max_length=128)):
    """Create a deposit instruction (awaiting_funds): no token without the bank's confirmation."""
    require_owner(db, current_user, req.wallet_address)
    try:
        return bo.create_deposit(db, int(current_user["user_id"]), req.amount, req.wallet_address, idempotency_key)
    except bo.BankingError as e:
        _bad(e)


@router.post("/banking/withdraw", status_code=201)
def banking_withdraw(req: WithdrawRequest, current_user: Dict = Depends(_get_current_user), db: Session = Depends(get_db),
                     idempotency_key: Optional[str] = Header(default=None, max_length=128)):
    require_owner(db, current_user, req.wallet_address)
    require_second_factor(db, current_user, req.totp_code, mandatory=True)
    try:
        return bo.create_withdrawal(db, int(current_user["user_id"]), req.amount, req.wallet_address, req.iban,
                                    idempotency_key)
    except bo.BankingError as e:
        _bad(e)


class DepositConfirmation(BaseModel):
    reference: str
    amount: Money
    bank_tx_id: str


@router.post("/banking/deposits/confirm")
def banking_confirm_deposit(req: DepositConfirmation, _officer: Dict = Depends(require_roles("compliance", "admin")),
                            db: Session = Depends(get_db)):
    """Manual confirmation (compliance) of a credit seen on the bank account."""
    try:
        return bo.confirm_deposit(db, req.reference, req.amount, req.bank_tx_id)
    except bo.BankingError as e:
        _bad(e)


@router.post("/banking/webhook/deposit")
async def banking_deposit_webhook(request: Request, db: Session = Depends(get_db)):
    """Credit notification from the bank/BaaS, signed HMAC-SHA256 (X-Bank-Signature, BANK_WEBHOOK_SECRET)."""
    secret = os.getenv("BANK_WEBHOOK_SECRET", "")
    if len(secret) < 32:
        raise HTTPException(status_code=503, detail="Bank webhook not configured")
    body = await request.body()
    expected = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, request.headers.get("X-Bank-Signature", "")):
        raise HTTPException(status_code=401, detail="Invalid signature")
    try:
        req = DepositConfirmation.model_validate_json(body)
        return bo.confirm_deposit(db, req.reference, req.amount, req.bank_tx_id)
    except ValueError as e:
        _bad(e)


@router.get("/banking/statement")
def banking_statement(from_date: Optional[str] = None, to_date: Optional[str] = None,
                      current_user: Dict = Depends(_get_current_user), db: Session = Depends(get_db)):
    now = datetime.utcnow()
    try:
        fd = datetime.fromisoformat(from_date) if from_date else now - timedelta(days=30)
        td = datetime.fromisoformat(to_date) if to_date else now
        return bo.get_account_statement(db, int(current_user["user_id"]), fd, td)
    except (ValueError, bo.BankingError) as e:
        _bad(e)


@router.post("/banking/schedule-payment", status_code=201)
def banking_schedule_payment(req: SchedulePaymentRequest, current_user: Dict = Depends(_get_current_user),
                             db: Session = Depends(get_db)):
    require_owner(db, current_user, req.from_address)
    try:
        return bo.schedule_payment(db, int(current_user["user_id"]), req.from_address, req.to_address, req.amount,
                                   req.scheduled_at)
    except bo.BankingError as e:
        _bad(e)


@router.post("/banking/recurring-payment", status_code=201)
def banking_recurring_payment(req: RecurringPaymentRequest, current_user: Dict = Depends(_get_current_user),
                              db: Session = Depends(get_db)):
    require_owner(db, current_user, req.from_address)
    try:
        return bo.recurring_payment(db, int(current_user["user_id"]), req.from_address, req.to_address, req.amount,
                                    req.frequency, req.start_date)
    except bo.BankingError as e:
        _bad(e)


@router.get("/banking/reserve-status")
def banking_reserve_status(db: Session = Depends(get_db)):
    return bo.get_reserve_status(db)
