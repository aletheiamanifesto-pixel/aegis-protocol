#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
routers/banking.py - Banking endpoints for AEGIS Protocol.
"""

from datetime import datetime, timedelta
from typing import Dict, Optional

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from routers.auth import _get_current_user
from security import get_db as _sec_get_db, require_owner, require_second_factor
from schemas import (
    DepositRequest,
    RecurringPaymentRequest,
    SchedulePaymentRequest,
    WithdrawRequest,
)

try:
    from db import get_db
    _db_available = True
except ImportError:
    _db_available = False

    def get_db():
        yield None

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

router = APIRouter(tags=["banking"])


@router.post("/banking/deposit")
def banking_deposit(req: DepositRequest, current_user: Dict = Depends(_get_current_user),
                    db=Depends(_sec_get_db)):
    if not _bo_available:
        raise HTTPException(status_code=503, detail="Banking operations not available")
    require_owner(db, current_user, req.wallet_address)
    try:
        result = deposit_eur(current_user["user_id"], req.amount, req.wallet_address)
        return result
    except BankingError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/banking/withdraw")
def banking_withdraw(req: WithdrawRequest, current_user: Dict = Depends(_get_current_user),
                     db=Depends(_sec_get_db)):
    if not _bo_available:
        raise HTTPException(status_code=503, detail="Banking operations not available")
    require_owner(db, current_user, req.wallet_address)
    require_second_factor(db, current_user, req.totp_code, mandatory=True)
    try:
        result = withdraw_eur(current_user["user_id"], req.amount, req.wallet_address, req.iban)
        return result
    except BankingError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/banking/statement")
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


@router.post("/banking/schedule-payment")
def banking_schedule_payment(
    req: SchedulePaymentRequest,
    current_user: Dict = Depends(_get_current_user),
    db=Depends(_sec_get_db),
):
    require_owner(db, current_user, req.from_address)
    if not _bo_available:
        raise HTTPException(status_code=503, detail="Banking operations not available")
    try:
        result = schedule_payment(
            current_user["user_id"], req.from_address, req.to_address, req.amount, req.scheduled_at
        )
        return result
    except BankingError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/banking/recurring-payment")
def banking_recurring_payment(
    req: RecurringPaymentRequest,
    current_user: Dict = Depends(_get_current_user),
    db=Depends(_sec_get_db),
):
    require_owner(db, current_user, req.from_address)
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


@router.get("/banking/reserve-status")
def banking_reserve_status():
    if not _bo_available:
        raise HTTPException(status_code=503, detail="Banking operations not available")
    return get_reserve_status()
