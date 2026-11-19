#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
banking_operations.py - EUR operations (deposits, withdrawals, statements, scheduled payments).

All state lives in the DATABASE (bank_operations, scheduled_payments): with N workers or
N instances there is one bank. Amounts are Decimal with 2 decimals (never float).

Flows (truthful, no faked "completed"):
  DEPOSIT     create_deposit → "awaiting_funds" with a unique bank reference to put in the SEPA
              transfer → confirm_deposit (signed bank webhook or compliance) → "completed".
              Minting the tokens is done by the AegisVault signers on the confirmed bank tx.
  WITHDRAWAL  create_withdrawal → "awaiting_escrow" with payout_ref_hash → the user calls
              AegisVault.requestWithdrawal(amount, payout_ref_hash) from their device → the signers
              pay and call completeWithdrawal.
  IDEMPOTENCY the same Idempotency-Key from the same user returns the same operation (a network
              retry does not double a deposit).
"""

from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta
from decimal import ROUND_HALF_EVEN, Decimal, InvalidOperation
from typing import Any, Dict, List, Optional

from sqlalchemy import func
from sqlalchemy.exc import IntegrityError

import db_models

CENT = Decimal("0.01")
MAX_SINGLE_DEPOSIT = Decimal("1000000.00")
FREQUENCIES = ("daily", "weekly", "monthly", "quarterly")


class BankingError(Exception):
    pass


def to_money(value: Any) -> Decimal:
    """Convert to Decimal with 2 decimals; rejects NaN/inf and more than 2 decimal places."""
    try:
        d = Decimal(str(value))
    except (InvalidOperation, ValueError) as exc:
        raise BankingError("Invalid amount") from exc
    if not d.is_finite():
        raise BankingError("Invalid amount")
    if d != d.quantize(CENT):
        raise BankingError("At most 2 decimal places")
    return d.quantize(CENT, rounding=ROUND_HALF_EVEN)


def _mask_iban(iban: str) -> str:
    return iban[:2] + "****" + iban[-2:]


def _valid_iban(iban: str) -> bool:
    """IBAN check (ISO 13616, mod 97)."""
    if not 15 <= len(iban) <= 34 or not iban[:2].isalpha() or not iban[2:4].isdigit() or not iban.isalnum():
        return False
    rearranged = iban[4:] + iban[:4]
    digits = "".join(str(int(c, 36)) for c in rearranged)
    return int(digits) % 97 == 1


def _op_dict(op: "db_models.BankOperation") -> Dict[str, Any]:
    d = {
        "operation_id": op.id,
        "kind": op.kind,
        "amount_eur": str(op.amount),
        "wallet_address": op.wallet_address,
        "status": op.status,
        "reference": op.reference,
        "created_at": op.created_at.isoformat(),
    }
    if op.kind == "deposit":
        d["instructions"] = (
            f"Send exactly {op.amount} EUR by SEPA transfer with reason {op.reference}. "
            "The tokens are issued after the bank confirms receipt."
        )
    if op.kind == "withdrawal":
        d["destination_iban"] = op.iban_masked
        d["payout_ref_hash"] = op.payout_ref_hash
        d["next_step"] = "Call AegisVault.requestWithdrawal(amount, payout_ref_hash) from your wallet"
    return d


def _existing(db, user_id: int, kind: str, idempotency_key: Optional[str]):
    if not idempotency_key:
        return None
    return db.query(db_models.BankOperation).filter_by(user_id=user_id, kind=kind, idempotency_key=idempotency_key).first()


def _save(db, op) -> "db_models.BankOperation":
    db.add(op)
    try:
        db.commit()
    except IntegrityError:
        # two concurrent requests with the same key: the second gets the first one's operation
        db.rollback()
        existing = _existing(db, op.user_id, op.kind, op.idempotency_key)
        if existing is None:
            raise
        return existing
    db.refresh(op)
    return op


# ---------------------------------------------------------------------------
# Deposits
# ---------------------------------------------------------------------------

def create_deposit(db, user_id: int, amount: Any, wallet_address: str, idempotency_key: Optional[str] = None) -> Dict[str, Any]:
    amount = to_money(amount)
    if amount <= 0:
        raise BankingError("Deposit amount must be positive")
    if amount > MAX_SINGLE_DEPOSIT:
        raise BankingError("Single deposit limit is 1,000,000 EUR")
    existing = _existing(db, user_id, "deposit", idempotency_key)
    if existing is not None:
        return _op_dict(existing)
    op = db_models.BankOperation(
        user_id=user_id, kind="deposit", amount=amount, wallet_address=wallet_address, status="awaiting_funds",
        reference="DEP-" + secrets.token_hex(6).upper(), idempotency_key=idempotency_key,
    )
    return _op_dict(_save(db, op))


def confirm_deposit(db, reference: str, received_amount: Any, bank_tx_id: str) -> Dict[str, Any]:
    """Confirmation of receipt from the bank (webhook) or from compliance. Idempotent on the reference."""
    op = db.query(db_models.BankOperation).filter_by(reference=reference, kind="deposit").with_for_update().first()
    if op is None:
        raise BankingError("Unknown reference")
    if op.status == "completed":
        return _op_dict(op)
    if op.status != "awaiting_funds":
        raise BankingError(f"Deposit in state {op.status}")
    if to_money(received_amount) != op.amount:
        op.status = "amount_mismatch"
        op.bank_tx_id = bank_tx_id
        db.commit()
        raise BankingError("Received amount different from the expected one: manual review")
    op.status, op.bank_tx_id, op.updated_at = "completed", bank_tx_id, datetime.utcnow()
    db.commit()
    return _op_dict(op)


# ---------------------------------------------------------------------------
# Withdrawals
# ---------------------------------------------------------------------------

def create_withdrawal(db, user_id: int, amount: Any, wallet_address: str, iban: str,
                      idempotency_key: Optional[str] = None) -> Dict[str, Any]:
    amount = to_money(amount)
    if amount <= 0:
        raise BankingError("Withdrawal amount must be positive")
    iban_clean = iban.replace(" ", "").upper()
    if not _valid_iban(iban_clean):
        raise BankingError("Invalid IBAN")
    existing = _existing(db, user_id, "withdrawal", idempotency_key)
    if existing is not None:
        return _op_dict(existing)
    reference = "WIT-" + secrets.token_hex(6).upper()
    # On-chain only the hash goes (never the IBAN): it binds the escrow to THESE payout details.
    from eth_utils import keccak

    payout_ref_hash = "0x" + keccak(f"{iban_clean}|{reference}".encode()).hex()
    op = db_models.BankOperation(
        user_id=user_id, kind="withdrawal", amount=amount, wallet_address=wallet_address, status="awaiting_escrow",
        reference=reference, idempotency_key=idempotency_key, iban_masked=_mask_iban(iban_clean),
        payout_ref_hash=payout_ref_hash,
    )
    return _op_dict(_save(db, op))


# ---------------------------------------------------------------------------
# Statements and reserve
# ---------------------------------------------------------------------------

def get_account_statement(db, user_id: int, from_date: datetime, to_date: datetime) -> Dict[str, Any]:
    if from_date > to_date:
        raise BankingError("from_date must be before to_date")
    ops = (db.query(db_models.BankOperation)
           .filter(db_models.BankOperation.user_id == user_id,
                   db_models.BankOperation.created_at >= from_date,
                   db_models.BankOperation.created_at <= to_date)
           .order_by(db_models.BankOperation.created_at).all())
    total_in = sum((o.amount for o in ops if o.kind == "deposit" and o.status == "completed"), Decimal("0.00"))
    total_out = sum((o.amount for o in ops if o.kind == "withdrawal" and o.status == "completed"), Decimal("0.00"))
    statement_id = "STMT-" + hashlib.sha256(f"{user_id}:{from_date.isoformat()}:{to_date.isoformat()}".encode()).hexdigest()[:12].upper()
    return {
        "statement_id": statement_id,
        "user_id": str(user_id),
        "period_from": from_date.isoformat(),
        "period_to": to_date.isoformat(),
        "generated_at": datetime.utcnow().isoformat(),
        "operations": [_op_dict(o) for o in ops],
        "summary": {"total_in": str(total_in), "total_out": str(total_out), "net": str(total_in - total_out)},
    }


def _total(db, kind: str) -> Decimal:
    v = db.query(func.coalesce(func.sum(db_models.BankOperation.amount), 0)).filter_by(kind=kind, status="completed").scalar()
    return to_money(v or 0)


def get_reserve_status(db) -> Dict[str, Any]:
    """Bookkeeping view from the operations CONFIRMED by the bank (not proof of reserve:
    that is AegisVault.attestReserve by an independent attestor)."""
    deposits, withdrawals = _total(db, "deposit"), _total(db, "withdrawal")
    outstanding = deposits - withdrawals
    audit_hash = "0x" + hashlib.sha256(f"{deposits}:{withdrawals}:{datetime.utcnow().date().isoformat()}".encode()).hexdigest()
    return {
        "total_deposits_eur": str(deposits),
        "total_withdrawals_eur": str(withdrawals),
        "total_outstanding_eur": str(outstanding),
        "source": "bank-confirmed operations (bookkeeping)",
        "audit_hash": audit_hash,
        "timestamp": datetime.utcnow().isoformat(),
    }


def get_reserve_ratio(db=None) -> Optional[float]:
    """Kept for the reports: None if the database is not reachable (never a made-up number)."""
    if db is None:
        from db import SessionLocal

        db = SessionLocal()
        try:
            return get_reserve_ratio(db)
        finally:
            db.close()
    status = get_reserve_status(db)
    outstanding = Decimal(status["total_outstanding_eur"])
    return 1.0 if outstanding <= 0 else float(Decimal(status["total_deposits_eur"]) / outstanding)


# ---------------------------------------------------------------------------
# Scheduled / recurring payments
# ---------------------------------------------------------------------------

def _schedule_dict(p) -> Dict[str, Any]:
    return {
        "schedule_id": p.id,
        "from_address": p.from_address,
        "to_address": p.to_address,
        "amount": str(p.amount),
        "scheduled_at": p.scheduled_at.isoformat(),
        "is_recurring": p.is_recurring,
        "frequency": p.frequency,
        "status": p.status,
    }


def schedule_payment(db, user_id: int, from_address: str, to_address: str, amount: Any,
                     scheduled_at: datetime) -> Dict[str, Any]:
    amount = to_money(amount)
    if amount <= 0:
        raise BankingError("Payment amount must be positive")
    if scheduled_at <= datetime.utcnow():
        raise BankingError("Scheduled time must be in the future")
    p = db_models.ScheduledPayment(user_id=user_id, from_address=from_address, to_address=to_address,
                                   amount=amount, scheduled_at=scheduled_at, is_recurring=False, status="pending")
    db.add(p)
    db.commit()
    db.refresh(p)
    return _schedule_dict(p)


def recurring_payment(db, user_id: int, from_address: str, to_address: str, amount: Any, frequency: str,
                      start_date: Optional[datetime] = None) -> Dict[str, Any]:
    if frequency not in FREQUENCIES:
        raise BankingError(f"frequency must be one of: {list(FREQUENCIES)}")
    amount = to_money(amount)
    if amount <= 0:
        raise BankingError("Payment amount must be positive")
    start_date = start_date or datetime.utcnow() + timedelta(days=1)
    if start_date <= datetime.utcnow():
        raise BankingError("start_date must be in the future")
    p = db_models.ScheduledPayment(user_id=user_id, from_address=from_address, to_address=to_address,
                                   amount=amount, scheduled_at=start_date, is_recurring=True,
                                   frequency=frequency, status="active")
    db.add(p)
    db.commit()
    db.refresh(p)
    return _schedule_dict(p)


__all__: List[str] = [
    "BankingError", "to_money", "create_deposit", "confirm_deposit", "create_withdrawal",
    "get_account_statement", "get_reserve_status", "get_reserve_ratio", "schedule_payment", "recurring_payment",
]
