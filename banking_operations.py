#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
banking_operations.py - Banking operations for AEGIS Protocol.

Implements deposit/withdraw (EUR<->AEGIS EUR), statements, scheduled/recurring payments,
and reserve status reporting.
"""

import hashlib
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional


class BankingError(Exception):
    pass


# ---------------------------------------------------------------------------
# Reserve tracking (in-memory for MVP)
# ---------------------------------------------------------------------------

_total_deposits: float = 0.0
_total_withdrawals: float = 0.0
_reserve_audits: List[Dict] = []


def get_reserve_ratio() -> float:
    """
    Calculate the current reserve ratio (EUR reserves / AEGIS EUR outstanding).
    Should always be >= 1.0 (100%) in a sound system.
    """
    outstanding = _total_deposits - _total_withdrawals
    if outstanding <= 0:
        return 1.0
    if _total_deposits == 0:
        return 0.0
    return _total_deposits / outstanding


# ---------------------------------------------------------------------------
# Deposit / Withdraw
# ---------------------------------------------------------------------------


def deposit_eur(user_id: str, amount: float, wallet_address: str) -> Dict[str, Any]:
    """
    Deposit EUR and mint equivalent AEGIS EUR tokens.

    Args:
        user_id: User identifier.
        amount: Amount in EUR to deposit.
        wallet_address: User's wallet address to receive AEGIS EUR.

    Returns:
        Dict with operation_id, amount, status, aegis_eur_minted.

    Note:
        In production, this triggers:
        1. EUR bank transfer verification (SEPA/SWIFT)
        2. AegisVault.deposit() -> mints AEGIS EUR 1:1
        3. Updates DB balance
    """
    global _total_deposits

    if amount <= 0:
        raise BankingError("Deposit amount must be positive")
    if amount > 1_000_000:
        raise BankingError("Single deposit limit is 1,000,000 EUR")

    operation_id = str(uuid.uuid4())
    _total_deposits += amount

    return {
        "operation_id": operation_id,
        "user_id": user_id,
        "wallet_address": wallet_address,
        "amount_eur": amount,
        "aegis_eur_minted": amount,
        "status": "completed",
        "timestamp": datetime.utcnow().isoformat(),
        "reserve_ratio": get_reserve_ratio(),
        "tx_reference": f"DEP-{operation_id[:8].upper()}",
    }


def withdraw_eur(
    user_id: str,
    amount: float,
    wallet_address: str,
    iban: str,
) -> Dict[str, Any]:
    """
    Burn AEGIS EUR tokens and send EUR back via IBAN.

    Args:
        user_id: User identifier.
        amount: Amount in AEGIS EUR to redeem.
        wallet_address: Wallet address to burn from.
        iban: Destination IBAN for EUR payout.

    Returns:
        Dict with operation_id, amount, status, iban.
    """
    global _total_withdrawals

    if amount <= 0:
        raise BankingError("Withdrawal amount must be positive")

    iban_clean = iban.replace(" ", "").upper()
    if len(iban_clean) < 15 or len(iban_clean) > 34:
        raise BankingError("Invalid IBAN format")

    operation_id = str(uuid.uuid4())
    _total_withdrawals += amount

    return {
        "operation_id": operation_id,
        "user_id": user_id,
        "wallet_address": wallet_address,
        "amount_aegis_eur": amount,
        "amount_eur_sent": amount,
        "destination_iban": iban_clean[:4] + "****" + iban_clean[-4:],  # Masked
        "status": "processing",
        "estimated_arrival": (datetime.utcnow() + timedelta(days=2)).isoformat(),
        "timestamp": datetime.utcnow().isoformat(),
        "tx_reference": f"WIT-{operation_id[:8].upper()}",
    }


def get_account_statement(
    user_id: str,
    from_date: datetime,
    to_date: datetime,
    transactions: Optional[List[Dict]] = None,
) -> Dict[str, Any]:
    """
    Generate an account statement for a date range.

    Args:
        user_id: User identifier.
        from_date: Start date.
        to_date: End date.
        transactions: Pre-fetched transaction list (from DB).

    Returns:
        Dict with statement data including transactions and summary.
    """
    if from_date > to_date:
        raise BankingError("from_date must be before to_date")

    txns = transactions or []

    total_in = sum(t.get("amount", 0) for t in txns if t.get("direction") == "in")
    total_out = sum(t.get("amount", 0) for t in txns if t.get("direction") == "out")

    statement_id = "STMT-" + hashlib.sha256(
        f"{user_id}:{from_date.isoformat()}:{to_date.isoformat()}".encode()
    ).hexdigest()[:12].upper()

    return {
        "statement_id": statement_id,
        "user_id": user_id,
        "period_from": from_date.isoformat(),
        "period_to": to_date.isoformat(),
        "generated_at": datetime.utcnow().isoformat(),
        "transactions": txns,
        "summary": {
            "total_incoming": total_in,
            "total_outgoing": total_out,
            "net_change": total_in - total_out,
            "transaction_count": len(txns),
        },
        "currency": "AEGIS EUR",
    }


# ---------------------------------------------------------------------------
# Scheduled / Recurring Payments
# ---------------------------------------------------------------------------

_scheduled_payments: List[Dict] = []


def schedule_payment(
    user_id: str,
    from_address: str,
    to_address: str,
    amount: float,
    scheduled_at: datetime,
) -> Dict[str, Any]:
    """
    Schedule a one-time future payment.

    Args:
        user_id: User identifier.
        from_address: Source wallet.
        to_address: Destination wallet.
        amount: Amount in AEGIS EUR.
        scheduled_at: When to execute the payment.

    Returns:
        Dict with schedule_id and details.
    """
    if amount <= 0:
        raise BankingError("Payment amount must be positive")
    if scheduled_at <= datetime.utcnow():
        raise BankingError("Scheduled time must be in the future")

    schedule_id = str(uuid.uuid4())
    payment = {
        "schedule_id": schedule_id,
        "user_id": user_id,
        "from_address": from_address,
        "to_address": to_address,
        "amount": amount,
        "scheduled_at": scheduled_at.isoformat(),
        "is_recurring": False,
        "frequency": None,
        "status": "pending",
        "created_at": datetime.utcnow().isoformat(),
    }
    _scheduled_payments.append(payment)
    return payment


def recurring_payment(
    user_id: str,
    from_address: str,
    to_address: str,
    amount: float,
    frequency: str,
    start_date: Optional[datetime] = None,
) -> Dict[str, Any]:
    """
    Set up a recurring payment.

    Args:
        user_id: User identifier.
        from_address: Source wallet.
        to_address: Destination wallet.
        amount: Amount per payment in AEGIS EUR.
        frequency: 'daily', 'weekly', 'monthly', 'quarterly'.
        start_date: When to start. Defaults to tomorrow.

    Returns:
        Dict with schedule_id and details.
    """
    valid_frequencies = ["daily", "weekly", "monthly", "quarterly"]
    if frequency not in valid_frequencies:
        raise BankingError(f"frequency must be one of: {valid_frequencies}")
    if amount <= 0:
        raise BankingError("Payment amount must be positive")

    if start_date is None:
        start_date = datetime.utcnow() + timedelta(days=1)

    if start_date <= datetime.utcnow():
        raise BankingError("start_date must be in the future")

    schedule_id = str(uuid.uuid4())
    payment = {
        "schedule_id": schedule_id,
        "user_id": user_id,
        "from_address": from_address,
        "to_address": to_address,
        "amount": amount,
        "frequency": frequency,
        "is_recurring": True,
        "start_date": start_date.isoformat(),
        "next_execution": start_date.isoformat(),
        "status": "active",
        "created_at": datetime.utcnow().isoformat(),
        "executions_count": 0,
    }
    _scheduled_payments.append(payment)
    return payment


def get_reserve_status() -> Dict[str, Any]:
    """
    Get the current state of AEGIS EUR reserves.

    Returns:
        Dict with reserve ratio, total deposits, total outstanding, and audit hash.
    """
    total_outstanding = _total_deposits - _total_withdrawals
    ratio = get_reserve_ratio()

    audit_data = f"{_total_deposits}:{_total_withdrawals}:{datetime.utcnow().date().isoformat()}"
    audit_hash = "0x" + hashlib.sha256(audit_data.encode()).hexdigest()

    return {
        "reserve_ratio": ratio,
        "is_fully_backed": ratio >= 1.0,
        "total_deposits_eur": _total_deposits,
        "total_withdrawals_eur": _total_withdrawals,
        "total_outstanding_aegis_eur": max(0, total_outstanding),
        "status": "healthy" if ratio >= 1.0 else "undercollateralized",
        "last_audit_hash": audit_hash,
        "timestamp": datetime.utcnow().isoformat(),
        "compliance": "MiCA Article 36 - 1:1 backing required",
    }
