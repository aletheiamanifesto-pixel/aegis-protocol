#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for banking_operations.py"""

import pytest
from datetime import datetime, timedelta
from banking_operations import (
    deposit_eur,
    withdraw_eur,
    get_account_statement,
    schedule_payment,
    recurring_payment,
    get_reserve_status,
    BankingError,
)


@pytest.fixture(autouse=True)
def reset_banking_state():
    """Reset banking state between tests."""
    import banking_operations as bo
    bo._total_deposits = 0.0
    bo._total_withdrawals = 0.0
    bo._scheduled_payments.clear()
    yield
    bo._total_deposits = 0.0
    bo._total_withdrawals = 0.0
    bo._scheduled_payments.clear()


class TestDeposit:
    def test_basic_deposit(self):
        result = deposit_eur("user1", 1000.0, "0xwallet")
        assert result["status"] == "completed"
        assert result["amount_eur"] == 1000.0
        assert result["aegis_eur_minted"] == 1000.0
        assert "operation_id" in result
        assert "tx_reference" in result

    def test_deposit_updates_reserve(self):
        deposit_eur("user1", 500.0, "0xwallet")
        status = get_reserve_status()
        assert status["total_deposits_eur"] == 500.0

    def test_zero_deposit_raises(self):
        with pytest.raises(BankingError):
            deposit_eur("user1", 0, "0xwallet")

    def test_negative_deposit_raises(self):
        with pytest.raises(BankingError):
            deposit_eur("user1", -100.0, "0xwallet")

    def test_deposit_over_limit_raises(self):
        with pytest.raises(BankingError):
            deposit_eur("user1", 1_000_001.0, "0xwallet")

    def test_tx_reference_format(self):
        result = deposit_eur("user1", 100.0, "0xwallet")
        assert result["tx_reference"].startswith("DEP-")


class TestWithdraw:
    def test_basic_withdraw(self):
        result = withdraw_eur("user1", 500.0, "0xwallet", "DE89370400440532013000")
        assert result["status"] == "processing"
        assert result["amount_aegis_eur"] == 500.0
        assert "destination_iban" in result
        assert "****" in result["destination_iban"]

    def test_zero_withdraw_raises(self):
        with pytest.raises(BankingError):
            withdraw_eur("user1", 0, "0xwallet", "DE89370400440532013000")

    def test_invalid_iban_raises(self):
        with pytest.raises(BankingError):
            withdraw_eur("user1", 100.0, "0xwallet", "INVALID")

    def test_iban_masked_in_response(self):
        result = withdraw_eur("user1", 100.0, "0xwallet", "DE89370400440532013000")
        assert "****" in result["destination_iban"]

    def test_tx_reference_format(self):
        result = withdraw_eur("user1", 100.0, "0xwallet", "DE89370400440532013000")
        assert result["tx_reference"].startswith("WIT-")


class TestAccountStatement:
    def test_basic_statement(self):
        from_date = datetime.utcnow() - timedelta(days=30)
        to_date = datetime.utcnow()
        result = get_account_statement("user1", from_date, to_date)
        assert "statement_id" in result
        assert result["statement_id"].startswith("STMT-")
        assert "summary" in result

    def test_statement_with_transactions(self):
        from_date = datetime.utcnow() - timedelta(days=7)
        to_date = datetime.utcnow()
        txns = [
            {"amount": 100.0, "direction": "in"},
            {"amount": 50.0, "direction": "out"},
        ]
        result = get_account_statement("user1", from_date, to_date, txns)
        assert result["summary"]["total_incoming"] == 100.0
        assert result["summary"]["total_outgoing"] == 50.0
        assert result["summary"]["net_change"] == 50.0

    def test_invalid_date_range_raises(self):
        with pytest.raises(BankingError):
            get_account_statement(
                "user1",
                datetime.utcnow(),
                datetime.utcnow() - timedelta(days=1),
            )


class TestSchedulePayment:
    def test_schedule_payment(self):
        future = datetime.utcnow() + timedelta(hours=1)
        result = schedule_payment("user1", "0xfrom", "0xto", 100.0, future)
        assert result["status"] == "pending"
        assert result["is_recurring"] is False
        assert "schedule_id" in result

    def test_past_date_raises(self):
        with pytest.raises(BankingError):
            schedule_payment("user1", "0xfrom", "0xto", 100.0, datetime.utcnow() - timedelta(hours=1))

    def test_zero_amount_raises(self):
        with pytest.raises(BankingError):
            schedule_payment("user1", "0xfrom", "0xto", 0, datetime.utcnow() + timedelta(hours=1))


class TestRecurringPayment:
    def test_monthly_recurring(self):
        result = recurring_payment("user1", "0xfrom", "0xto", 50.0, "monthly")
        assert result["is_recurring"] is True
        assert result["frequency"] == "monthly"
        assert result["status"] == "active"

    def test_invalid_frequency_raises(self):
        with pytest.raises(BankingError):
            recurring_payment("user1", "0xfrom", "0xto", 50.0, "hourly")

    def test_zero_amount_raises(self):
        with pytest.raises(BankingError):
            recurring_payment("user1", "0xfrom", "0xto", 0, "weekly")


class TestReserveStatus:
    def test_initial_reserve_status(self):
        status = get_reserve_status()
        assert status["is_fully_backed"]
        assert status["status"] == "healthy"
        assert "last_audit_hash" in status
        assert status["last_audit_hash"].startswith("0x")

    def test_reserve_after_deposit(self):
        deposit_eur("user1", 1000.0, "0xwallet")
        status = get_reserve_status()
        assert status["total_deposits_eur"] == 1000.0
        assert status["is_fully_backed"]
