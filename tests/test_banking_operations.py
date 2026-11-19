#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""banking_operations: state in the DB, Decimal, idempotency, deposits only on bank confirmation."""

import hashlib
import hmac
import json
from datetime import datetime, timedelta
from decimal import Decimal

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import banking_operations as bo
import db_models

IBAN = "IT60X0542811101000000123456"  # valid IBAN (example)
WALLET = "0x" + "ab" * 20


@pytest.fixture
def db():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    db_models.Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine)()
    s.add(db_models.User(id=1, username="u1", email="u1@example.com", hashed_password="x"))
    s.commit()
    yield s
    s.close()


class TestMoney:
    def test_no_float_rounding(self):
        assert bo.to_money("0.1") + bo.to_money("0.2") == Decimal("0.30")

    @pytest.mark.parametrize("bad", ["1.001", "NaN", "inf", "abc"])
    def test_invalid_amounts(self, bad):
        with pytest.raises(bo.BankingError):
            bo.to_money(bad)


class TestDeposit:
    def test_deposit_is_not_completed_without_bank(self, db):
        r = bo.create_deposit(db, 1, "1000.00", WALLET)
        assert r["status"] == "awaiting_funds"
        assert r["reference"].startswith("DEP-")
        assert "SEPA" in r["instructions"]
        assert bo.get_reserve_status(db)["total_deposits_eur"] == "0.00"

    def test_confirmation_completes_and_is_idempotent(self, db):
        ref = bo.create_deposit(db, 1, "250.10", WALLET)["reference"]
        assert bo.confirm_deposit(db, ref, "250.10", "BANK-1")["status"] == "completed"
        assert bo.confirm_deposit(db, ref, "250.10", "BANK-1")["status"] == "completed"
        assert bo.get_reserve_status(db)["total_deposits_eur"] == "250.10"

    def test_wrong_amount_goes_to_review(self, db):
        ref = bo.create_deposit(db, 1, "100.00", WALLET)["reference"]
        with pytest.raises(bo.BankingError):
            bo.confirm_deposit(db, ref, "99.99", "BANK-2")
        assert bo.get_reserve_status(db)["total_deposits_eur"] == "0.00"

    def test_retry_with_same_idempotency_key_does_not_duplicate(self, db):
        a = bo.create_deposit(db, 1, "10.00", WALLET, idempotency_key="k-1")
        b = bo.create_deposit(db, 1, "10.00", WALLET, idempotency_key="k-1")
        assert a["operation_id"] == b["operation_id"]
        assert db.query(db_models.BankOperation).count() == 1

    @pytest.mark.parametrize("amount", ["0", "-5", "1000000.01"])
    def test_limits(self, db, amount):
        with pytest.raises(bo.BankingError):
            bo.create_deposit(db, 1, amount, WALLET)


class TestWithdrawal:
    def test_withdrawal_binds_escrow_to_iban_without_putting_it_on_chain(self, db):
        r = bo.create_withdrawal(db, 1, "50.00", WALLET, IBAN)
        assert r["status"] == "awaiting_escrow"
        assert r["destination_iban"] == "IT****56"
        assert r["payout_ref_hash"].startswith("0x") and IBAN not in json.dumps(r)

    def test_invalid_iban_rejected(self, db):
        with pytest.raises(bo.BankingError):
            bo.create_withdrawal(db, 1, "50.00", WALLET, "IT60X0542811101000000123457")  # wrong checksum


class TestStatementAndSchedules:
    def test_statement_from_db(self, db):
        ref = bo.create_deposit(db, 1, "100.00", WALLET)["reference"]
        bo.confirm_deposit(db, ref, "100.00", "B")
        st = bo.get_account_statement(db, 1, datetime.utcnow() - timedelta(days=1), datetime.utcnow() + timedelta(days=1))
        assert st["summary"]["total_in"] == "100.00" and len(st["operations"]) == 1

    def test_schedule_and_recurring_persisted(self, db):
        bo.schedule_payment(db, 1, WALLET, "0x" + "cd" * 20, "5.00", datetime.utcnow() + timedelta(days=1))
        bo.recurring_payment(db, 1, WALLET, "0x" + "cd" * 20, "7.50", "monthly")
        assert db.query(db_models.ScheduledPayment).count() == 2
        with pytest.raises(bo.BankingError):
            bo.recurring_payment(db, 1, WALLET, "0x" + "cd" * 20, "7.50", "hourly")


class TestBankingApi:
    """Via the API: signed bank webhook, no token issued without confirmation."""

    def test_webhook_signature_and_flow(self, monkeypatch):
        from tests.test_main_app import _my_wallet, _register_and_login, client  # noqa: F401
        from fastapi.testclient import TestClient

        from main_app import app

        c = TestClient(app)
        h = _register_and_login(c, "_bank_api")
        addr = _my_wallet(c, h)
        r = c.post("/banking/deposit", json={"amount": "12.34", "wallet_address": addr}, headers={**h, "Idempotency-Key": "abc"})
        assert r.status_code == 201, r.text
        dep = r.json()
        assert c.post("/banking/deposit", json={"amount": "12.34", "wallet_address": addr},
                      headers={**h, "Idempotency-Key": "abc"}).json()["operation_id"] == dep["operation_id"]

        secret = "s" * 40
        monkeypatch.setenv("BANK_WEBHOOK_SECRET", secret)
        body = json.dumps({"reference": dep["reference"], "amount": "12.34", "bank_tx_id": "SEPA-9"}).encode()
        assert c.post("/banking/webhook/deposit", content=body, headers={"X-Bank-Signature": "0" * 64}).status_code == 401
        sig = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
        ok = c.post("/banking/webhook/deposit", content=body, headers={"X-Bank-Signature": sig})
        assert ok.status_code == 200 and ok.json()["status"] == "completed"

    def test_float_with_too_many_decimals_rejected(self):
        from fastapi.testclient import TestClient

        from main_app import app
        from tests.test_main_app import _my_wallet, _register_and_login

        c = TestClient(app)
        h = _register_and_login(c, "_bank_dec")
        addr = _my_wallet(c, h)
        assert c.post("/banking/deposit", json={"amount": "1.005", "wallet_address": addr}, headers=h).status_code == 422
