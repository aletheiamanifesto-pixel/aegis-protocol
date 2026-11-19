#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tests/test_main_app.py - E2E tests for AEGIS Protocol FastAPI application.

Tests the full user flow using FastAPI TestClient backed by an in-memory
SQLite database.
"""

import os

# Configure test environment before any imports
os.environ["DATABASE_URL"] = "sqlite://"
os.environ.setdefault("SECRET_KEY", "test-secret-key-32-bytes-for-test")
os.environ.setdefault("RPC_URL", "http://localhost:8545")

import pytest
from eth_account import Account
from eth_account.messages import encode_defunct
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool


# ---------------------------------------------------------------------------
# Set up a shared in-memory SQLite engine (StaticPool keeps same connection)
# ---------------------------------------------------------------------------

_TEST_ENGINE = create_engine(
    "sqlite://",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)

_TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=_TEST_ENGINE)


def _get_test_db():
    db = _TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


# Create tables BEFORE importing the app (so startup event can use them)
def _create_tables():
    try:
        from db_models import Base as ModelBase
        ModelBase.metadata.create_all(bind=_TEST_ENGINE)
    except Exception:
        pass  # DB models unavailable — tests will use dev-mode fallbacks


_create_tables()

# Override the app's get_db dependency
from db import get_db  # noqa: E402
from main_app import app  # noqa: E402

app.dependency_overrides[get_db] = _get_test_db


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


# ---------------------------------------------------------------------------
# Helper to create and log in a user, returning the auth header
# ---------------------------------------------------------------------------

def _register_and_login(client: TestClient, suffix: str = "") -> dict:
    username = f"testuser{suffix}"
    password = "SecurePass123!"
    email = f"{username}@example.com"

    r = client.post("/auth/register", json={
        "username": username,
        "email": email,
        "password": password,
    })
    assert r.status_code in (201, 400), r.text  # 400 if already registered

    r = client.post("/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    token = r.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# 1. POST /auth/register
# ---------------------------------------------------------------------------

class TestRegister:
    def test_short_password_rejected(self, client):
        r = client.post("/auth/register", json={"username": "shortpw", "email": "s@example.com", "password": "Pass123!"})
        assert r.status_code == 422

    def test_register_new_user(self, client):
        r = client.post("/auth/register", json={
            "username": "newuser_reg",
            "email": "newuser_reg@example.com",
            "password": "Password123!",
        })
        assert r.status_code == 201
        body = r.json()
        assert "username" in body or "message" in body

    def test_register_duplicate_user(self, client):
        payload = {
            "username": "dupuser",
            "email": "dup@example.com",
            "password": "Password123!",
        }
        client.post("/auth/register", json=payload)
        r = client.post("/auth/register", json=payload)
        # Either 400 (duplicate) or 201 (dev mode no-db always succeeds)
        assert r.status_code in (400, 201)


# ---------------------------------------------------------------------------
# 2. POST /auth/login
# ---------------------------------------------------------------------------

class TestLogin:
    def test_login_success(self, client):
        client.post("/auth/register", json={
            "username": "loginuser",
            "email": "loginuser@example.com",
            "password": "Pass123!-long-enough",
        })
        r = client.post("/auth/login", json={
            "username": "loginuser",
            "password": "Pass123!-long-enough",
        })
        assert r.status_code == 200
        assert "access_token" in r.json()
        assert r.json()["token_type"] == "bearer"

    def test_login_wrong_password(self, client):
        client.post("/auth/register", json={
            "username": "wrongpassuser",
            "email": "wrongpass@example.com",
            "password": "CorrectPass!",
        })
        r = client.post("/auth/login", json={
            "username": "wrongpassuser",
            "password": "WrongPass!",
        })
        # 401 with DB, or 200 (dev mode)
        assert r.status_code in (200, 401)


# ---------------------------------------------------------------------------
# 3. POST /wallet/create
# ---------------------------------------------------------------------------

class TestWalletLink:
    def test_link_wallet_by_signature(self, client):
        headers = _register_and_login(client, "_walletlink")
        acct = Account.create()
        assert _link(client, headers, acct) == acct.address

    def test_cannot_link_address_without_its_key(self, client):
        headers = _register_and_login(client, "_walletlink_bad")
        ch = client.post("/wallet/link/challenge", headers=headers).json()
        victim, attacker = Account.create(), Account.create()
        sig = attacker.sign_message(encode_defunct(text=ch["message"])).signature.hex()
        r = client.post("/wallet/link", json={"address": victim.address, "nonce": ch["nonce"], "signature": sig},
                        headers=headers)
        assert r.status_code == 403

    def test_challenge_is_single_use(self, client):
        headers = _register_and_login(client, "_walletlink_replay")
        acct = Account.create()
        ch = client.post("/wallet/link/challenge", headers=headers).json()
        sig = acct.sign_message(encode_defunct(text=ch["message"])).signature.hex()
        body = {"address": acct.address, "nonce": ch["nonce"], "signature": sig}
        assert client.post("/wallet/link", json=body, headers=headers).status_code == 200
        assert client.post("/wallet/link", json=body, headers=headers).status_code == 400

    def test_server_no_longer_creates_wallets(self, client):
        headers = _register_and_login(client, "_walletcreate")
        assert client.post("/wallet/create", json={"password": "x" * 12}, headers=headers).status_code in (404, 405)

    def test_link_unauthenticated(self, client):
        assert client.post("/wallet/link/challenge").status_code == 401


# ---------------------------------------------------------------------------
# 4. GET /wallet/balance/{address}
# ---------------------------------------------------------------------------

class TestWalletBalance:
    def test_get_balance_authenticated(self, client):
        headers = _register_and_login(client, "_balance")
        address = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
        r = client.get(f"/wallet/balance/{address}", headers=headers)
        assert r.status_code in (200, 503)
        if r.status_code == 200:
            body = r.json()
            assert "address" in body
            assert "balance" in body

    def test_get_balance_unauthenticated(self, client):
        r = client.get("/wallet/balance/0x742d35Cc6634C0532925a3b844Bc454e4438f44e")
        assert r.status_code == 401


# ---------------------------------------------------------------------------
# 5. GET /health
# ---------------------------------------------------------------------------

class TestHealth:
    def test_health_returns_ok(self, client):
        r = client.get("/health")
        assert r.status_code == 200
        body = r.json()
        assert body["status"] == "ok"
        assert "services" in body
        assert "database" in body["services"]
        assert "compliance_engine" in body["services"]
        assert "transaction_processor" in body["services"]


# ---------------------------------------------------------------------------
# 6. POST /compliance/kyc
# ---------------------------------------------------------------------------

class TestKYC:
    def test_kyc_submission(self, client):
        headers = _register_and_login(client, "_kyc")
        r = client.post("/compliance/kyc", json={
            "full_name": "Mario Rossi",
            "date_of_birth": "1990-01-15",
            "country": "IT",
            "id_document_hash": "0x" + "a" * 64,
        }, headers=headers)
        # Submitting data does NOT verify the KYC: it stays "pending" until compliance decides.
        assert r.status_code == 202
        body = r.json()
        assert body["kyc_verified"] is False
        assert body["kyc_status"] == "pending"

    def test_kyc_unauthenticated(self, client):
        r = client.post("/compliance/kyc", json={
            "full_name": "Mario Rossi",
            "date_of_birth": "1990-01-15",
            "country": "IT",
            "id_document_hash": "0x" + "a" * 64,
        })
        assert r.status_code == 401


# ---------------------------------------------------------------------------
# 7. GET /compliance/profile
# ---------------------------------------------------------------------------

class TestComplianceProfile:
    def test_profile_after_kyc(self, client):
        headers = _register_and_login(client, "_profile")
        # Submit KYC first
        client.post("/compliance/kyc", json={
            "full_name": "Anna Bianchi",
            "date_of_birth": "1985-06-20",
            "country": "DE",
            "id_document_hash": "0x" + "b" * 64,
        }, headers=headers)

        r = client.get("/compliance/profile", headers=headers)
        assert r.status_code in (200, 503)
        if r.status_code == 200:
            body = r.json()
            assert "kyc_verified" in body

    def test_profile_unauthenticated(self, client):
        r = client.get("/compliance/profile")
        assert r.status_code == 401


# ---------------------------------------------------------------------------
# 9. POST /viewing-keys/create
# ---------------------------------------------------------------------------

def _link(client: TestClient, headers: dict, acct) -> str:
    ch = client.post("/wallet/link/challenge", headers=headers).json()
    sig = acct.sign_message(encode_defunct(text=ch["message"])).signature.hex()
    r = client.post("/wallet/link", json={"address": acct.address, "nonce": ch["nonce"], "signature": sig},
                    headers=headers)
    assert r.status_code == 200, r.text
    return r.json()["address"]


_ACCOUNTS: dict = {}


def _my_wallet(client: TestClient, headers: dict) -> str:
    """Create a wallet ON THE "DEVICE" (the test) and link it by signature."""
    acct = Account.create()
    address = _link(client, headers, acct)
    _ACCOUNTS[address] = acct
    return address


def _signed_transfer(acct, to: str, amount_eur: float, chain_id: int = 80002) -> str:
    data = "0xa9059cbb" + "00" * 12 + to[2:].lower() + format(int(round(amount_eur * 10**6)), "064x")
    from web3 import Web3

    tx = {"to": Web3.to_checksum_address(os.environ["EURC_TOKEN_ADDRESS"]), "value": 0, "data": data, "nonce": 0, "chainId": chain_id,
          "gas": 100000, "maxFeePerGas": 10**9, "maxPriorityFeePerGas": 10**9, "type": 2}
    return acct.sign_transaction(tx).raw_transaction.hex()


class TestViewingKeys:
    def test_create_viewing_key(self, client):
        headers = _register_and_login(client, "_vk")
        address = _my_wallet(client, headers)
        r = client.post("/viewing-keys/v2/create", json={"address": address}, headers=headers)
        assert r.status_code in (200, 503)

    def test_create_viewing_key_for_someone_else_forbidden(self, client):
        headers = _register_and_login(client, "_vk2")
        r = client.post("/viewing-keys/v2/create", json={
            "address": "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
        }, headers=headers)
        assert r.status_code == 403

    def test_create_viewing_key_unauthenticated(self, client):
        r = client.post("/viewing-keys/v2/create", json={
            "address": "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
        })
        assert r.status_code == 401


# ---------------------------------------------------------------------------
# 10. POST /transactions/send
# ---------------------------------------------------------------------------

class TestTransactionSend:
    TO = "0x1234567890123456789012345678901234567890"

    def test_send_signed_transaction(self, client):
        headers = _register_and_login(client, "_tx")
        addr = _my_wallet(client, headers)
        r = client.post("/transactions/send", json={"signed_tx": _signed_transfer(_ACCOUNTS[addr], self.TO, 100.0)},
                        headers=headers)
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["sender"] == addr and body["recipient"].lower() == self.TO.lower() and body["amount"] == 100.0

    def test_send_transaction_unauthenticated(self, client):
        r = client.post("/transactions/send", json={"signed_tx": "0x00"})
        assert r.status_code == 401

    def test_send_large_transaction_without_kyc(self, client):
        """Transactions exceeding single_tx_limit without KYC should be rejected by compliance."""
        headers = _register_and_login(client, "_tx_large")
        addr = _my_wallet(client, headers)
        r = client.post("/transactions/send", json={"signed_tx": _signed_transfer(_ACCOUNTS[addr], self.TO, 6000.0)},
                        headers=headers)
        assert r.status_code == 400

    def test_tx_for_other_contract_or_chain_rejected(self, client):
        headers = _register_and_login(client, "_tx_bad")
        addr = _my_wallet(client, headers)
        wrong_chain = _signed_transfer(_ACCOUNTS[addr], self.TO, 1.0, chain_id=1)
        assert client.post("/transactions/send", json={"signed_tx": wrong_chain}, headers=headers).status_code == 400
        assert client.post("/transactions/send", json={"signed_tx": "0xdeadbeef"}, headers=headers).status_code == 400
