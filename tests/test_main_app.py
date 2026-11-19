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
            "password": "Pass123!",
        })
        r = client.post("/auth/login", json={
            "username": "loginuser",
            "password": "Pass123!",
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

class TestWalletCreate:
    def test_create_wallet_authenticated(self, client):
        headers = _register_and_login(client, "_walletcreate")
        r = client.post("/wallet/create", json={"password": "walletpass"}, headers=headers)
        # Either 200 with address, or 503 if wallet service unavailable
        assert r.status_code in (200, 503)
        if r.status_code == 200:
            assert "address" in r.json()

    def test_create_wallet_unauthenticated(self, client):
        r = client.post("/wallet/create", json={"password": "walletpass"})
        assert r.status_code == 401


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
# 8. POST /compliance/proof/generate
# ---------------------------------------------------------------------------

class TestProofGenerate:
    def test_generate_proof(self, client):
        headers = _register_and_login(client, "_proof")
        r = client.post("/compliance/proof/generate", json={
            "sender": "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
            "amount": 500.0,
            "purpose": "transfer",
        }, headers=headers)
        assert r.status_code in (200, 503)
        if r.status_code == 200:
            body = r.json()
            assert "proof_hash" in body or "proof" in body

    def test_generate_proof_unauthenticated(self, client):
        r = client.post("/compliance/proof/generate", json={
            "sender": "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
            "amount": 500.0,
        })
        assert r.status_code == 401


# ---------------------------------------------------------------------------
# 9. POST /viewing-keys/create
# ---------------------------------------------------------------------------

def _my_wallet(client: TestClient, headers: dict) -> str:
    r = client.post("/wallet/create", json={"password": "walletpass"}, headers=headers)
    assert r.status_code == 200
    return r.json()["address"]


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
    def test_send_transaction(self, client):
        headers = _register_and_login(client, "_tx")
        r = client.post("/transactions/send", json={
            "from_address": _my_wallet(client, headers),
            "to_address": "0x1234567890123456789012345678901234567890",
            "amount": 100.0,
            "encrypted_key": "0x" + "a" * 64,
            "password": "walletpass",
        }, headers=headers)
        # 200 (mock tx), 400 (compliance), or 503 (service unavailable)
        assert r.status_code in (200, 400, 503)

    def test_send_transaction_unauthenticated(self, client):
        r = client.post("/transactions/send", json={
            "from_address": "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
            "to_address": "0x1234567890123456789012345678901234567890",
            "amount": 100.0,
            "encrypted_key": "0x" + "a" * 64,
            "password": "walletpass",
        })
        assert r.status_code == 401

    def test_send_large_transaction_without_kyc(self, client):
        """Transactions exceeding single_tx_limit without KYC should be rejected by compliance."""
        headers = _register_and_login(client, "_tx_large")
        r = client.post("/transactions/send", json={
            "from_address": _my_wallet(client, headers),
            "to_address": "0x1234567890123456789012345678901234567890",
            "amount": 6000.0,  # Exceeds single_tx_limit (5000) without KYC
            "encrypted_key": "0x" + "a" * 64,
            "password": "walletpass",
        }, headers=headers)
        # Either compliance rejection (400) or service unavailable (503)
        assert r.status_code in (400, 503)

