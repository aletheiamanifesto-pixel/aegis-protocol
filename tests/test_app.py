"""
Tests for the AEGIS Protocol FastAPI application.
"""

import time

import pytest
from fastapi.testclient import TestClient

from main_app import app


client = TestClient(app)


def _make_tx_payload(**overrides):
    """Return a valid EuroDigitalTransaction payload with optional overrides."""
    payload = {
        "tx_hash": "0xabc123",
        "sender": "0x1111111111111111111111111111111111111111",
        "recipient_hash": "0x2222222222222222222222222222222222222222",
        "amount": 500.0,
        "timestamp": int(time.time()),
        "nonce": 0,
    }
    payload.update(overrides)
    return payload


# --------------------------------------------------------------------------- #
# Health / root
# --------------------------------------------------------------------------- #


def test_root():
    resp = client.get("/")
    assert resp.status_code == 200
    data = resp.json()
    assert data["service"] == "AEGIS Protocol"
    assert data["status"] == "running"


def test_health():
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


# --------------------------------------------------------------------------- #
# POST /transaction – compliant scenarios
# --------------------------------------------------------------------------- #


def test_transaction_below_threshold():
    """Amount < 1000 EUR → compliant without proof."""
    resp = client.post("/transaction", json=_make_tx_payload(amount=999.99))
    assert resp.status_code == 200
    data = resp.json()
    assert data["compliant"] is True
    assert data["status"] == "verified"


def test_transaction_at_threshold_with_proof():
    """Amount >= 1000 EUR with proof_hash → compliant."""
    resp = client.post(
        "/transaction",
        json=_make_tx_payload(amount=1000.0, proof_hash="0xproof"),
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["compliant"] is True


# --------------------------------------------------------------------------- #
# POST /transaction – non-compliant scenarios
# --------------------------------------------------------------------------- #


def test_transaction_at_threshold_without_proof():
    """Amount >= 1000 EUR without proof_hash → rejected."""
    resp = client.post(
        "/transaction",
        json=_make_tx_payload(amount=1500.0, proof_hash=None),
    )
    assert resp.status_code == 422
    detail = resp.json()["detail"]
    assert detail["compliant"] is False
    assert any("MICA_PROOF_REQUIRED" in f for f in detail["flags"])


def test_transaction_invalid_payload():
    """Missing required fields → 422 validation error."""
    resp = client.post("/transaction", json={"amount": 10})
    assert resp.status_code == 422
