"""Second factor: RFC 6238, anti-replay, login and withdrawals."""

import time

import totp
from tests.test_main_app import _my_wallet, _register_and_login, client  # noqa: F401

RFC_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"  # "12345678901234567890"


def test_rfc6238_vectors():
    assert totp.code_at(RFC_SECRET, 59) == "287082"
    assert totp.code_at(RFC_SECRET, 1111111109) == "081804"
    assert totp.code_at(RFC_SECRET, 2000000000) == "279037"


def test_code_cannot_be_replayed():
    s = totp.new_secret()
    now = 1_800_000_000
    step = totp.verify(s, totp.code_at(s, now), now=now)
    assert step is not None
    assert totp.verify(s, totp.code_at(s, now), last_step=step, now=now) is None


def _enable_2fa(client, headers):
    secret = client.post("/auth/2fa/setup", headers=headers).json()["secret"]
    r = client.post("/auth/2fa/enable", json={"code": totp.code_at(secret, time.time())}, headers=headers)
    assert r.status_code == 200, r.text
    return secret


def test_login_requires_code_after_enabling(client):
    h = _register_and_login(client, "_2fa_login")
    secret = _enable_2fa(client, h)
    assert client.get("/auth/me", headers=h).status_code == 401  # old sessions closed
    creds = {"username": "testuser_2fa_login", "password": "SecurePass123!"}
    assert client.post("/auth/login", json=creds).status_code == 401
    # the code used for enabling cannot be reused: the next one is needed
    r = client.post("/auth/login", json={**creds, "totp_code": totp.code_at(secret, time.time() + 30)})
    assert r.status_code == 200, r.text


def test_withdrawal_requires_2fa(client):
    h = _register_and_login(client, "_2fa_wd")
    addr = _my_wallet(client, h)
    body = {"amount": 10, "wallet_address": addr, "iban": "IT60X0542811101000000123456", "totp_code": "000000"}
    r = client.post("/banking/withdraw", json=body, headers=h)
    assert r.status_code == 403 and "two-factor" in r.json()["detail"].lower()
