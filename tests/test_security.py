"""Security tests: every attack described in the repo review must fail.

Reuses the app, client and in-memory database of test_main_app.
"""

import hashlib
import hmac
import json

import pytest

from tests.test_main_app import _my_wallet, _register_and_login, client  # noqa: F401

import db_models
from db import get_db
from main_app import app


def _TestingSessionLocal():
    """Session on the SAME database the app is using right now (other test modules may
    have replaced the get_db override)."""
    gen = app.dependency_overrides.get(get_db, get_db)()
    return next(gen)

OTHER = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"


def _set_role(username: str, role: str, authority_type=None) -> None:
    """Bootstrap via the database (as scripts/create_admin.py does in production)."""
    db = _TestingSessionLocal()
    u = db.query(db_models.User).filter(db_models.User.username == username).one()
    u.role, u.authority_type = role, authority_type
    db.commit()
    db.close()


def _user_id(username: str) -> int:
    db = _TestingSessionLocal()
    uid = db.query(db_models.User).filter(db_models.User.username == username).one().id
    db.close()
    return uid


def _login(client, username: str) -> dict:
    r = client.post("/auth/login", json={"username": username, "password": "SecurePass123!"})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


# ---------------------------------------------------------------- ownership (IDOR)

def test_cannot_send_from_someone_elses_address(client):
    """A tx signed by a key whose address is not linked to the account is refused."""
    from eth_account import Account

    from tests.test_main_app import _signed_transfer

    h = _register_and_login(client, "_idor_tx")
    stranger = Account.create()
    r = client.post("/transactions/send", json={"signed_tx": _signed_transfer(stranger, "0x" + "12" * 20, 1.0)}, headers=h)
    assert r.status_code == 403


def test_cannot_read_someone_elses_history_or_audit(client):
    alice = _register_and_login(client, "_idor_a")
    bob = _register_and_login(client, "_idor_b")
    addr = _my_wallet(client, alice)
    assert client.get(f"/wallet/transactions/{addr}", headers=alice).status_code == 200
    assert client.get(f"/wallet/transactions/{addr}", headers=bob).status_code == 403
    assert client.get(f"/viewing-keys/v2/{addr}/audit", headers=bob).status_code == 403
    assert client.get(f"/regulatory/requests/{addr}", headers=bob).status_code == 403


def test_banking_and_bridge_require_ownership(client):
    h = _register_and_login(client, "_idor_bank")
    assert client.post("/banking/deposit", json={"amount": 10, "wallet_address": OTHER}, headers=h).status_code == 403
    r = client.post("/api/v1/bridge/initiate", json={
        "source_chain": "polygon", "dest_chain": "ethereum", "token_address": OTHER,
        "amount": 1, "recipient": OTHER, "sender": OTHER}, headers=h)
    assert r.status_code == 403


def test_address_cannot_be_claimed_twice(client):
    """Even someone holding the key cannot move an address that is already linked to another account."""
    from eth_account import Account
    from eth_account.messages import encode_defunct

    from tests.test_main_app import _link

    a = _register_and_login(client, "_claim_a")
    b = _register_and_login(client, "_claim_b")
    acct = Account.create()
    _link(client, a, acct)
    ch = client.post("/wallet/link/challenge", headers=b).json()
    sig = acct.sign_message(encode_defunct(text=ch["message"])).signature.hex()
    r = client.post("/wallet/link", json={"address": acct.address, "nonce": ch["nonce"], "signature": sig}, headers=b)
    assert r.status_code == 409


# ---------------------------------------------------------------- KYC

KYC = {"full_name": "Mario Rossi", "date_of_birth": "1990-01-15", "country": "IT", "id_document_hash": "0x" + "a" * 64}


def test_kyc_cannot_be_self_approved(client):
    h = _register_and_login(client, "_kyc_self")
    uid = _user_id("testuser_kyc_self")
    assert client.post("/compliance/kyc", json=KYC, headers=h).json()["kyc_verified"] is False
    r = client.post(f"/compliance/kyc/{uid}/decision", json={"approved": True, "tier": 3}, headers=h)
    assert r.status_code == 403
    assert client.get("/compliance/profile", headers=h).json()["kyc_verified"] is False


def test_compliance_officer_approves_but_not_themselves(client):
    user = _register_and_login(client, "_kyc_u")
    _register_and_login(client, "_kyc_officer")
    _set_role("testuser_kyc_officer", "compliance")
    officer = _login(client, "testuser_kyc_officer")
    uid = _user_id("testuser_kyc_u")
    client.post("/compliance/kyc", json=KYC, headers=user)
    r = client.post(f"/compliance/kyc/{uid}/decision", json={"approved": True, "tier": 2}, headers=officer)
    assert r.status_code == 200 and r.json()["kyc_verified"] is True
    assert client.get("/compliance/profile", headers=user).json()["kyc_tier"] == 2
    own = _user_id("testuser_kyc_officer")
    assert client.post(f"/compliance/kyc/{own}/decision", json={"approved": True}, headers=officer).status_code == 403


def test_kyc_webhook_requires_valid_signature(client, monkeypatch):
    secret = "w" * 40
    monkeypatch.setenv("KYC_WEBHOOK_SECRET", secret)
    _register_and_login(client, "_kyc_hook")
    uid = _user_id("testuser_kyc_hook")
    body = json.dumps({"user_id": uid, "approved": True, "tier": 1, "provider_ref": "sumsub-123"}).encode()
    bad = client.post("/compliance/kyc/webhook", content=body, headers={"X-KYC-Signature": "00" * 32})
    assert bad.status_code == 401
    sig = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    ok = client.post("/compliance/kyc/webhook", content=body, headers={"X-KYC-Signature": sig})
    assert ok.status_code == 200 and ok.json()["kyc_verified"] is True


# ---------------------------------------------------------------- regulatory flow

def _request_body(owner: str) -> dict:
    return {"requester_id": "spoofed", "requester_type": "judicial_authority", "owner_address": owner,
            "tx_hash": "0x" + "ab" * 32, "scope": "single_tx", "duration_days": 30,
            "legal_reference": "D.lgs. 231/2007 art. 6", "reason": "verifica"}


def test_only_authorities_request_access_and_identity_comes_from_account(client):
    owner = _register_and_login(client, "_reg_owner")
    addr = _my_wallet(client, owner)
    plain = _register_and_login(client, "_reg_plain")
    assert client.post("/regulatory/request-access", json=_request_body(addr), headers=plain).status_code == 403

    _register_and_login(client, "_reg_uif")
    _set_role("testuser_reg_uif", "authority", "uif")
    uif = _login(client, "testuser_reg_uif")
    r = client.post("/regulatory/request-access", json=_request_body(addr), headers=uif)
    assert r.status_code == 200, r.text
    req = r.json()
    assert req["requester_type"] == "uif"  # not "judicial_authority" as written in the body
    assert req["requester_id"] == str(_user_id("testuser_reg_uif"))

    # A third party cannot approve or see the request; the owner can.
    rid = req["request_id"]
    intruder = _register_and_login(client, "_reg_intruder")
    approve = {"owner_address": addr, "scope": "single_tx", "duration_days": 7}
    assert client.post(f"/regulatory/requests/{rid}/approve", json=approve, headers=intruder).status_code == 403
    assert client.get(f"/regulatory/requests/detail/{rid}", headers=intruder).status_code == 403
    assert client.get(f"/regulatory/requests/detail/{rid}", headers=uif).status_code == 200
    r = client.post(f"/regulatory/requests/{rid}/approve", json=approve, headers=owner)
    assert r.status_code == 200, r.text


# ---------------------------------------------------------------- login and tokens

def test_login_lockout_after_repeated_failures(client):
    _register_and_login(client, "_brute")
    for _ in range(5):
        assert client.post("/auth/login", json={"username": "testuser_brute", "password": "wrong"}).status_code == 401
    r = client.post("/auth/login", json={"username": "testuser_brute", "password": "SecurePass123!"})
    assert r.status_code == 429


def test_attacker_cannot_lock_out_the_real_user_from_another_ip(client):
    """5 failures from the attacker's IP do not block the legitimate user who comes from another IP."""
    from fastapi.testclient import TestClient

    from main_app import app

    _register_and_login(client, "_victim")
    attacker = TestClient(app, client=("203.0.113.66", 5000))
    victim = TestClient(app, client=("198.51.100.7", 5000))
    for _ in range(5):
        attacker.post("/auth/login", json={"username": "testuser_victim", "password": "wrong"})
    assert attacker.post("/auth/login", json={"username": "testuser_victim", "password": "SecurePass123!"}).status_code == 429
    assert victim.post("/auth/login", json={"username": "testuser_victim", "password": "SecurePass123!"}).status_code == 200


def test_logout_revokes_tokens(client):
    h = _register_and_login(client, "_logout")
    assert client.get("/auth/me", headers=h).status_code == 200
    assert client.post("/auth/logout", headers=h).status_code == 200
    assert client.get("/auth/me", headers=h).status_code == 401


def test_roles_only_assigned_by_admin(client):
    h = _register_and_login(client, "_wannabe")
    uid = _user_id("testuser_wannabe")
    assert client.post(f"/admin/users/{uid}/role", json={"role": "admin"}, headers=h).status_code == 403
    _register_and_login(client, "_admin")
    _set_role("testuser_admin", "admin")
    admin = _login(client, "testuser_admin")
    r = client.post(f"/admin/users/{uid}/role", json={"role": "authority", "authority_type": "tax_authority"}, headers=admin)
    assert r.status_code == 200
    # the old token is revoked by the role change
    assert client.get("/auth/me", headers=h).status_code == 401
    assert client.get("/auth/me", headers=_login(client, "testuser_wannabe")).json()["role"] == "authority"


def test_operator_only_endpoints(client):
    h = _register_and_login(client, "_op")
    body = {"bundle_id": "b1", "merkle_root": "0x" + "00" * 32, "tx_count": 1}
    assert client.post("/api/v1/settlement/submit-bundle", json=body, headers=h).status_code == 403
    assert client.get("/api/v1/reporting/compliance-report", headers=h).status_code == 403


@pytest.mark.parametrize("token", ["", "Bearer abc", "Bearer " + "x" * 200])
def test_garbage_tokens_rejected(client, token):
    assert client.get("/auth/me", headers={"Authorization": token}).status_code == 401
