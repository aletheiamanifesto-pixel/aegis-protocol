"""KYC credentials for the ZK circuit and relayer: only verified customers, data from the verification."""

import shutil
import subprocess
from pathlib import Path

import pytest

import pool_service
from tests.test_security import _login, _set_role, _user_id  # noqa: F401
from tests.test_main_app import _register_and_login, client  # noqa: F401

ROOT = Path(__file__).resolve().parent.parent
PSEUDONYM = "0x" + "1f" * 31


def _verified_user(client, suffix, country="IT", tier=2):
    h = _register_and_login(client, suffix)
    _register_and_login(client, suffix + "_off")
    _set_role(f"testuser{suffix}_off", "compliance")
    officer = _login(client, f"testuser{suffix}_off")
    uid = _user_id(f"testuser{suffix}")
    r = client.post(f"/compliance/kyc/{uid}/decision", json={"approved": True, "tier": tier, "country": country}, headers=officer)
    assert r.status_code == 200, r.text
    return h


def test_unverified_user_gets_no_credential(client):
    h = _register_and_login(client, "_pool_nokyc")
    assert client.post("/pool/credential", json={"pseudonym": PSEUDONYM}, headers=h).status_code == 403


def test_credential_is_valid_schnorr_over_poseidon2(client):
    from crypto_primitives import schnorr_verify

    h = _verified_user(client, "_pool_ok")
    r = client.post("/pool/credential", json={"pseudonym": PSEUDONYM}, headers=h)
    assert r.status_code == 200, r.text
    c = r.json()
    assert c["tier"] == 2 and c["jurisdiction"] == 0  # from the verification, not from the request
    assert c["expiry"] - __import__("time").time() <= 86_400 + 5  # 24-hour credentials
    msg = pool_service.credential_hash(int(c["pseudonym"], 16), c["tier"], c["jurisdiction"], c["expiry"], int(c["person_tag"], 16))
    sig = c["signature"]
    pub = (int(c["issuer"]["x"]), int(c["issuer"]["y"]))
    rpt = (int(sig["r"]["x"]), int(sig["r"]["y"]))
    s_full = int(sig["s_lo"], 16) + (int(sig["s_hi"], 16) << 128)
    assert schnorr_verify(pub, msg, rpt, s_full)
    assert not schnorr_verify(pub, msg + 1, rpt, s_full)


def test_same_person_tag_on_every_pseudonym(client):
    """The rate limit is per PERSON: two pseudonyms of the same customer share the tag."""
    h = _verified_user(client, "_pool_tag")
    a = client.post("/pool/credential", json={"pseudonym": "0x" + "41" * 31}, headers=h).json()
    b = client.post("/pool/credential", json={"pseudonym": "0x" + "42" * 31}, headers=h).json()
    assert a["person_tag"] == b["person_tag"]
    other = _verified_user(client, "_pool_tag2")
    c = client.post("/pool/credential", json={"pseudonym": "0x" + "43" * 31}, headers=other).json()
    assert c["person_tag"] != a["person_tag"]


def test_pseudonym_cannot_be_reused_by_another_customer(client):
    a = _verified_user(client, "_pool_a")
    b = _verified_user(client, "_pool_b")
    p = "0x" + "2e" * 31
    assert client.post("/pool/credential", json={"pseudonym": p}, headers=a).status_code == 200
    assert client.post("/pool/credential", json={"pseudonym": p}, headers=b).status_code == 409


def test_unsupported_jurisdiction_rejected(client):
    h = _verified_user(client, "_pool_us", country="US")
    assert client.post("/pool/credential", json={"pseudonym": PSEUDONYM[:-2] + "aa"}, headers=h).status_code == 400


def _relay_body(relayer, fee=0, public_out=0):
    z = "0"
    return {"proof": {"proof": "0x00", "root": "1", "nullifiers": ["2", "3"], "outCommitments": ["4", "5"],
                      "publicIn": 0, "publicOut": public_out, "timestamp": 1, "issuer": {"x": z, "y": z},
                      "taxEph": {"x": z, "y": z}, "taxCt": [z] * 4, "amlEph": {"x": z, "y": z}, "amlCt": [z] * 8,
                      "rateNullifier": z},
            "ext": {"recipient": "0x" + "11" * 20, "relayer": relayer, "fee": fee}}


def test_relay_only_for_own_customers_and_recorded(client):
    stranger = _register_and_login(client, "_pool_stranger")
    relayer = client.get("/pool/issuer").json()["relayer"]
    assert client.post("/pool/relay", json=_relay_body(relayer), headers=stranger).status_code == 403

    h = _verified_user(client, "_pool_relay")
    client.post("/pool/credential", json={"pseudonym": "0x" + "3d" * 31}, headers=h)
    assert client.post("/pool/relay", json=_relay_body("0x" + "99" * 20), headers=h).status_code == 400  # wrong relayer
    assert client.post("/pool/relay", json=_relay_body(relayer, fee=5, public_out=1), headers=h).status_code == 400  # fee > withdrawal
    r = client.post("/pool/relay", json=_relay_body(relayer), headers=h)
    assert r.status_code == 200 and r.json()["simulated"] is True
    assert len(client.get("/pool/relays/mine", headers=h).json()["relays"]) == 1


@pytest.mark.skipif(shutil.which("node") is None, reason="node not available")
def test_credential_hash_matches_js_sdk_and_circuit():
    script = (
        "import('./sdk/aegis-core.mjs').then(c => console.log(c.credentialHashV2(123456789n,"
        " {tier: 2, jurisdiction: 1, expiry: 1800000000n, personTag: 55n}).toString()))"
    )
    out = subprocess.run(["node", "-e", script], cwd=ROOT, capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, out.stderr
    assert int(out.stdout.strip()) == pool_service.credential_hash(123456789, 2, 1, 1800000000, 55)
