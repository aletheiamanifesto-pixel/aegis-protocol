"""Viewing keys and regulatory requests survive restarts and are encrypted at rest."""

import json

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import db_models
from viewing_keys.persistence import persistent_regulatory_manager, persistent_vk_manager

ADDR = "0x" + "ab" * 20


@pytest.fixture
def Session():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    db_models.Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)


def test_keys_survive_a_restart(Session):
    db1 = Session()
    vk = persistent_vk_manager(db1)
    master = vk.create_master_key(ADDR)
    sub = vk.derive_sub_key(master_key_id=master["key_id"], scope=__import__("viewing_keys").KeyScope.BALANCE_ONLY,
                            context="bank", expires_in=3600, max_uses=2)
    enc = vk.encrypt_transaction(ADDR, {"balance": 4200, "address": ADDR, "recipient": "0x1"})
    db1.close()

    # "restart": new session, new manager, no shared memory
    db2 = Session()
    vk2 = persistent_vk_manager(db2)
    info = vk2.get_key_info(sub["key_id"])
    assert info["address"] == ADDR and info["parent_id"] == master["key_id"]
    out = vk2.decrypt_transaction(sub["key_id"], enc)
    # decrypted with the key restored from the DB, filtered by the BALANCE_ONLY scope
    assert out.get("balance", out.get("data", {}).get("balance")) == 4200 or "4200" in json.dumps(out)
    assert "recipient" not in json.dumps(out)
    assert vk2.get_key_info(sub["key_id"])["use_count"] == 1  # in-place change persisted
    assert any(e["operation"] for e in vk2.get_audit_trail(ADDR))


def test_secrets_are_encrypted_at_rest(Session):
    db = Session()
    vk = persistent_vk_manager(db)
    vk.create_master_key(ADDR)
    rows = db.query(db_models.PersistentState).all()
    assert rows
    for r in rows:
        assert ADDR not in r.value and "secret" not in r.value
        with pytest.raises(json.JSONDecodeError):
            json.loads(r.value)


def test_failed_operation_leaves_no_partial_state(Session):
    db = Session()
    vk = persistent_vk_manager(db)
    with pytest.raises(Exception):
        vk.derive_sub_key(master_key_id="missing", scope=__import__("viewing_keys").KeyScope.BALANCE_ONLY,
                          context="x", expires_in=10, max_uses=1)
    assert db.query(db_models.PersistentState).filter_by(namespace="vk2.keys").count() == 0


def test_regulatory_requests_survive_a_restart(Session):
    db1 = Session()
    vk = persistent_vk_manager(db1)
    vk.create_master_key(ADDR)
    rm = persistent_regulatory_manager(db1, vk)
    req = rm.create_request(requester_id="7", requester_type="uif", owner_address=ADDR, tx_hash="0x" + "cd" * 32,
                            scope_requested="single_tx", duration_days=30,
                            legal_reference="D.lgs. 231/2007", reason="check")
    db1.close()

    db2 = Session()
    vk2 = persistent_vk_manager(db2)
    rm2 = persistent_regulatory_manager(db2, vk2)
    assert [r["request_id"] for r in rm2.list_pending_requests(ADDR)] == [req["request_id"]]
    approved = rm2.approve_request(request_id=req["request_id"], owner_address=ADDR,
                                   approved_scope="single_tx", approved_duration_days=7)
    db2.close()

    db3 = Session()
    rm3 = persistent_regulatory_manager(db3, persistent_vk_manager(db3))
    detail = rm3.get_request(req["request_id"])
    assert detail["status"] == "approved"
    assert detail["viewing_key_id"] == approved.get("viewing_key_id", detail["viewing_key_id"])
