#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tests/test_viewing_keys_v2.py - Tests for Viewing Keys V2 (HKDF + AES-256-GCM).
"""

import time
import pytest

from viewing_keys import (
    ViewingKeyManagerV2,
    ViewingKeyError,
    KeyScope,
    KeyStatus,
    RegulatoryEscrowManager,
)
from viewing_keys.scope_filter import filter_by_scope


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def manager():
    return ViewingKeyManagerV2()


@pytest.fixture
def address():
    return "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"


@pytest.fixture
def sample_tx():
    return {
        "tx_hash": "0xabc123",
        "amount": 100.0,
        "balance": 5000.0,
        "address": "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
        "timestamp": "2026-01-01T00:00:00",
        "transactions": [{"id": "tx1", "amount": 50.0}],
        "min_amount": 50.0,
        "max_amount": 200.0,
    }


# ---------------------------------------------------------------------------
# Master key tests
# ---------------------------------------------------------------------------

class TestCreateMasterKey:
    def test_create_master_key(self, manager, address):
        result = manager.create_master_key(address)
        assert result["key_id"]
        assert result["address"] == address
        assert result["master_secret"]
        assert len(bytes.fromhex(result["master_secret"])) == 32
        assert result["created_at"] > 0

        info = manager.get_key_info(result["key_id"])
        assert info["scope"] == KeyScope.FULL_ACCESS.value
        assert info["status"] == KeyStatus.ACTIVE.value
        assert info["parent_id"] is None

    def test_create_master_key_duplicate(self, manager, address):
        first = manager.create_master_key(address)
        second = manager.create_master_key(address)

        assert first["key_id"] != second["key_id"]
        # Old master should be revoked
        old_info = manager.get_key_info(first["key_id"])
        assert old_info["status"] == KeyStatus.REVOKED.value
        # New master should be active
        new_info = manager.get_key_info(second["key_id"])
        assert new_info["status"] == KeyStatus.ACTIVE.value


# ---------------------------------------------------------------------------
# Sub-key derivation tests
# ---------------------------------------------------------------------------

class TestDeriveSubKey:
    def test_derive_sub_key(self, manager, address):
        master = manager.create_master_key(address)
        sub = manager.derive_sub_key(master["key_id"], KeyScope.BALANCE_ONLY)
        assert sub["key_id"] != master["key_id"]
        assert sub["parent_id"] == master["key_id"]
        assert sub["scope"] == KeyScope.BALANCE_ONLY.value
        assert sub["expires_at"] is None
        assert sub["max_uses"] is None

    def test_derive_sub_key_with_expiry(self, manager, address):
        master = manager.create_master_key(address)
        sub = manager.derive_sub_key(master["key_id"], KeyScope.TX_ONLY, expires_in=3600)
        assert sub["expires_at"] is not None
        assert sub["expires_at"] > time.time()
        assert sub["expires_at"] <= time.time() + 3601

    def test_derive_sub_key_with_max_uses(self, manager, address):
        master = manager.create_master_key(address)
        sub = manager.derive_sub_key(master["key_id"], KeyScope.SINGLE_TX, max_uses=5)
        assert sub["max_uses"] == 5


# ---------------------------------------------------------------------------
# Encrypt / Decrypt tests
# ---------------------------------------------------------------------------

class TestEncryptDecrypt:
    def test_encrypt_decrypt_full_access(self, manager, address, sample_tx):
        manager.create_master_key(address)
        master_id = manager._master_keys[address]
        encrypted = manager.encrypt_transaction(address, sample_tx)
        decrypted = manager.decrypt_transaction(master_id, encrypted)
        assert decrypted == sample_tx

    def test_encrypt_decrypt_balance_only(self, manager, address, sample_tx):
        master = manager.create_master_key(address)
        sub = manager.derive_sub_key(master["key_id"], KeyScope.BALANCE_ONLY)
        encrypted = manager.encrypt_transaction(address, sample_tx)
        decrypted = manager.decrypt_transaction(sub["key_id"], encrypted)
        assert set(decrypted.keys()) <= {"balance", "address"}
        assert decrypted.get("balance") == sample_tx["balance"]

    def test_encrypt_decrypt_tx_only(self, manager, address, sample_tx):
        master = manager.create_master_key(address)
        sub = manager.derive_sub_key(master["key_id"], KeyScope.TX_ONLY)
        encrypted = manager.encrypt_transaction(address, sample_tx)
        decrypted = manager.decrypt_transaction(sub["key_id"], encrypted)
        assert "transactions" in decrypted
        assert "balance" not in decrypted
        assert "tx_hash" not in decrypted

    def test_encrypt_decrypt_limited(self, manager, address, sample_tx):
        master = manager.create_master_key(address)
        sub = manager.derive_sub_key(master["key_id"], KeyScope.LIMITED)
        encrypted = manager.encrypt_transaction(address, sample_tx)
        decrypted = manager.decrypt_transaction(sub["key_id"], encrypted)
        assert set(decrypted.keys()) == {"address"}
        assert decrypted["address"] == address


# ---------------------------------------------------------------------------
# Key validity / error tests
# ---------------------------------------------------------------------------

class TestKeyValidity:
    def test_decrypt_revoked_key_fails(self, manager, address, sample_tx):
        master = manager.create_master_key(address)
        sub = manager.derive_sub_key(master["key_id"], KeyScope.FULL_ACCESS)
        manager.revoke_key(sub["key_id"])
        encrypted = manager.encrypt_transaction(address, sample_tx)
        with pytest.raises(ViewingKeyError, match="revoked"):
            manager.decrypt_transaction(sub["key_id"], encrypted)

    def test_decrypt_expired_key_fails(self, manager, address, sample_tx):
        master = manager.create_master_key(address)
        sub = manager.derive_sub_key(master["key_id"], KeyScope.FULL_ACCESS, expires_in=1)
        # Manually expire the key
        manager._keys[sub["key_id"]].expires_at = time.time() - 1
        encrypted = manager.encrypt_transaction(address, sample_tx)
        with pytest.raises(ViewingKeyError, match="expired"):
            manager.decrypt_transaction(sub["key_id"], encrypted)

    def test_decrypt_max_uses_exhausted(self, manager, address, sample_tx):
        master = manager.create_master_key(address)
        sub = manager.derive_sub_key(master["key_id"], KeyScope.FULL_ACCESS, max_uses=5)
        encrypted = manager.encrypt_transaction(address, sample_tx)
        for _ in range(5):
            manager.decrypt_transaction(sub["key_id"], encrypted)
        with pytest.raises(ViewingKeyError, match="max uses"):
            manager.decrypt_transaction(sub["key_id"], encrypted)


# ---------------------------------------------------------------------------
# Revocation tests
# ---------------------------------------------------------------------------

class TestRevocation:
    def test_revoke_cascade(self, manager, address):
        master = manager.create_master_key(address)
        sub1 = manager.derive_sub_key(master["key_id"], KeyScope.BALANCE_ONLY)
        sub2 = manager.derive_sub_key(master["key_id"], KeyScope.TX_ONLY)

        result = manager.revoke_key(master["key_id"])
        assert master["key_id"] in result["revoked_ids"]
        assert sub1["key_id"] in result["revoked_ids"]
        assert sub2["key_id"] in result["revoked_ids"]

        assert manager.get_key_info(master["key_id"])["status"] == KeyStatus.REVOKED.value
        assert manager.get_key_info(sub1["key_id"])["status"] == KeyStatus.REVOKED.value
        assert manager.get_key_info(sub2["key_id"])["status"] == KeyStatus.REVOKED.value

    def test_regenerate_master(self, manager, address):
        master = manager.create_master_key(address)
        sub = manager.derive_sub_key(master["key_id"], KeyScope.BALANCE_ONLY)

        new_master = manager.regenerate_master_key(address)
        assert new_master["key_id"] != master["key_id"]
        assert manager.get_key_info(master["key_id"])["status"] == KeyStatus.REVOKED.value
        assert manager.get_key_info(sub["key_id"])["status"] == KeyStatus.REVOKED.value
        assert manager.get_key_info(new_master["key_id"])["status"] == KeyStatus.ACTIVE.value

    def test_revoke_all_keys(self, manager, address):
        master = manager.create_master_key(address)
        manager.derive_sub_key(master["key_id"], KeyScope.BALANCE_ONLY)
        manager.derive_sub_key(master["key_id"], KeyScope.TX_ONLY)

        result = manager.revoke_all_keys(address)
        assert result["revoked_count"] == 3  # master + 2 sub-keys
        for kid, rec in manager._keys.items():
            if rec.address == address:
                assert rec.status == KeyStatus.REVOKED


# ---------------------------------------------------------------------------
# Escrow tests
# ---------------------------------------------------------------------------

class TestRegulatoryEscrow:
    def test_escrow_without_regulator_key(self):
        escrow_mgr = RegulatoryEscrowManager(regulator_public_key_hex=None)
        result = escrow_mgr.create_escrow({"amount": 100}, "0xtx123")
        assert result is None

    def test_escrow_create_and_decrypt(self):
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives import serialization

        # Generate regulator key pair
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()

        pub_der_hex = public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).hex()
        priv_der_hex = private_key.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).hex()

        escrow_mgr = RegulatoryEscrowManager(regulator_public_key_hex=pub_der_hex)
        tx_data = {"amount": 500.0, "sender": "0xAlice", "recipient": "0xBob"}
        escrow = escrow_mgr.create_escrow(tx_data, "0xhash1")
        assert escrow is not None
        assert "ciphertext_hex" in escrow
        assert escrow["tx_hash"] == "0xhash1"

        decrypted = escrow_mgr.regulator_decrypt_escrow(
            escrow,
            priv_der_hex,
            legal_reference="Ord. Trib. Milano 2026/1234",
        )
        assert decrypted["decrypted_data"] == tx_data
        assert decrypted["legal_reference"] == "Ord. Trib. Milano 2026/1234"
        assert decrypted["tx_hash"] == "0xhash1"


# ---------------------------------------------------------------------------
# Audit trail test
# ---------------------------------------------------------------------------

class TestAuditTrail:
    def test_audit_trail(self, manager, address, sample_tx):
        master = manager.create_master_key(address)
        sub = manager.derive_sub_key(master["key_id"], KeyScope.BALANCE_ONLY)
        encrypted = manager.encrypt_transaction(address, sample_tx)
        manager.decrypt_transaction(sub["key_id"], encrypted)
        manager.revoke_key(sub["key_id"])

        trail = manager.get_audit_trail(address)
        operations = [e["operation"] for e in trail]
        assert "create_master" in operations
        assert "derive" in operations
        assert "encrypt" in operations
        assert "decrypt" in operations
        assert "revoke" in operations


# ---------------------------------------------------------------------------
# Scope filter parametrized test
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("scope,expected_keys", [
    (KeyScope.FULL_ACCESS, {"tx_hash", "amount", "balance", "address", "timestamp",
                             "transactions", "min_amount", "max_amount"}),
    (KeyScope.BALANCE_ONLY, {"balance", "address"}),
    (KeyScope.TX_ONLY, {"transactions"}),
    (KeyScope.SINGLE_TX, {"tx_hash", "amount", "timestamp"}),
    (KeyScope.AMOUNT_RANGE, {"amount_in_range"}),
    (KeyScope.LIMITED, {"address"}),
])
def test_scope_filter_all_scopes(scope, expected_keys, sample_tx):
    result = filter_by_scope(sample_tx, scope)
    assert set(result.keys()) == expected_keys
