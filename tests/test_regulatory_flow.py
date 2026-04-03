#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tests/test_regulatory_flow.py - End-to-end tests for the Regulatory Access Flow.

Covers:
  1. Create a regulator request → PENDING_USER_APPROVAL
  2. Approve request → APPROVED, sub-key created with correct scope/duration
  3. Deny request → DENIED
  4. Decrypt with approved key → only scope-filtered fields visible
  5. Key expiry after approved duration
  6. Manual revocation of approved key
  7. Scope restriction: owner can grant more restrictive scope than requested
  8. legal_reference mandatory: request without it is rejected
  9. Pending request auto-expires after 7 days
"""

import time
import pytest

from viewing_keys.viewing_keys_v2 import ViewingKeyManagerV2, ViewingKeyError
from viewing_keys.scope_filter import KeyScope, KeyStatus
from viewing_keys.regulatory_flow import (
    RegulatoryAccessManager,
    RegulatoryAccessRequest,
    RequestStatus,
    REQUEST_AUTO_EXPIRE_DAYS,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def vk_manager():
    return ViewingKeyManagerV2()


@pytest.fixture
def reg_manager(vk_manager):
    return RegulatoryAccessManager(vk_manager)


@pytest.fixture
def owner_address():
    return "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"


@pytest.fixture
def tx_hash():
    return "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab"


@pytest.fixture
def sample_tx():
    return {
        "tx_hash": "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab",
        "amount": 1500.0,
        "balance": 10000.0,
        "address": "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
        "timestamp": "2026-01-01T12:00:00",
        "transactions": [{"id": "t1", "amount": 1500.0}],
        "min_amount": 100.0,
        "max_amount": 5000.0,
    }


def _make_request(reg_manager, owner_address, tx_hash, scope=KeyScope.SINGLE_TX,
                  duration_days=30, legal_reference="Decreto 231/2007 Art. 35"):
    """Helper to create a standard test request."""
    return reg_manager.create_request(
        requester_id="uif-test-agency",
        requester_type="uif",
        owner_address=owner_address,
        tx_hash=tx_hash,
        scope_requested=scope,
        duration_days=duration_days,
        legal_reference=legal_reference,
        reason="Suspicious transaction investigation",
    )


# ---------------------------------------------------------------------------
# 1. Test: create request → PENDING_USER_APPROVAL
# ---------------------------------------------------------------------------

class TestCreateRequest:
    def test_create_request_pending(self, reg_manager, owner_address, tx_hash):
        result = _make_request(reg_manager, owner_address, tx_hash)

        assert result["request_id"]
        assert result["status"] == RequestStatus.PENDING_USER_APPROVAL.value
        assert result["requester_id"] == "uif-test-agency"
        assert result["requester_type"] == "uif"
        assert result["owner_address"] == owner_address
        assert result["tx_hash"] == tx_hash
        assert result["scope_requested"] == KeyScope.SINGLE_TX.value
        assert result["duration_days_requested"] == 30
        assert result["legal_reference"] == "Decreto 231/2007 Art. 35"
        assert result["responded_at"] is None
        assert result["viewing_key_id"] is None

    def test_create_request_stored(self, reg_manager, owner_address, tx_hash):
        result = _make_request(reg_manager, owner_address, tx_hash)
        fetched = reg_manager.get_request(result["request_id"])
        assert fetched is not None
        assert fetched["request_id"] == result["request_id"]

    def test_list_pending_requests(self, reg_manager, owner_address, tx_hash):
        r1 = _make_request(reg_manager, owner_address, tx_hash)
        r2 = _make_request(reg_manager, owner_address, tx_hash)

        pending = reg_manager.list_pending_requests(owner_address)
        ids = [p["request_id"] for p in pending]
        assert r1["request_id"] in ids
        assert r2["request_id"] in ids

    def test_list_pending_only_shows_pending(self, reg_manager, owner_address, tx_hash):
        """After approval, the request no longer appears in pending list."""
        r = _make_request(reg_manager, owner_address, tx_hash)
        reg_manager.approve_request(
            r["request_id"], owner_address, KeyScope.SINGLE_TX, 30
        )
        pending = reg_manager.list_pending_requests(owner_address)
        assert all(p["request_id"] != r["request_id"] for p in pending)


# ---------------------------------------------------------------------------
# 2. Test: approve request → APPROVED, sub-key with correct scope/duration
# ---------------------------------------------------------------------------

class TestApproveRequest:
    def test_approve_sets_status(self, reg_manager, owner_address, tx_hash):
        r = _make_request(reg_manager, owner_address, tx_hash)
        result = reg_manager.approve_request(
            r["request_id"], owner_address, KeyScope.SINGLE_TX, 30
        )
        assert result["status"] == RequestStatus.APPROVED.value

    def test_approve_creates_sub_key(self, reg_manager, vk_manager, owner_address, tx_hash):
        r = _make_request(reg_manager, owner_address, tx_hash)
        result = reg_manager.approve_request(
            r["request_id"], owner_address, KeyScope.SINGLE_TX, 30
        )
        key_id = result["viewing_key_id"]
        assert key_id is not None
        key_info = vk_manager.get_key_info(key_id)
        assert key_info is not None
        assert key_info["scope"] == KeyScope.SINGLE_TX.value
        assert key_info["status"] == KeyStatus.ACTIVE.value

    def test_approve_sub_key_expiry(self, reg_manager, vk_manager, owner_address, tx_hash):
        r = _make_request(reg_manager, owner_address, tx_hash, duration_days=5)
        result = reg_manager.approve_request(
            r["request_id"], owner_address, KeyScope.SINGLE_TX, 5
        )
        key_id = result["viewing_key_id"]
        key_info = vk_manager.get_key_info(key_id)
        expected_expiry = time.time() + 5 * 86400
        assert key_info["expires_at"] is not None
        assert abs(key_info["expires_at"] - expected_expiry) < 5  # within 5 s

    def test_approve_scope_and_duration_stored(self, reg_manager, owner_address, tx_hash):
        r = _make_request(reg_manager, owner_address, tx_hash, duration_days=14)
        result = reg_manager.approve_request(
            r["request_id"], owner_address, KeyScope.SINGLE_TX, 14
        )
        assert result["scope_granted"] == KeyScope.SINGLE_TX.value
        assert result["duration_days_granted"] == 14

    def test_approve_wrong_owner_fails(self, reg_manager, owner_address, tx_hash):
        r = _make_request(reg_manager, owner_address, tx_hash)
        with pytest.raises(ValueError, match="owner_address does not match"):
            reg_manager.approve_request(
                r["request_id"], "0xDifferentAddress", KeyScope.SINGLE_TX, 30
            )

    def test_double_approve_fails(self, reg_manager, owner_address, tx_hash):
        r = _make_request(reg_manager, owner_address, tx_hash)
        reg_manager.approve_request(
            r["request_id"], owner_address, KeyScope.SINGLE_TX, 30
        )
        with pytest.raises(ValueError, match="expected 'pending_user_approval'"):
            reg_manager.approve_request(
                r["request_id"], owner_address, KeyScope.SINGLE_TX, 30
            )


# ---------------------------------------------------------------------------
# 3. Test: deny request → DENIED
# ---------------------------------------------------------------------------

class TestDenyRequest:
    def test_deny_sets_status(self, reg_manager, owner_address, tx_hash):
        r = _make_request(reg_manager, owner_address, tx_hash)
        result = reg_manager.deny_request(r["request_id"], owner_address, "Not relevant")
        assert result["status"] == RequestStatus.DENIED.value
        assert result["denied_reason"] == "Not relevant"

    def test_deny_records_responded_at(self, reg_manager, owner_address, tx_hash):
        r = _make_request(reg_manager, owner_address, tx_hash)
        before = time.time()
        result = reg_manager.deny_request(r["request_id"], owner_address)
        assert result["responded_at"] is not None
        assert result["responded_at"] >= before

    def test_deny_wrong_owner_fails(self, reg_manager, owner_address, tx_hash):
        r = _make_request(reg_manager, owner_address, tx_hash)
        with pytest.raises(ValueError, match="owner_address does not match"):
            reg_manager.deny_request(r["request_id"], "0xOtherAddress")


# ---------------------------------------------------------------------------
# 4. Test: decrypt with approved key → scope-filtered
# ---------------------------------------------------------------------------

class TestDecryptWithApprovedKey:
    def test_decrypt_single_tx_scope(
        self, reg_manager, vk_manager, owner_address, tx_hash, sample_tx
    ):
        # Create master key and encrypt tx
        vk_manager.create_master_key(owner_address)
        encrypted = vk_manager.encrypt_transaction(owner_address, sample_tx)

        # Agency requests single_tx scope
        r = _make_request(reg_manager, owner_address, tx_hash, scope=KeyScope.SINGLE_TX)
        result = reg_manager.approve_request(
            r["request_id"], owner_address, KeyScope.SINGLE_TX, 30
        )
        key_id = result["viewing_key_id"]

        # Decrypt — should only see tx_hash, amount, timestamp
        decrypted = vk_manager.decrypt_transaction(key_id, encrypted)
        assert set(decrypted.keys()) <= {"tx_hash", "amount", "timestamp"}
        assert "balance" not in decrypted

    def test_decrypt_balance_only_scope(
        self, reg_manager, vk_manager, owner_address, tx_hash, sample_tx
    ):
        vk_manager.create_master_key(owner_address)
        encrypted = vk_manager.encrypt_transaction(owner_address, sample_tx)

        r = _make_request(
            reg_manager, owner_address, tx_hash, scope=KeyScope.FULL_ACCESS
        )
        result = reg_manager.approve_request(
            r["request_id"], owner_address, KeyScope.BALANCE_ONLY, 30
        )
        key_id = result["viewing_key_id"]

        decrypted = vk_manager.decrypt_transaction(key_id, encrypted)
        assert "balance" in decrypted
        assert "tx_hash" not in decrypted


# ---------------------------------------------------------------------------
# 5. Test: key expiry after approved duration
# ---------------------------------------------------------------------------

class TestKeyExpiry:
    def test_key_expires_after_duration(
        self, reg_manager, vk_manager, owner_address, tx_hash, sample_tx
    ):
        vk_manager.create_master_key(owner_address)
        encrypted = vk_manager.encrypt_transaction(owner_address, sample_tx)

        r = _make_request(reg_manager, owner_address, tx_hash)
        result = reg_manager.approve_request(
            r["request_id"], owner_address, KeyScope.SINGLE_TX, 1
        )
        key_id = result["viewing_key_id"]

        # Manually fast-forward the expiry
        vk_manager._keys[key_id].expires_at = time.time() - 1

        with pytest.raises(ViewingKeyError, match="expired"):
            vk_manager.decrypt_transaction(key_id, encrypted)


# ---------------------------------------------------------------------------
# 6. Test: manual revocation by owner
# ---------------------------------------------------------------------------

class TestManualRevocation:
    def test_revoke_approved_key(
        self, reg_manager, vk_manager, owner_address, tx_hash, sample_tx
    ):
        vk_manager.create_master_key(owner_address)
        encrypted = vk_manager.encrypt_transaction(owner_address, sample_tx)

        r = _make_request(reg_manager, owner_address, tx_hash)
        approved = reg_manager.approve_request(
            r["request_id"], owner_address, KeyScope.SINGLE_TX, 30
        )
        key_id = approved["viewing_key_id"]

        # Revoke via regulatory manager
        revoked = reg_manager.revoke_approved_key(r["request_id"], owner_address)
        assert revoked["status"] == RequestStatus.REVOKED.value

        # Key should now be unusable
        with pytest.raises(ViewingKeyError, match="revoked"):
            vk_manager.decrypt_transaction(key_id, encrypted)

    def test_revoke_wrong_owner_fails(self, reg_manager, owner_address, tx_hash):
        r = _make_request(reg_manager, owner_address, tx_hash)
        reg_manager.approve_request(
            r["request_id"], owner_address, KeyScope.SINGLE_TX, 30
        )
        with pytest.raises(ValueError, match="owner_address does not match"):
            reg_manager.revoke_approved_key(r["request_id"], "0xOtherAddress")


# ---------------------------------------------------------------------------
# 7. Test: scope restriction — owner grants more restrictive scope
# ---------------------------------------------------------------------------

class TestScopeRestriction:
    def test_grant_more_restrictive_scope(
        self, reg_manager, vk_manager, owner_address, tx_hash, sample_tx
    ):
        """Agency requests FULL_ACCESS but owner grants only SINGLE_TX."""
        vk_manager.create_master_key(owner_address)
        encrypted = vk_manager.encrypt_transaction(owner_address, sample_tx)

        # Request FULL_ACCESS
        r = _make_request(
            reg_manager, owner_address, tx_hash, scope=KeyScope.FULL_ACCESS
        )
        # Approve with SINGLE_TX (more restrictive) — must succeed
        result = reg_manager.approve_request(
            r["request_id"], owner_address, KeyScope.SINGLE_TX, 30
        )
        assert result["scope_granted"] == KeyScope.SINGLE_TX.value

        # Verify the key only returns SINGLE_TX fields
        key_id = result["viewing_key_id"]
        decrypted = vk_manager.decrypt_transaction(key_id, encrypted)
        assert set(decrypted.keys()) <= {"tx_hash", "amount", "timestamp"}

    def test_grant_less_restrictive_scope_fails(
        self, reg_manager, owner_address, tx_hash
    ):
        """Owner cannot grant a scope that is less restrictive than requested."""
        # Request only SINGLE_TX but try to grant FULL_ACCESS (less restrictive)
        r = _make_request(
            reg_manager, owner_address, tx_hash, scope=KeyScope.SINGLE_TX
        )
        with pytest.raises(ValueError, match="less restrictive"):
            reg_manager.approve_request(
                r["request_id"], owner_address, KeyScope.FULL_ACCESS, 30
            )

    def test_grant_same_scope_ok(self, reg_manager, owner_address, tx_hash):
        r = _make_request(
            reg_manager, owner_address, tx_hash, scope=KeyScope.BALANCE_ONLY
        )
        result = reg_manager.approve_request(
            r["request_id"], owner_address, KeyScope.BALANCE_ONLY, 30
        )
        assert result["status"] == RequestStatus.APPROVED.value

    def test_grant_shorter_duration_ok(self, reg_manager, owner_address, tx_hash):
        r = _make_request(
            reg_manager, owner_address, tx_hash, duration_days=30
        )
        result = reg_manager.approve_request(
            r["request_id"], owner_address, KeyScope.SINGLE_TX, 15
        )
        assert result["duration_days_granted"] == 15

    def test_grant_longer_duration_fails(self, reg_manager, owner_address, tx_hash):
        r = _make_request(
            reg_manager, owner_address, tx_hash, duration_days=10
        )
        with pytest.raises(ValueError, match="exceeds requested duration"):
            reg_manager.approve_request(
                r["request_id"], owner_address, KeyScope.SINGLE_TX, 20
            )


# ---------------------------------------------------------------------------
# 8. Test: legal_reference is mandatory
# ---------------------------------------------------------------------------

class TestLegalReferenceMandatory:
    def test_empty_legal_reference_rejected(self, reg_manager, owner_address, tx_hash):
        with pytest.raises(ValueError, match="legal_reference is required"):
            reg_manager.create_request(
                requester_id="uif-test",
                requester_type="uif",
                owner_address=owner_address,
                tx_hash=tx_hash,
                scope_requested=KeyScope.SINGLE_TX,
                duration_days=30,
                legal_reference="",
                reason="Test",
            )

    def test_whitespace_only_legal_reference_rejected(
        self, reg_manager, owner_address, tx_hash
    ):
        with pytest.raises(ValueError, match="legal_reference is required"):
            reg_manager.create_request(
                requester_id="uif-test",
                requester_type="uif",
                owner_address=owner_address,
                tx_hash=tx_hash,
                scope_requested=KeyScope.SINGLE_TX,
                duration_days=30,
                legal_reference="   ",
                reason="Test",
            )

    def test_valid_legal_reference_accepted(self, reg_manager, owner_address, tx_hash):
        result = _make_request(
            reg_manager, owner_address, tx_hash,
            legal_reference="D.Lgs 231/2007 Art. 35"
        )
        assert result["legal_reference"] == "D.Lgs 231/2007 Art. 35"


# ---------------------------------------------------------------------------
# 9. Test: pending request auto-expires after 7 days
# ---------------------------------------------------------------------------

class TestAutoExpiry:
    def test_pending_auto_expires_after_7_days(
        self, reg_manager, owner_address, tx_hash
    ):
        r = _make_request(reg_manager, owner_address, tx_hash)
        request_id = r["request_id"]

        # Fast-forward the created_at to beyond the 7-day window
        reg_manager._requests[request_id].created_at = (
            time.time() - (REQUEST_AUTO_EXPIRE_DAYS * 86400 + 1)
        )

        expired_ids = reg_manager.check_expired_requests()
        assert request_id in expired_ids

        updated = reg_manager.get_request(request_id)
        assert updated["status"] == RequestStatus.EXPIRED.value

    def test_recent_pending_not_expired(self, reg_manager, owner_address, tx_hash):
        r = _make_request(reg_manager, owner_address, tx_hash)
        request_id = r["request_id"]

        expired_ids = reg_manager.check_expired_requests()
        assert request_id not in expired_ids

        updated = reg_manager.get_request(request_id)
        assert updated["status"] == RequestStatus.PENDING_USER_APPROVAL.value

    def test_approved_request_not_expired(self, reg_manager, owner_address, tx_hash):
        r = _make_request(reg_manager, owner_address, tx_hash)
        request_id = r["request_id"]

        # Approve the request
        reg_manager.approve_request(
            request_id, owner_address, KeyScope.SINGLE_TX, 30
        )

        # Fast-forward created_at — approved requests must not be re-expired
        reg_manager._requests[request_id].created_at = (
            time.time() - (REQUEST_AUTO_EXPIRE_DAYS * 86400 + 1)
        )

        expired_ids = reg_manager.check_expired_requests()
        assert request_id not in expired_ids

        updated = reg_manager.get_request(request_id)
        assert updated["status"] == RequestStatus.APPROVED.value


# ---------------------------------------------------------------------------
# Miscellaneous edge-case tests
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_unknown_request_id_returns_none(self, reg_manager):
        assert reg_manager.get_request("non-existent-id") is None

    def test_invalid_requester_type_rejected(self, reg_manager, owner_address, tx_hash):
        with pytest.raises(ValueError, match="Invalid requester_type"):
            reg_manager.create_request(
                requester_id="bad-actor",
                requester_type="unknown_agency",
                owner_address=owner_address,
                tx_hash=tx_hash,
                scope_requested=KeyScope.SINGLE_TX,
                duration_days=30,
                legal_reference="Some law",
                reason="Test",
            )

    def test_audit_trail_populated(self, reg_manager, owner_address, tx_hash):
        r = _make_request(reg_manager, owner_address, tx_hash)
        reg_manager.approve_request(
            r["request_id"], owner_address, KeyScope.SINGLE_TX, 30
        )
        trail = reg_manager.get_audit_trail()
        operations = [e["operation"] for e in trail]
        assert "create_request" in operations
        assert "approve_request" in operations

    def test_list_pending_empty_for_unknown_address(self, reg_manager):
        pending = reg_manager.list_pending_requests("0xUnknown")
        assert pending == []
