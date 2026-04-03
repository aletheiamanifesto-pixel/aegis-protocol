#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tests/test_regulatory_flow.py - End-to-end tests for the Regulatory Access Flow.

Covers:
  1. Regulator request creation → PENDING_USER_APPROVAL
  2. Owner approval → APPROVED, sub-key created with correct scope and duration
  3. Owner denial → DENIED
  4. Decrypt with approved key → only scope-filtered fields visible
  5. Key auto-expiry after granted duration
  6. Manual revocation before expiry
  7. Scope restriction: owner grants narrower scope than requested
  8. legal_reference is mandatory: empty string is rejected
  9. Pending request auto-expires after 7 days without response
"""

import time
import pytest

from viewing_keys import ViewingKeyManagerV2, ViewingKeyError, KeyScope
from viewing_keys.regulatory_flow import (
    RegulatoryAccessManager,
    RegulatoryFlowError,
    RequestStatus,
    PENDING_REQUEST_TTL_DAYS,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

OWNER = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
TX_HASH = "0xdeadbeef01234567890abcdef1234567890abcdef1234567890abcdef12345678"

SAMPLE_TX = {
    "tx_hash": TX_HASH,
    "amount": 2500.0,
    "balance": 10000.0,
    "address": OWNER,
    "timestamp": "2026-01-15T12:00:00Z",
    "transactions": [{"id": "tx1", "amount": 2500.0}],
    "min_amount": 1000.0,
    "max_amount": 5000.0,
}


@pytest.fixture
def vk_manager():
    return ViewingKeyManagerV2()


@pytest.fixture
def reg_manager(vk_manager):
    return RegulatoryAccessManager(vk_manager)


@pytest.fixture
def create_valid_request(reg_manager):
    """Helper fixture: creates a pending request and returns (reg_manager, request_info)."""
    info = reg_manager.create_request(
        requester_id="uif-rome-001",
        requester_type="uif",
        owner_address=OWNER,
        tx_hash=TX_HASH,
        scope_requested="single_tx",
        duration_days=30,
        legal_reference="Decreto 231/2007 Art. 35",
        reason="AML investigation into suspicious transaction",
    )
    return reg_manager, info


# ---------------------------------------------------------------------------
# 1. Test: create request → PENDING_USER_APPROVAL
# ---------------------------------------------------------------------------

class TestCreateRequest:
    def test_create_request_returns_pending(self, reg_manager):
        info = reg_manager.create_request(
            requester_id="uif-rome-001",
            requester_type="uif",
            owner_address=OWNER,
            tx_hash=TX_HASH,
            scope_requested="single_tx",
            duration_days=30,
            legal_reference="Decreto 231/2007 Art. 35",
            reason="AML investigation",
        )
        assert info["request_id"]
        assert info["status"] == RequestStatus.PENDING_USER_APPROVAL.value
        assert info["requester_id"] == "uif-rome-001"
        assert info["requester_type"] == "uif"
        assert info["owner_address"] == OWNER
        assert info["tx_hash"] == TX_HASH
        assert info["scope_requested"] == "single_tx"
        assert info["duration_days_requested"] == 30
        assert info["legal_reference"] == "Decreto 231/2007 Art. 35"
        assert info["viewing_key_id"] is None
        assert info["denied_reason"] is None
        assert len(info["audit_events"]) == 1
        assert info["audit_events"][0]["event"] == "request_created"

    def test_list_pending_shows_new_request(self, create_valid_request):
        rm, info = create_valid_request
        pending = rm.list_pending_requests(OWNER)
        ids = [r["request_id"] for r in pending]
        assert info["request_id"] in ids

    def test_get_request_returns_details(self, create_valid_request):
        rm, info = create_valid_request
        details = rm.get_request(info["request_id"])
        assert details is not None
        assert details["request_id"] == info["request_id"]

    def test_get_nonexistent_request_returns_none(self, reg_manager):
        assert reg_manager.get_request("nonexistent-id") is None


# ---------------------------------------------------------------------------
# 2. Test: owner approval → APPROVED, sub-key created
# ---------------------------------------------------------------------------

class TestApproveRequest:
    def test_approve_creates_sub_key(self, vk_manager, reg_manager):
        # Create a master key for the owner first
        master = vk_manager.create_master_key(OWNER)

        info = reg_manager.create_request(
            requester_id="esma-eu-002",
            requester_type="esma",
            owner_address=OWNER,
            tx_hash=TX_HASH,
            scope_requested="single_tx",
            duration_days=30,
            legal_reference="MiCA Art. 88 para. 2",
            reason="Market surveillance",
        )

        result = reg_manager.approve_request(
            request_id=info["request_id"],
            owner_address=OWNER,
            approved_scope="single_tx",
            approved_duration_days=14,
        )

        assert result["status"] == RequestStatus.APPROVED.value
        assert result["viewing_key_id"] is not None
        assert result["scope_granted"] == "single_tx"
        assert result["duration_days_granted"] == 14
        assert result["responded_at"] is not None

        # Sub-key should exist and have correct properties
        key_id = result["viewing_key_id"]
        key_info = vk_manager.get_key_info(key_id)
        assert key_info["scope"] == "single_tx"
        assert key_info["status"] == "active"
        assert key_info["expires_at"] is not None
        # Should expire in ~14 days
        expected_expiry = time.time() + 14 * 86400
        assert abs(key_info["expires_at"] - expected_expiry) < 5  # within 5 seconds

    def test_approve_wrong_owner_fails(self, vk_manager, reg_manager):
        vk_manager.create_master_key(OWNER)
        info = reg_manager.create_request(
            requester_id="uif-rome-001",
            requester_type="uif",
            owner_address=OWNER,
            tx_hash=TX_HASH,
            scope_requested="single_tx",
            duration_days=30,
            legal_reference="Decreto 231/2007 Art. 35",
            reason="AML",
        )
        with pytest.raises(RegulatoryFlowError, match="owner_address does not match"):
            reg_manager.approve_request(
                request_id=info["request_id"],
                owner_address="0x0000000000000000000000000000000000000001",
                approved_scope="single_tx",
                approved_duration_days=14,
            )

    def test_approve_already_approved_fails(self, vk_manager, reg_manager):
        vk_manager.create_master_key(OWNER)
        info = reg_manager.create_request(
            requester_id="uif-rome-001",
            requester_type="uif",
            owner_address=OWNER,
            tx_hash=TX_HASH,
            scope_requested="single_tx",
            duration_days=30,
            legal_reference="Decreto 231/2007 Art. 35",
            reason="AML",
        )
        reg_manager.approve_request(
            request_id=info["request_id"],
            owner_address=OWNER,
            approved_scope="single_tx",
            approved_duration_days=14,
        )
        with pytest.raises(RegulatoryFlowError, match="not pending"):
            reg_manager.approve_request(
                request_id=info["request_id"],
                owner_address=OWNER,
                approved_scope="single_tx",
                approved_duration_days=14,
            )


# ---------------------------------------------------------------------------
# 3. Test: owner denial → DENIED
# ---------------------------------------------------------------------------

class TestDenyRequest:
    def test_deny_sets_denied_status(self, create_valid_request):
        rm, info = create_valid_request
        result = rm.deny_request(
            request_id=info["request_id"],
            owner_address=OWNER,
            reason="No valid legal basis in this jurisdiction",
        )
        assert result["status"] == RequestStatus.DENIED.value
        assert result["denied_reason"] == "No valid legal basis in this jurisdiction"
        assert result["responded_at"] is not None
        assert result["viewing_key_id"] is None

    def test_deny_removes_from_pending(self, create_valid_request):
        rm, info = create_valid_request
        rm.deny_request(
            request_id=info["request_id"],
            owner_address=OWNER,
            reason="Denied",
        )
        pending = rm.list_pending_requests(OWNER)
        ids = [r["request_id"] for r in pending]
        assert info["request_id"] not in ids

    def test_deny_wrong_owner_fails(self, create_valid_request):
        rm, info = create_valid_request
        with pytest.raises(RegulatoryFlowError, match="owner_address does not match"):
            rm.deny_request(
                request_id=info["request_id"],
                owner_address="0x0000000000000000000000000000000000000001",
                reason="Bad owner",
            )


# ---------------------------------------------------------------------------
# 4. Test: decrypt with approved key → scope-filtered fields only
# ---------------------------------------------------------------------------

class TestDecryptWithApprovedKey:
    def test_decrypt_single_tx_scope(self, vk_manager, reg_manager):
        master = vk_manager.create_master_key(OWNER)

        # Encrypt the transaction
        encrypted = vk_manager.encrypt_transaction(OWNER, SAMPLE_TX)

        info = reg_manager.create_request(
            requester_id="gdf-milan-003",
            requester_type="guardia_finanza",
            owner_address=OWNER,
            tx_hash=TX_HASH,
            scope_requested="single_tx",
            duration_days=30,
            legal_reference="D.Lgs. 231/2007 Art. 41",
            reason="Financial crime investigation",
        )

        result = reg_manager.approve_request(
            request_id=info["request_id"],
            owner_address=OWNER,
            approved_scope="single_tx",
            approved_duration_days=30,
        )

        key_id = result["viewing_key_id"]

        # Agency decrypts using the sub-key
        decrypted = vk_manager.decrypt_transaction(key_id, encrypted)

        # SINGLE_TX scope: should only see tx_hash, amount, timestamp
        assert "tx_hash" in decrypted
        assert "amount" in decrypted
        assert "timestamp" in decrypted
        # Should NOT see full balance or address
        assert "balance" not in decrypted
        assert "transactions" not in decrypted

    def test_decrypt_balance_only_scope(self, vk_manager, reg_manager):
        vk_manager.create_master_key(OWNER)
        encrypted = vk_manager.encrypt_transaction(OWNER, SAMPLE_TX)

        info = reg_manager.create_request(
            requester_id="tax-001",
            requester_type="tax_authority",
            owner_address=OWNER,
            tx_hash=TX_HASH,
            scope_requested="balance_only",
            duration_days=7,
            legal_reference="DPR 600/1973 Art. 32",
            reason="Tax compliance check",
        )
        result = reg_manager.approve_request(
            request_id=info["request_id"],
            owner_address=OWNER,
            approved_scope="balance_only",
            approved_duration_days=7,
        )

        decrypted = vk_manager.decrypt_transaction(result["viewing_key_id"], encrypted)
        assert "balance" in decrypted
        assert "address" in decrypted
        assert "tx_hash" not in decrypted
        assert "amount" not in decrypted


# ---------------------------------------------------------------------------
# 5. Test: key auto-expiry after granted duration
# ---------------------------------------------------------------------------

class TestKeyExpiry:
    def test_expired_key_cannot_decrypt(self, vk_manager, reg_manager):
        vk_manager.create_master_key(OWNER)
        encrypted = vk_manager.encrypt_transaction(OWNER, SAMPLE_TX)

        info = reg_manager.create_request(
            requester_id="uif-rome-001",
            requester_type="uif",
            owner_address=OWNER,
            tx_hash=TX_HASH,
            scope_requested="single_tx",
            duration_days=1,
            legal_reference="Decreto 231/2007 Art. 35",
            reason="AML",
        )

        result = reg_manager.approve_request(
            request_id=info["request_id"],
            owner_address=OWNER,
            approved_scope="single_tx",
            approved_duration_days=1,
        )

        key_id = result["viewing_key_id"]
        key_record = vk_manager._keys[key_id]

        # Force-expire the key by setting expires_at in the past
        key_record.expires_at = time.time() - 1

        with pytest.raises(ViewingKeyError, match="expired"):
            vk_manager.decrypt_transaction(key_id, encrypted)


# ---------------------------------------------------------------------------
# 6. Test: manual revocation before expiry
# ---------------------------------------------------------------------------

class TestManualRevocation:
    def test_revoke_approved_key(self, vk_manager, reg_manager):
        vk_manager.create_master_key(OWNER)
        encrypted = vk_manager.encrypt_transaction(OWNER, SAMPLE_TX)

        info = reg_manager.create_request(
            requester_id="esma-eu-002",
            requester_type="esma",
            owner_address=OWNER,
            tx_hash=TX_HASH,
            scope_requested="single_tx",
            duration_days=30,
            legal_reference="MiCA Art. 88",
            reason="Surveillance",
        )

        result = reg_manager.approve_request(
            request_id=info["request_id"],
            owner_address=OWNER,
            approved_scope="single_tx",
            approved_duration_days=30,
        )

        key_id = result["viewing_key_id"]

        # Key works before revocation
        decrypted = vk_manager.decrypt_transaction(key_id, encrypted)
        assert decrypted  # non-empty

        # Owner revokes
        revoke_result = reg_manager.revoke_approved_key(
            request_id=info["request_id"],
            owner_address=OWNER,
        )
        assert revoke_result["status"] == RequestStatus.REVOKED.value

        # Key no longer works
        with pytest.raises(ViewingKeyError, match="revoked"):
            vk_manager.decrypt_transaction(key_id, encrypted)

    def test_revoke_non_approved_request_fails(self, create_valid_request):
        rm, info = create_valid_request
        # Request is PENDING, not APPROVED → revoke should fail
        with pytest.raises(RegulatoryFlowError, match="not in APPROVED"):
            rm.revoke_approved_key(
                request_id=info["request_id"],
                owner_address=OWNER,
            )


# ---------------------------------------------------------------------------
# 7. Test: scope restriction — owner grants narrower scope than requested
# ---------------------------------------------------------------------------

class TestScopeRestriction:
    def test_owner_can_grant_narrower_scope(self, vk_manager, reg_manager):
        vk_manager.create_master_key(OWNER)
        encrypted = vk_manager.encrypt_transaction(OWNER, SAMPLE_TX)

        # Agency requests full_access
        info = reg_manager.create_request(
            requester_id="aml-001",
            requester_type="aml_authority",
            owner_address=OWNER,
            tx_hash=TX_HASH,
            scope_requested="full_access",
            duration_days=30,
            legal_reference="AMLD5 Art. 32a",
            reason="AML investigation",
        )

        # Owner only grants single_tx (more restrictive than full_access)
        result = reg_manager.approve_request(
            request_id=info["request_id"],
            owner_address=OWNER,
            approved_scope="single_tx",
            approved_duration_days=14,
        )

        assert result["scope_granted"] == "single_tx"
        assert result["duration_days_granted"] == 14

        # Decrypt: should only see SINGLE_TX fields
        decrypted = vk_manager.decrypt_transaction(result["viewing_key_id"], encrypted)
        assert "tx_hash" in decrypted
        assert "balance" not in decrypted

    def test_owner_cannot_grant_broader_scope_than_requested(self, vk_manager, reg_manager):
        vk_manager.create_master_key(OWNER)

        # Agency requests single_tx
        info = reg_manager.create_request(
            requester_id="uif-rome-001",
            requester_type="uif",
            owner_address=OWNER,
            tx_hash=TX_HASH,
            scope_requested="single_tx",
            duration_days=30,
            legal_reference="Decreto 231/2007 Art. 35",
            reason="AML",
        )

        # Owner tries to grant full_access (broader) — should fail
        with pytest.raises(RegulatoryFlowError, match="broader than"):
            reg_manager.approve_request(
                request_id=info["request_id"],
                owner_address=OWNER,
                approved_scope="full_access",
                approved_duration_days=30,
            )

    def test_owner_cannot_grant_longer_duration_than_requested(self, vk_manager, reg_manager):
        vk_manager.create_master_key(OWNER)
        info = reg_manager.create_request(
            requester_id="uif-rome-001",
            requester_type="uif",
            owner_address=OWNER,
            tx_hash=TX_HASH,
            scope_requested="single_tx",
            duration_days=7,
            legal_reference="Decreto 231/2007 Art. 35",
            reason="AML",
        )

        with pytest.raises(RegulatoryFlowError, match="exceeds"):
            reg_manager.approve_request(
                request_id=info["request_id"],
                owner_address=OWNER,
                approved_scope="single_tx",
                approved_duration_days=30,  # > 7 requested
            )


# ---------------------------------------------------------------------------
# 8. Test: legal_reference is mandatory
# ---------------------------------------------------------------------------

class TestLegalReferenceRequired:
    def test_empty_legal_reference_rejected(self, reg_manager):
        with pytest.raises(RegulatoryFlowError, match="legal_reference is mandatory"):
            reg_manager.create_request(
                requester_id="uif-rome-001",
                requester_type="uif",
                owner_address=OWNER,
                tx_hash=TX_HASH,
                scope_requested="single_tx",
                duration_days=30,
                legal_reference="",
                reason="AML",
            )

    def test_whitespace_only_legal_reference_rejected(self, reg_manager):
        with pytest.raises(RegulatoryFlowError, match="legal_reference is mandatory"):
            reg_manager.create_request(
                requester_id="uif-rome-001",
                requester_type="uif",
                owner_address=OWNER,
                tx_hash=TX_HASH,
                scope_requested="single_tx",
                duration_days=30,
                legal_reference="   ",
                reason="AML",
            )

    def test_invalid_requester_type_rejected(self, reg_manager):
        with pytest.raises(RegulatoryFlowError, match="Invalid requester_type"):
            reg_manager.create_request(
                requester_id="unknown-agency",
                requester_type="unknown_agency",
                owner_address=OWNER,
                tx_hash=TX_HASH,
                scope_requested="single_tx",
                duration_days=30,
                legal_reference="Decreto 231/2007 Art. 35",
                reason="AML",
            )

    def test_invalid_scope_rejected(self, reg_manager):
        with pytest.raises(RegulatoryFlowError, match="Invalid scope"):
            reg_manager.create_request(
                requester_id="uif-rome-001",
                requester_type="uif",
                owner_address=OWNER,
                tx_hash=TX_HASH,
                scope_requested="nonexistent_scope",
                duration_days=30,
                legal_reference="Decreto 231/2007 Art. 35",
                reason="AML",
            )


# ---------------------------------------------------------------------------
# 9. Test: pending request auto-expires after 7 days
# ---------------------------------------------------------------------------

class TestAutoExpiry:
    def test_pending_request_expires_after_ttl(self, reg_manager):
        info = reg_manager.create_request(
            requester_id="uif-rome-001",
            requester_type="uif",
            owner_address=OWNER,
            tx_hash=TX_HASH,
            scope_requested="single_tx",
            duration_days=30,
            legal_reference="Decreto 231/2007 Art. 35",
            reason="AML",
        )

        # Manually backdate the request's created_at beyond the TTL
        req = reg_manager._requests[info["request_id"]]
        req.created_at = time.time() - (PENDING_REQUEST_TTL_DAYS * 86400 + 1)

        expired_ids = reg_manager.check_expired_requests()
        assert info["request_id"] in expired_ids

        details = reg_manager.get_request(info["request_id"])
        assert details["status"] == RequestStatus.EXPIRED.value

    def test_recent_pending_request_not_expired(self, reg_manager):
        info = reg_manager.create_request(
            requester_id="uif-rome-001",
            requester_type="uif",
            owner_address=OWNER,
            tx_hash=TX_HASH,
            scope_requested="single_tx",
            duration_days=30,
            legal_reference="Decreto 231/2007 Art. 35",
            reason="AML",
        )

        expired_ids = reg_manager.check_expired_requests()
        assert info["request_id"] not in expired_ids

        details = reg_manager.get_request(info["request_id"])
        assert details["status"] == RequestStatus.PENDING_USER_APPROVAL.value

    def test_expired_requests_not_in_pending_list(self, reg_manager):
        info = reg_manager.create_request(
            requester_id="uif-rome-001",
            requester_type="uif",
            owner_address=OWNER,
            tx_hash=TX_HASH,
            scope_requested="single_tx",
            duration_days=30,
            legal_reference="Decreto 231/2007 Art. 35",
            reason="AML",
        )

        req = reg_manager._requests[info["request_id"]]
        req.created_at = time.time() - (PENDING_REQUEST_TTL_DAYS * 86400 + 1)

        # list_pending_requests auto-calls check_expired_requests
        pending = reg_manager.list_pending_requests(OWNER)
        ids = [r["request_id"] for r in pending]
        assert info["request_id"] not in ids
