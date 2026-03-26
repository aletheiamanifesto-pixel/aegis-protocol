#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for viewing_keys_service.py"""

import pytest
from datetime import datetime, timedelta
from models import ScopeType, ViewingKeyPermission


@pytest.fixture(autouse=True)
def reset_store():
    """Reset in-memory store before each test."""
    import viewing_keys_service as vks
    vks._permissions.clear()
    vks._encrypted_payloads.clear()
    vks._access_logs.clear()
    yield
    vks._permissions.clear()
    vks._encrypted_payloads.clear()
    vks._access_logs.clear()


class TestCreateViewingKey:
    def test_create_basic_key(self):
        from viewing_keys_service import create_viewing_key
        perm = create_viewing_key("0xowner1")
        assert perm.owner == "0xowner1"
        assert perm.active
        assert perm.scope == ScopeType.BALANCE_ONLY
        assert perm.expires_at > perm.granted_at

    def test_create_with_custom_scope(self):
        from viewing_keys_service import create_viewing_key
        perm = create_viewing_key("0xowner2", ScopeType.FULL_ACCESS, 7)
        assert perm.scope == ScopeType.FULL_ACCESS

    def test_duration_capped_at_90_days(self):
        from viewing_keys_service import create_viewing_key
        perm = create_viewing_key("0xowner3", duration_days=999)
        delta = perm.expires_at - perm.granted_at
        assert delta.days <= 90

    def test_duration_minimum_1_day(self):
        from viewing_keys_service import create_viewing_key
        perm = create_viewing_key("0xowner4", duration_days=0)
        delta = perm.expires_at - perm.granted_at
        assert delta.days >= 1


class TestGrantAccess:
    def test_grant_access(self):
        from viewing_keys_service import grant_access
        perm = grant_access("0xowner", "0xgrantee", ScopeType.BALANCE_ONLY, 14)
        assert perm.owner == "0xowner"
        assert perm.grantee == "0xgrantee"
        assert perm.active

    def test_grant_with_wallet_data(self):
        from viewing_keys_service import grant_access
        wallet_data = {"balance": 5000.0, "address": "0xowner", "transactions": []}
        perm = grant_access("0xowner", "0xgrantee", ScopeType.BALANCE_ONLY, wallet_data=wallet_data)
        assert perm.active


class TestRedeemViewingKey:
    def test_redeem_valid_key(self):
        from viewing_keys_service import create_viewing_key, redeem_viewing_key
        perm = create_viewing_key("0xowner")
        result = redeem_viewing_key(perm.permission_id, "0xowner")
        assert result["key_id"] == perm.permission_id
        assert "scope" in result

    def test_redeem_nonexistent_key_raises(self):
        from viewing_keys_service import redeem_viewing_key, ViewingKeyError
        with pytest.raises(ViewingKeyError):
            redeem_viewing_key("nonexistent-id", "0xgrantee")

    def test_redeem_unauthorized_raises(self):
        from viewing_keys_service import grant_access, redeem_viewing_key, ViewingKeyError
        perm = grant_access("0xowner", "0xgrantee", ScopeType.BALANCE_ONLY)
        with pytest.raises(ViewingKeyError):
            redeem_viewing_key(perm.permission_id, "0xunauthorized")

    def test_redeem_revoked_key_raises(self):
        from viewing_keys_service import create_viewing_key, revoke_viewing_key, redeem_viewing_key, ViewingKeyError
        perm = create_viewing_key("0xowner")
        revoke_viewing_key(perm.permission_id)
        with pytest.raises(ViewingKeyError):
            redeem_viewing_key(perm.permission_id, "0xowner")


class TestRevokeViewingKey:
    def test_revoke_key(self):
        from viewing_keys_service import create_viewing_key, revoke_viewing_key
        import viewing_keys_service as vks
        perm = create_viewing_key("0xowner")
        result = revoke_viewing_key(perm.permission_id, "0xowner")
        assert result is True
        assert not vks._permissions[perm.permission_id].active

    def test_revoke_nonexistent_raises(self):
        from viewing_keys_service import revoke_viewing_key, ViewingKeyError
        with pytest.raises(ViewingKeyError):
            revoke_viewing_key("bad-id")

    def test_revoke_already_revoked_ok(self):
        from viewing_keys_service import create_viewing_key, revoke_viewing_key
        perm = create_viewing_key("0xowner")
        revoke_viewing_key(perm.permission_id)
        result = revoke_viewing_key(perm.permission_id)
        assert result is True


class TestGetActiveKeys:
    def test_get_active_keys(self):
        from viewing_keys_service import create_viewing_key, get_active_keys
        create_viewing_key("0xowner_active")
        create_viewing_key("0xowner_active")
        keys = get_active_keys("0xowner_active")
        assert len(keys) == 2

    def test_revoked_key_not_in_active(self):
        from viewing_keys_service import create_viewing_key, revoke_viewing_key, get_active_keys
        perm = create_viewing_key("0xowner_revoke_test")
        revoke_viewing_key(perm.permission_id)
        keys = get_active_keys("0xowner_revoke_test")
        assert len(keys) == 0


class TestScopeFiltering:
    def test_balance_only_filter(self):
        from viewing_keys_service import _filter_by_scope
        data = {"balance": 1000, "address": "0x1", "transactions": [], "private": "secret"}
        filtered = _filter_by_scope(data, ScopeType.BALANCE_ONLY)
        assert "balance" in filtered
        assert "address" in filtered
        assert "transactions" not in filtered
        assert "private" not in filtered

    def test_full_access_filter(self):
        from viewing_keys_service import _filter_by_scope
        data = {"balance": 1000, "address": "0x1", "private": "secret"}
        filtered = _filter_by_scope(data, ScopeType.FULL_ACCESS)
        assert filtered == data
