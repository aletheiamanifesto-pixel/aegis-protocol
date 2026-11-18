#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
viewing_keys_service.py - Viewing Key lifecycle management for AEGIS Protocol.

Implements selective disclosure of wallet data via time-limited, scoped viewing keys.
"""

import hashlib
import json
import os
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any

from cryptography.fernet import Fernet

from models import ScopeType, ViewingKeyPermission, ViewingKeyRequest, AccessLog


class ViewingKeyError(Exception):
    pass


# ---------------------------------------------------------------------------
# In-memory store (replace with DB in production)
# ---------------------------------------------------------------------------

_permissions: Dict[str, ViewingKeyPermission] = {}
_encrypted_payloads: Dict[str, bytes] = {}  # permission_id -> fernet-encrypted payload
_access_logs: List[AccessLog] = []


def _get_fernet() -> Fernet:
    """Return a Fernet instance keyed from env SECRET_KEY."""
    import base64
    from aegis_env import get_secret_key

    secret = get_secret_key()
    key = base64.urlsafe_b64encode(hashlib.sha256(secret.encode()).digest())
    return Fernet(key)


# ---------------------------------------------------------------------------
# Service functions
# ---------------------------------------------------------------------------


def create_viewing_key(
    owner_address: str,
    scope: ScopeType = ScopeType.BALANCE_ONLY,
    duration_days: int = 30,
) -> ViewingKeyPermission:
    """
    Generate a viewing key for the wallet owner (self-grant).

    Args:
        owner_address: Wallet address that owns this key.
        scope: What data the key exposes.
        duration_days: How many days the key is valid (max 90).

    Returns:
        ViewingKeyPermission record.
    """
    duration_days = min(max(1, duration_days), 90)

    data_payload = json.dumps({
        "owner": owner_address,
        "scope": scope.value,
        "created": datetime.utcnow().isoformat(),
    }).encode()

    fernet = _get_fernet()
    encrypted = fernet.encrypt(data_payload)
    data_hash = "0x" + hashlib.sha256(data_payload).hexdigest()

    permission = ViewingKeyPermission(
        owner=owner_address,
        grantee=owner_address,
        scope=scope,
        data_hash=data_hash,
        granted_at=datetime.utcnow(),
        expires_at=datetime.utcnow() + timedelta(days=duration_days),
        active=True,
    )

    _permissions[permission.permission_id] = permission
    _encrypted_payloads[permission.permission_id] = encrypted
    return permission


def grant_access(
    owner_address: str,
    grantee: str,
    scope: ScopeType,
    duration_days: int = 30,
    wallet_data: Optional[Dict[str, Any]] = None,
) -> ViewingKeyPermission:
    """
    Grant selective access to wallet data to a grantee.

    Args:
        owner_address: Wallet owner granting access.
        grantee: Entity receiving access (address or identifier).
        scope: Access scope (FULL_ACCESS, BALANCE_ONLY, etc.).
        duration_days: Duration of grant (1-90 days).
        wallet_data: Optional dict of data to encrypt for grantee.

    Returns:
        ViewingKeyPermission record.
    """
    duration_days = min(max(1, duration_days), 90)

    filtered_data = _filter_by_scope(wallet_data or {}, scope)
    data_payload = json.dumps({
        "owner": owner_address,
        "grantee": grantee,
        "scope": scope.value,
        "data": filtered_data,
        "granted_at": datetime.utcnow().isoformat(),
    }).encode()

    fernet = _get_fernet()
    encrypted = fernet.encrypt(data_payload)
    data_hash = "0x" + hashlib.sha256(data_payload).hexdigest()

    permission = ViewingKeyPermission(
        owner=owner_address,
        grantee=grantee,
        scope=scope,
        data_hash=data_hash,
        granted_at=datetime.utcnow(),
        expires_at=datetime.utcnow() + timedelta(days=duration_days),
        active=True,
    )

    _permissions[permission.permission_id] = permission
    _encrypted_payloads[permission.permission_id] = encrypted

    _log_access(permission.permission_id, "grant_issued", f"Access granted to {grantee} with scope {scope.value}")
    return permission


def redeem_viewing_key(
    key_id: str,
    grantee: str,
    ip_address: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Redeem a viewing key to access wallet data.

    Args:
        key_id: The permission_id of the viewing key.
        grantee: Identifier of the entity redeeming the key.
        ip_address: IP address for audit log.

    Returns:
        Dict with scope, data_hash, and access metadata.

    Raises:
        ViewingKeyError: If key is not found, expired, or unauthorized.
    """
    permission = _permissions.get(key_id)
    if not permission:
        raise ViewingKeyError(f"Viewing key {key_id} not found")

    if not permission.active:
        raise ViewingKeyError(f"Viewing key {key_id} has been revoked")

    check_expiry(key_id)
    permission = _permissions.get(key_id)
    if not permission or not permission.active:
        raise ViewingKeyError(f"Viewing key {key_id} has expired")

    if permission.grantee != grantee and permission.owner != grantee:
        raise ViewingKeyError(f"Unauthorized: {grantee} cannot redeem key {key_id}")

    _log_access(
        key_id,
        "redeemed",
        f"Key redeemed by {grantee}",
        ip_address=ip_address,
    )

    return {
        "key_id": key_id,
        "scope": permission.scope.value,
        "data_hash": permission.data_hash,
        "owner": permission.owner,
        "grantee": permission.grantee,
        "expires_at": permission.expires_at.isoformat(),
        "accessed_at": datetime.utcnow().isoformat(),
    }


def revoke_viewing_key(key_id: str, revoker: str = "") -> bool:
    """
    Revoke a viewing key, preventing further access.

    Args:
        key_id: The permission_id to revoke.
        revoker: Who is revoking (for audit log).

    Returns:
        True if successfully revoked.
    """
    permission = _permissions.get(key_id)
    if not permission:
        raise ViewingKeyError(f"Viewing key {key_id} not found")

    if not permission.active:
        return True  # Already revoked

    updated = ViewingKeyPermission(
        permission_id=permission.permission_id,
        owner=permission.owner,
        grantee=permission.grantee,
        scope=permission.scope,
        data_hash=permission.data_hash,
        granted_at=permission.granted_at,
        expires_at=permission.expires_at,
        active=False,
        revoked_at=datetime.utcnow(),
    )
    _permissions[key_id] = updated

    _log_access(key_id, "revoked", f"Key revoked by {revoker}")
    return True


def check_expiry(key_id: str) -> bool:
    """
    Check if a viewing key has expired and auto-revoke if so.

    Returns:
        True if key is still valid, False if expired.
    """
    permission = _permissions.get(key_id)
    if not permission:
        return False

    if not permission.active:
        return False

    if datetime.utcnow() > permission.expires_at:
        updated = ViewingKeyPermission(
            permission_id=permission.permission_id,
            owner=permission.owner,
            grantee=permission.grantee,
            scope=permission.scope,
            data_hash=permission.data_hash,
            granted_at=permission.granted_at,
            expires_at=permission.expires_at,
            active=False,
            revoked_at=datetime.utcnow(),
        )
        _permissions[key_id] = updated
        _log_access(key_id, "auto_expired", "Key auto-revoked due to expiry")
        return False

    return True


def get_active_keys(owner_address: str) -> List[ViewingKeyPermission]:
    """Get all active viewing keys for an owner."""
    active = []
    for key_id, permission in list(_permissions.items()):
        if permission.owner == owner_address:
            if check_expiry(key_id):
                active.append(_permissions[key_id])
    return active


def get_access_logs(key_id: str) -> List[AccessLog]:
    """Get all access logs for a specific viewing key."""
    return [log for log in _access_logs if log.permission_id == key_id]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _filter_by_scope(data: Dict[str, Any], scope: ScopeType) -> Dict[str, Any]:
    """Filter wallet data based on the access scope."""
    if scope == ScopeType.FULL_ACCESS:
        return data
    elif scope == ScopeType.BALANCE_ONLY:
        return {k: v for k, v in data.items() if k in ("balance", "address")}
    elif scope == ScopeType.TRANSACTIONS_ONLY:
        return {k: v for k, v in data.items() if k in ("transactions", "address")}
    elif scope == ScopeType.LIMITED:
        return {k: v for k, v in data.items() if k in ("address",)}
    return {}


def _log_access(
    permission_id: str,
    action: str,
    notes: str = "",
    ip_address: Optional[str] = None,
) -> None:
    """Record an access event to the audit log."""
    log = AccessLog(
        permission_id=permission_id,
        accessed_at=datetime.utcnow(),
        data_accessed=action,
        ip_address=ip_address,
        approved=True,
        notes=notes,
    )
    _access_logs.append(log)
