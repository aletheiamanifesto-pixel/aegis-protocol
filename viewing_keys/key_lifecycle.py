#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
viewing_keys/key_lifecycle.py - Utility functions for viewing key lifecycle management.
"""

import time
from typing import Dict, List, Tuple

from viewing_keys.scope_filter import KeyStatus


def check_key_validity(record) -> Tuple[bool, str]:
    """Check whether a key is still usable.

    Args:
        record: ViewingKeyRecord instance.

    Returns:
        (is_valid, reason) tuple.
    """
    if record.status == KeyStatus.REVOKED:
        return False, "key has been revoked"

    if record.expires_at is not None and time.time() > record.expires_at:
        return False, "key has expired"

    if record.max_uses is not None and record.use_count >= record.max_uses:
        return False, "max uses exhausted"

    return True, "ok"


def cascade_revoke(keys_store: Dict, key_id: str) -> List[str]:
    """Revoke a key and all its sub-keys recursively.

    Args:
        keys_store: The dict mapping key_id -> ViewingKeyRecord.
        key_id: The key to start revocation from.

    Returns:
        List of all key_ids that were revoked.
    """
    revoked: List[str] = []
    _revoke_recursive(keys_store, key_id, revoked)
    return revoked


def _revoke_recursive(keys_store: Dict, key_id: str, revoked: List[str]) -> None:
    record = keys_store.get(key_id)
    if record is None:
        return
    if record.status != KeyStatus.REVOKED:
        record.status = KeyStatus.REVOKED
        record.revoked_at = time.time()
        revoked.append(key_id)
    for child_id in list(record.children_ids):
        _revoke_recursive(keys_store, child_id, revoked)


def find_keys_by_address(keys_store: Dict, address: str) -> List[str]:
    """Find all key_ids (master + sub) for an address.

    Args:
        keys_store: The dict mapping key_id -> ViewingKeyRecord.
        address: The wallet address.

    Returns:
        List of key_ids belonging to that address.
    """
    return [kid for kid, rec in keys_store.items() if rec.address == address]
