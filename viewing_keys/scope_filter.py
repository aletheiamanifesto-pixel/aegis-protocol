#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
viewing_keys/scope_filter.py - KeyScope, KeyStatus enums and scope-based data filtering.
"""

from enum import Enum
from typing import Any, Dict


class KeyScope(str, Enum):
    FULL_ACCESS = "full_access"
    BALANCE_ONLY = "balance_only"
    TX_ONLY = "tx_only"
    SINGLE_TX = "single_tx"
    AMOUNT_RANGE = "amount_range"
    LIMITED = "limited"


class KeyStatus(str, Enum):
    ACTIVE = "active"
    REVOKED = "revoked"
    EXPIRED = "expired"


def filter_by_scope(data: Dict[str, Any], scope: KeyScope) -> Dict[str, Any]:
    """Filter decrypted data based on viewing key scope.

    FULL_ACCESS  → entire original dict
    BALANCE_ONLY → {"balance": ..., "address": ...}
    TX_ONLY      → {"transactions": [...]} (if present)
    SINGLE_TX    → {"tx_hash": ..., "amount": ..., "timestamp": ...}
    AMOUNT_RANGE → {"amount_in_range": True/False}
    LIMITED      → {"address": ...}
    """
    if scope == KeyScope.FULL_ACCESS:
        return dict(data)

    if scope == KeyScope.BALANCE_ONLY:
        result = {}
        if "balance" in data:
            result["balance"] = data["balance"]
        if "address" in data:
            result["address"] = data["address"]
        return result

    if scope == KeyScope.TX_ONLY:
        result = {}
        if "transactions" in data:
            result["transactions"] = data["transactions"]
        return result

    if scope == KeyScope.SINGLE_TX:
        result = {}
        for field in ("tx_hash", "amount", "timestamp"):
            if field in data:
                result[field] = data[field]
        return result

    if scope == KeyScope.AMOUNT_RANGE:
        amount = data.get("amount")
        min_amount = data.get("min_amount")
        max_amount = data.get("max_amount")
        in_range = False
        if amount is not None and min_amount is not None and max_amount is not None:
            in_range = min_amount <= amount <= max_amount
        return {"amount_in_range": in_range}

    if scope == KeyScope.LIMITED:
        result = {}
        if "address" in data:
            result["address"] = data["address"]
        return result

    return dict(data)
