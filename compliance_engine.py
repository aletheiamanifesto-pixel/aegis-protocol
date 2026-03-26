#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
compliance_engine.py — KYC/AML compliance engine for the AEGIS Protocol.

Provides ``check_compliance(account)`` which returns a :class:`ComplianceStatus`
summarising the KYC verification state, AML screening result, risk tier, and
applicable transaction limits for a given Ethereum address.

In production this module would connect to:
- A licensed KYC provider (e.g. Sumsub, Onfido) via REST API.
- An on-chain AML oracle or OFAC sanctions list mirror.
- The institution's internal risk-scoring database.

The current implementation uses an in-memory mock registry so that the full
API surface can be exercised without external dependencies.
"""

import hashlib
import re
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ComplianceStatus(BaseModel):
    """KYC/AML compliance status for a single Ethereum address."""

    account: str = Field(..., description="Checksummed Ethereum address")
    kyc_verified: bool = Field(..., description="True if KYC has been completed")
    aml_screened: bool = Field(..., description="True if AML screening is current")
    risk_level: RiskLevel = Field(..., description="Computed risk tier")
    daily_limit_eur: float = Field(..., description="Maximum daily EUR volume")
    single_tx_limit_eur: float = Field(..., description="Maximum single-transaction EUR amount")
    last_check: datetime = Field(..., description="Timestamp of this compliance check")
    notes: Optional[str] = Field(None, description="Human-readable compliance notes")

    model_config = {"json_schema_extra": {"example": {
        "account": "0xAbCd...",
        "kyc_verified": True,
        "aml_screened": True,
        "risk_level": "low",
        "daily_limit_eur": 1_000_000.0,
        "single_tx_limit_eur": 100_000.0,
        "last_check": "2026-01-01T00:00:00Z",
    }}}


# ---------------------------------------------------------------------------
# Internal mock registry
# ---------------------------------------------------------------------------
# Keys are lowercase Ethereum addresses; values are partial ComplianceStatus dicts.
# Replace this with a real database / API call in production.

_MOCK_REGISTRY: dict = {
    # Fully verified institutional account
    "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": {
        "kyc_verified": True,
        "aml_screened": True,
        "risk_level": RiskLevel.LOW,
        "daily_limit_eur": 10_000_000.0,
        "single_tx_limit_eur": 1_000_000.0,
        "notes": "Tier-1 institutional account",
    },
    # KYC done but AML pending — medium risk
    "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb": {
        "kyc_verified": True,
        "aml_screened": False,
        "risk_level": RiskLevel.MEDIUM,
        "daily_limit_eur": 50_000.0,
        "single_tx_limit_eur": 10_000.0,
        "notes": "AML screening in progress",
    },
    # High-risk / sanctioned placeholder
    "0xcccccccccccccccccccccccccccccccccccccccc": {
        "kyc_verified": False,
        "aml_screened": True,
        "risk_level": RiskLevel.CRITICAL,
        "daily_limit_eur": 0.0,
        "single_tx_limit_eur": 0.0,
        "notes": "Account flagged — pending manual review",
    },
}

# Default profile for unknown addresses (unverified retail)
_DEFAULT_PROFILE: dict = {
    "kyc_verified": False,
    "aml_screened": False,
    "risk_level": RiskLevel.HIGH,
    "daily_limit_eur": 1_000.0,
    "single_tx_limit_eur": 500.0,
    "notes": "Unverified account — default limits apply",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_ETH_ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")


def _normalise_address(account: str) -> str:
    """Return the lowercase form of *account* after basic format validation."""
    if not _ETH_ADDRESS_RE.match(account):
        raise ValueError(f"Invalid Ethereum address: {account!r}")
    return account.lower()


def _derive_risk_level(kyc: bool, aml: bool) -> RiskLevel:
    """Derive a risk level from the KYC/AML flags for unknown accounts."""
    if kyc and aml:
        return RiskLevel.LOW
    if kyc or aml:
        return RiskLevel.MEDIUM
    return RiskLevel.HIGH


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check_compliance(account: str) -> ComplianceStatus:
    """Return the compliance status for *account*.

    Args:
        account: An Ethereum address (hex, with or without checksum).

    Returns:
        A :class:`ComplianceStatus` instance with current KYC/AML data.

    Raises:
        ValueError: If *account* is not a valid Ethereum address format.
    """
    normalised = _normalise_address(account)
    profile = _MOCK_REGISTRY.get(normalised, _DEFAULT_PROFILE).copy()

    return ComplianceStatus(
        account=account,
        kyc_verified=profile["kyc_verified"],
        aml_screened=profile["aml_screened"],
        risk_level=profile["risk_level"],
        daily_limit_eur=profile["daily_limit_eur"],
        single_tx_limit_eur=profile["single_tx_limit_eur"],
        last_check=datetime.now(timezone.utc),
        notes=profile.get("notes"),
    )


def is_transaction_allowed(account: str, amount_eur: float) -> tuple[bool, str]:
    """Check whether a single transaction of *amount_eur* is allowed for *account*.

    Returns:
        A tuple of (``allowed``, ``reason``).
    """
    status = check_compliance(account)
    if not status.kyc_verified:
        return False, "KYC verification required"
    if status.risk_level == RiskLevel.CRITICAL:
        return False, "Account is blocked — critical risk level"
    if amount_eur > status.single_tx_limit_eur:
        return False, (
            f"Amount {amount_eur:.2f} EUR exceeds single-transaction limit "
            f"{status.single_tx_limit_eur:.2f} EUR"
        )
    return True, "Transaction permitted"

