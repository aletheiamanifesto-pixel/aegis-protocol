#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
compliance_engine.py - MiCA Compliance Engine for AEGIS Protocol

Handles:
  - KYC verification checks
  - AML / velocity-limit screening
  - ZK proof requirement determination (MiCA threshold: >= 1000 EUR)
  - Suspicious-activity detection
"""

import hashlib
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MICA_ZK_THRESHOLD_EUR: float = 1000.0   # >= triggers ZK-KYC proof requirement
MAX_TX_PER_MINUTE: int = 5               # velocity window
MAX_DAILY_DEFAULT: float = 10_000.0
MAX_SINGLE_DEFAULT: float = 5_000.0


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class ComplianceResult:
    approved: bool
    message: str
    requires_zk_proof: bool = False
    risk_level: str = "low"
    flags: List[str] = field(default_factory=list)


@dataclass
class ZKProofStub:
    """Deterministic proof stub (SHA-256 based) used until a real ZK circuit is wired in."""
    proof_hash: str
    public_inputs: Dict
    valid_until: int  # unix timestamp
    generated_at: int


class ComplianceError(Exception):
    pass


# ---------------------------------------------------------------------------
# In-memory velocity tracker (production: use Redis / DB)
# ---------------------------------------------------------------------------

_velocity_store: Dict[str, List[float]] = {}  # address -> list of timestamps


def _record_tx(address: str) -> int:
    """Record a transaction timestamp and return count in last 60 s."""
    now = time.time()
    timestamps = _velocity_store.setdefault(address, [])
    timestamps.append(now)
    # prune old entries
    _velocity_store[address] = [t for t in timestamps if now - t <= 60]
    return len(_velocity_store[address])


def _tx_count_last_minute(address: str) -> int:
    now = time.time()
    return sum(1 for t in _velocity_store.get(address, []) if now - t <= 60)


# ---------------------------------------------------------------------------
# Compliance Engine
# ---------------------------------------------------------------------------


class ComplianceEngine:
    """Evaluate whether a transaction satisfies MiCA compliance rules."""

    def check_transaction(
        self,
        sender: str,
        amount: float,
        kyc_verified: bool = False,
        daily_spent: float = 0.0,
        daily_limit: float = MAX_DAILY_DEFAULT,
        single_tx_limit: float = MAX_SINGLE_DEFAULT,
    ) -> ComplianceResult:
        flags: List[str] = []

        # --- Negative amount guard ---
        if amount <= 0:
            return ComplianceResult(
                approved=False,
                message="Transaction amount must be positive",
                risk_level="low",
            )

        # --- Single-transaction limit ---
        if amount > single_tx_limit:
            return ComplianceResult(
                approved=False,
                message=f"Amount {amount} EUR exceeds single-transaction limit {single_tx_limit} EUR",
                risk_level="high",
                flags=["single_tx_limit_exceeded"],
            )

        # --- Daily limit ---
        if daily_spent + amount > daily_limit:
            return ComplianceResult(
                approved=False,
                message=f"Daily limit {daily_limit} EUR would be exceeded",
                risk_level="medium",
                flags=["daily_limit_exceeded"],
            )

        # --- Velocity check ---
        tx_count = _tx_count_last_minute(sender)
        if tx_count >= MAX_TX_PER_MINUTE:
            flags.append("velocity_exceeded")
            return ComplianceResult(
                approved=False,
                message=f"Velocity limit exceeded: {tx_count} transactions in last 60 s",
                risk_level="high",
                flags=flags,
            )

        # --- MiCA ZK-KYC threshold ---
        requires_zk = amount >= MICA_ZK_THRESHOLD_EUR
        if requires_zk and not kyc_verified:
            flags.append("zk_proof_required")
            return ComplianceResult(
                approved=False,
                message=(
                    f"Transactions >= {MICA_ZK_THRESHOLD_EUR} EUR require a ZK-KYC proof "
                    f"(MiCA Article 83). Please complete KYC first."
                ),
                requires_zk_proof=True,
                risk_level="medium",
                flags=flags,
            )

        if requires_zk:
            flags.append("zk_proof_required")

        # --- Record and approve ---
        _record_tx(sender)
        risk = "medium" if requires_zk else "low"
        return ComplianceResult(
            approved=True,
            message="Transaction approved",
            requires_zk_proof=requires_zk,
            risk_level=risk,
            flags=flags,
        )

    def verify_kyc(self, user_id: str, document_hash: str) -> ComplianceResult:
        """
        Stub for KYC verification.  In production this would call an
        identity-provider API (e.g. Onfido / Jumio).
        """
        if not document_hash or len(document_hash) < 8:
            return ComplianceResult(
                approved=False,
                message="Invalid KYC document hash",
                risk_level="high",
            )
        # Deterministic acceptance for demo
        return ComplianceResult(
            approved=True,
            message="KYC verification passed",
            risk_level="low",
        )

    def generate_zk_proof(self, user_id: str, amount: float, purpose: str = "kyc") -> ZKProofStub:
        """
        Generate a deterministic ZK-proof stub (SHA-256 of inputs).
        Production: replace with real Groth16 / PLONK circuit call.
        """
        raw = f"{user_id}:{amount}:{purpose}:{int(time.time() // 3600)}"
        proof_hash = "0x" + hashlib.sha256(raw.encode()).hexdigest()
        now = int(time.time())
        return ZKProofStub(
            proof_hash=proof_hash,
            public_inputs={
                "user_id_hash": "0x" + hashlib.sha256(user_id.encode()).hexdigest(),
                "amount_range": f">= {MICA_ZK_THRESHOLD_EUR}",
                "purpose": purpose,
            },
            valid_until=now + 86_400,  # 24 h
            generated_at=now,
        )

