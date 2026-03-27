#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
compliance_engine.py - MiCA Compliance Engine for AEGIS Protocol
"""

import hashlib
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from bundler.adaptive_velocity import VelocityTracker
from bundler.config import BundlerConfig


MICA_ZK_THRESHOLD_EUR: float = 1000.0
MAX_DAILY_DEFAULT: float = 10_000.0
MAX_SINGLE_DEFAULT: float = 5_000.0

_velocity_tracker = VelocityTracker()
_default_config = BundlerConfig()


@dataclass
class ComplianceResult:
    approved: bool
    message: str
    requires_zk_proof: bool = False
    risk_level: str = "low"
    flags: List[str] = field(default_factory=list)


@dataclass
class ZKProofStub:
    proof_hash: str
    public_inputs: Dict
    valid_until: int
    generated_at: int


class ComplianceError(Exception):
    pass


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
        op_type: str = "single_tx",
    ) -> ComplianceResult:
        flags: List[str] = []

        if amount <= 0:
            return ComplianceResult(
                approved=False,
                message="Amount must be positive",
                requires_zk_proof=False,
                risk_level="low",
            )

        if amount > single_tx_limit:
            flags.append("SINGLE_TX_LIMIT_EXCEEDED")
            return ComplianceResult(
                approved=False,
                message=f"Transaction amount {amount} EUR exceeds single-tx limit {single_tx_limit} EUR",
                requires_zk_proof=True,
                risk_level="high",
                flags=flags,
            )

        if daily_spent + amount > daily_limit:
            flags.append("DAILY_LIMIT_EXCEEDED")
            return ComplianceResult(
                approved=False,
                message=f"Daily limit {daily_limit} EUR would be exceeded",
                requires_zk_proof=True,
                risk_level="medium",
                flags=flags,
            )

        velocity_limit = _default_config.velocity_limits.get(op_type, 30)
        if not _velocity_tracker.check(sender, op_type, velocity_limit):
            flags.append("VELOCITY_LIMIT_EXCEEDED")
            tx_count = _velocity_tracker.get_count(sender, op_type)
            return ComplianceResult(
                approved=False,
                message=(
                    f"Velocity limit exceeded for op_type={op_type}: "
                    f"{tx_count} transactions in last 60 seconds"
                ),
                requires_zk_proof=False,
                risk_level="high",
                flags=flags,
            )

        requires_zk = amount >= MICA_ZK_THRESHOLD_EUR
        if requires_zk:
            flags.append("ZK_PROOF_REQUIRED")
            if not kyc_verified:
                return ComplianceResult(
                    approved=False,
                    message=f"Transactions >= {MICA_ZK_THRESHOLD_EUR} EUR require KYC verification",
                    requires_zk_proof=True,
                    risk_level="medium",
                    flags=flags,
                )

        _velocity_tracker.record(sender, op_type)

        return ComplianceResult(
            approved=True,
            message="Transaction approved",
            requires_zk_proof=requires_zk,
            risk_level="low" if not flags else "medium",
            flags=flags,
        )

    def generate_zk_proof_stub(self, sender: str, amount: float, purpose: str = "transfer") -> ZKProofStub:
        """Generate a deterministic ZK proof stub (SHA-256 based) for development."""
        now = int(time.time())
        raw = f"{sender}:{amount}:{purpose}:{now}".encode()
        proof_hash = "0x" + hashlib.sha256(raw).hexdigest()
        return ZKProofStub(
            proof_hash=proof_hash,
            public_inputs={
                "sender_hash": hashlib.sha256(sender.encode()).hexdigest(),
                "amount_range": amount >= MICA_ZK_THRESHOLD_EUR,
            },
            valid_until=now + 3600,
            generated_at=now,
        )

    def get_mica_threshold(self) -> float:
        return MICA_ZK_THRESHOLD_EUR
