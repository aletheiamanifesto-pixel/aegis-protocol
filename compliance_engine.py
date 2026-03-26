"""
compliance_engine.py - MiCA Compliance Engine for AEGIS Protocol

Ensures that EUR Digital transactions comply with MiCA regulations.
Key rules:
- Transactions >= 1000 EUR require ZK-KYC proof.
- Max 5 transactions per minute velocity window.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional

from models import EuroDigitalTransaction, TransactionStatus

MICA_THRESHOLD_EUR = 1000.0
MAX_TX_PER_MINUTE = 5


@dataclass
class ComplianceResult:
    """Result of a compliance check."""
    compliant: bool
    transaction_status: TransactionStatus
    flags: List[str] = field(default_factory=list)
    message: str = ""


class ComplianceEngine:
    """Simulates MiCA compliance checks on EUR Digital transactions."""

    def __init__(self) -> None:
        self._recent_txs: List[float] = []

    def _check_velocity(self, timestamp: int) -> Optional[str]:
        """Check if transaction velocity exceeds the allowed limit."""
        now = float(timestamp)
        window_start = now - 60.0
        self._recent_txs = [t for t in self._recent_txs if t > window_start]
        if len(self._recent_txs) >= MAX_TX_PER_MINUTE:
            return "VELOCITY_EXCEEDED: more than 5 transactions in 60s window"
        self._recent_txs.append(now)
        return None

    def _check_mica_threshold(self, tx: EuroDigitalTransaction) -> Optional[str]:
        """Transactions >= 1000 EUR require a ZK-KYC proof hash."""
        if tx.amount >= MICA_THRESHOLD_EUR and not tx.proof_hash:
            return (
                f"MICA_PROOF_REQUIRED: amount {tx.amount} EUR >= {MICA_THRESHOLD_EUR} EUR "
                "requires a ZK-KYC proof_hash"
            )
        return None

    def check_transaction(self, tx: EuroDigitalTransaction) -> ComplianceResult:
        """Run all compliance checks on a single transaction.

        Returns a ComplianceResult indicating whether the transaction is
        compliant, along with any flags raised during the checks.
        """
        flags: List[str] = []

        velocity_flag = self._check_velocity(tx.timestamp)
        if velocity_flag:
            flags.append(velocity_flag)

        mica_flag = self._check_mica_threshold(tx)
        if mica_flag:
            flags.append(mica_flag)

        if flags:
            return ComplianceResult(
                compliant=False,
                transaction_status=TransactionStatus.FAILED,
                flags=flags,
                message="Transaction failed compliance checks.",
            )

        return ComplianceResult(
            compliant=True,
            transaction_status=TransactionStatus.VERIFIED,
            flags=[],
            message="Transaction is MiCA compliant.",
        )
