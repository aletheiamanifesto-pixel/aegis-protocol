"""
compliance_engine.py - MiCA Compliance Engine for AEGIS Protocol

Implements MiCA regulatory rules for Euro Digital transactions.
Transactions above the threshold require ZK-KYC verification.
"""

from dataclasses import dataclass
from typing import Optional

from models import EuroDigitalTransaction, ComplianceRule, TransactionStatus


# MiCA threshold in EUR: transactions above this require ZK proof
MICA_THRESHOLD_EUR = 1000.0


@dataclass
class ComplianceResult:
    """Result of a compliance check."""
    approved: bool
    message: str
    requires_zk_proof: bool = False
    rule_id: Optional[str] = None


class ComplianceEngine:
    """
    MiCA Compliance Engine.

    Evaluates Euro Digital transactions against MiCA regulatory rules.
    Transactions exceeding the threshold require ZK-KYC verification.
    """

    def __init__(self, threshold: float = MICA_THRESHOLD_EUR):
        self.threshold = threshold
        self.mica_rule = ComplianceRule(
            rule_id="MICA-001",
            rule_type="transaction_limit",
            trigger_amount=threshold,
            action="require_proof",
            description=(
                "MiCA Art. 68 – Transazioni superiori a "
                f"{threshold}€ richiedono verifica ZK-KYC"
            ),
            active=True,
        )

    def check_transaction(self, transaction: EuroDigitalTransaction) -> ComplianceResult:
        """
        Evaluate a single transaction against MiCA rules.

        Args:
            transaction: The Euro Digital transaction to evaluate.

        Returns:
            ComplianceResult with approval status and message.
        """
        if not self.mica_rule.active:
            return ComplianceResult(
                approved=True,
                message="Approvata",
                rule_id=self.mica_rule.rule_id,
            )

        if transaction.amount > self.threshold:
            return ComplianceResult(
                approved=False,
                message="Serve verifica ZK",
                requires_zk_proof=True,
                rule_id=self.mica_rule.rule_id,
            )

        return ComplianceResult(
            approved=True,
            message="Approvata",
            rule_id=self.mica_rule.rule_id,
        )

    def check_transaction_with_proof(
        self,
        transaction: EuroDigitalTransaction,
        proof_hash: Optional[str] = None,
    ) -> ComplianceResult:
        """
        Evaluate a transaction, accepting a ZK proof for high-value ones.

        Args:
            transaction: The Euro Digital transaction to evaluate.
            proof_hash: Optional ZK proof hash for high-value transactions.

        Returns:
            ComplianceResult with approval status and message.
        """
        result = self.check_transaction(transaction)

        if not result.approved and result.requires_zk_proof and proof_hash:
            # ZK proof provided — transaction can proceed
            return ComplianceResult(
                approved=True,
                message="Approvata",
                requires_zk_proof=False,
                rule_id=self.mica_rule.rule_id,
            )

        return result
