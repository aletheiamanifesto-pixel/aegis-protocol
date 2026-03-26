#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
compliance_engine.py – MiCA Compliance Engine for AEGIS Protocol

Implements:
  1. MiCA compliance rule set via ``ComplianceRule`` (models.py).
  2. ``verify_transaction_limits`` – enforces the 1 000 € MiCA threshold
     (transactions above the threshold require a ZK-KYC proof).
  3. ``SuspiciousActivityReporter`` (SAR) – velocity-based monitoring that
     detects > 5 transactions/minute and triggers REGULATOR_ROLE freezing.

All public functions are **async** with structured error handling so that
every compliance failure is captured as a typed ``ComplianceError``.
"""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from models import (
    ComplianceProfile,
    ComplianceRule,
    EuroDigitalTransaction,
    SuspiciousActivityReport,
)

# ──────────────────────────────────────────────────────────────────────────────
# Logging
# ──────────────────────────────────────────────────────────────────────────────
logger = logging.getLogger("aegis.compliance")
logger.setLevel(logging.DEBUG)

if not logger.handlers:
    _handler = logging.StreamHandler()
    _handler.setFormatter(
        logging.Formatter("[%(asctime)s] %(levelname)s %(name)s – %(message)s")
    )
    logger.addHandler(_handler)


# ──────────────────────────────────────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────────────────────────────────────
MICA_THRESHOLD_EUR: float = 1_000.0
"""MiCA single-transaction threshold (EUR).  Transactions above this amount
require a mandatory ZK-KYC proof before being forwarded to the EntryPoint."""

MAX_TX_PER_MINUTE: int = 5
"""Maximum number of transactions allowed within a 60-second rolling window.
Exceeding this limit triggers a Suspicious Activity Report (SAR)."""

VELOCITY_WINDOW_SECONDS: int = 60
"""Duration of the rolling window used by :class:`SuspiciousActivityReporter`
for velocity checks."""


# ──────────────────────────────────────────────────────────────────────────────
# Custom Errors
# ──────────────────────────────────────────────────────────────────────────────
class ComplianceErrorType(str, Enum):
    """Enumeration of compliance failure categories."""

    THRESHOLD_EXCEEDED = "threshold_exceeded"
    ZK_PROOF_REQUIRED = "zk_proof_required"
    ZK_PROOF_MISSING = "zk_proof_missing"
    VELOCITY_BREACH = "velocity_breach"
    DAILY_LIMIT_EXCEEDED = "daily_limit_exceeded"
    KYC_NOT_VERIFIED = "kyc_not_verified"
    RULE_VIOLATION = "rule_violation"
    ACCOUNT_FROZEN = "account_frozen"


class ComplianceError(Exception):
    """Raised when a compliance check fails.

    Attributes:
        error_type: The specific category of the failure.
        details:    Human-readable description.
        metadata:   Arbitrary key/value pairs for audit logging.
    """

    def __init__(
        self,
        error_type: ComplianceErrorType,
        details: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.error_type = error_type
        self.details = details
        self.metadata = metadata or {}
        super().__init__(f"[{error_type.value}] {details}")


# ──────────────────────────────────────────────────────────────────────────────
# §1 – MiCA Compliance Rule Set
# ──────────────────────────────────────────────────────────────────────────────
def build_mica_rules() -> List[ComplianceRule]:
    """Create the canonical set of MiCA compliance rules for Aegis.

    Returns:
        A list of :class:`ComplianceRule` instances covering:
        - Single-transaction KYC threshold (1 000 €)
        - Large-transaction enhanced due-diligence (10 000 €)
        - Daily cumulative limit (15 000 €)
        - Anti-money-laundering screening threshold (50 000 €)
    """
    now = datetime.now(tz=timezone.utc)
    return [
        ComplianceRule(
            rule_id="MICA-001",
            rule_type="transaction_limit",
            trigger_amount=MICA_THRESHOLD_EUR,
            action="require_proof",
            description=(
                "MiCA Art. 68 – Single transactions exceeding 1 000 EUR "
                "require mandatory ZK-KYC proof before execution."
            ),
            effective_from=now,
            active=True,
        ),
        ComplianceRule(
            rule_id="MICA-002",
            rule_type="kyc",
            trigger_amount=10_000.0,
            action="require_proof",
            description=(
                "MiCA enhanced due-diligence – Transactions above 10 000 EUR "
                "require enhanced KYC verification and proof of source of funds."
            ),
            effective_from=now,
            active=True,
        ),
        ComplianceRule(
            rule_id="MICA-003",
            rule_type="transaction_limit",
            trigger_amount=15_000.0,
            action="block",
            description=(
                "MiCA daily cumulative limit – Users without enhanced KYC "
                "cannot exceed 15 000 EUR in daily cumulative transactions."
            ),
            effective_from=now,
            active=True,
        ),
        ComplianceRule(
            rule_id="MICA-004",
            rule_type="aml",
            trigger_amount=50_000.0,
            action="notify",
            description=(
                "AML reporting threshold – Transactions exceeding 50 000 EUR "
                "trigger an automatic SAR notification to regulators."
            ),
            effective_from=now,
            active=True,
        ),
    ]


# ──────────────────────────────────────────────────────────────────────────────
# §2 – Transaction Limit Verification
# ──────────────────────────────────────────────────────────────────────────────
@dataclass
class TransactionVerificationResult:
    """Outcome of :func:`verify_transaction_limits`.

    Attributes:
        allowed:            Whether the transaction may proceed.
        requires_zk_proof:  ``True`` if a ZK-KYC proof must be attached.
        triggered_rules:    List of rule IDs that were activated.
        message:            Human-readable summary.
    """

    allowed: bool
    requires_zk_proof: bool = False
    triggered_rules: List[str] = field(default_factory=list)
    message: str = ""


async def verify_transaction_limits(
    amount: float,
    user_history: List[EuroDigitalTransaction],
    profile: Optional[ComplianceProfile] = None,
    rules: Optional[List[ComplianceRule]] = None,
) -> TransactionVerificationResult:
    """Verify whether a transaction complies with MiCA limits.

    Algorithm:
      1. Load the MiCA rule set (or use the caller-supplied override).
      2. Compute the 24-hour cumulative spend from *user_history*.
      3. Walk the active rules in ascending ``trigger_amount`` order.
      4. For every triggered rule, record it and determine the required action.
      5. If the amount exceeds the 1 000 € MiCA threshold → ZK-KYC proof
         is **mandatory**.

    Args:
        amount:       Transaction amount in EUR.
        user_history: Recent transactions by the same user.
        profile:      Optional :class:`ComplianceProfile` for daily-limit
                      checks.  If ``None`` a permissive default is used.
        rules:        Optional custom rule list.  Defaults to
                      :func:`build_mica_rules`.

    Returns:
        A :class:`TransactionVerificationResult` describing the outcome.

    Raises:
        ComplianceError: On unrecoverable compliance violations (e.g. the
            daily cumulative limit has been exceeded).
    """
    if amount <= 0:
        raise ComplianceError(
            ComplianceErrorType.RULE_VIOLATION,
            "Transaction amount must be positive.",
            {"amount": amount},
        )

    active_rules = rules or build_mica_rules()
    active_rules = [r for r in active_rules if r.active]
    active_rules.sort(key=lambda r: r.trigger_amount)

    # ── Compute 24h cumulative spend ──────────────────────────────────────
    now_ts = int(time.time())
    twenty_four_hours_ago = now_ts - 86_400
    daily_total = sum(
        tx.amount for tx in user_history if tx.timestamp >= twenty_four_hours_ago
    )
    daily_total_with_new = daily_total + amount

    triggered: List[str] = []
    requires_zk = False
    blocked = False

    for rule in active_rules:
        if rule.rule_type == "transaction_limit" and rule.trigger_amount <= amount:
            triggered.append(rule.rule_id)
            if rule.action == "require_proof":
                requires_zk = True
                logger.info(
                    "Rule %s triggered: amount %.2f EUR ≥ threshold %.2f EUR → ZK-KYC proof required",
                    rule.rule_id,
                    amount,
                    rule.trigger_amount,
                )
            elif rule.action == "block":
                # Check if enhanced KYC is present
                if profile and profile.kyc_verified:
                    logger.info(
                        "Rule %s triggered but user has enhanced KYC – allowing",
                        rule.rule_id,
                    )
                else:
                    blocked = True
                    logger.warning(
                        "Rule %s triggered: daily cumulative %.2f EUR → BLOCKED",
                        rule.rule_id,
                        daily_total_with_new,
                    )

        elif rule.rule_type == "kyc" and amount >= rule.trigger_amount:
            triggered.append(rule.rule_id)
            requires_zk = True
            logger.info(
                "Rule %s triggered: enhanced KYC required for %.2f EUR",
                rule.rule_id,
                amount,
            )

        elif rule.rule_type == "aml" and amount >= rule.trigger_amount:
            triggered.append(rule.rule_id)
            logger.warning(
                "Rule %s triggered: AML notification for %.2f EUR",
                rule.rule_id,
                amount,
            )

    # ── Daily limit check ────────────────────────────────────────────────
    if profile and daily_total_with_new > profile.daily_limit:
        raise ComplianceError(
            ComplianceErrorType.DAILY_LIMIT_EXCEEDED,
            (
                f"Daily cumulative {daily_total_with_new:.2f} EUR exceeds "
                f"limit {profile.daily_limit:.2f} EUR."
            ),
            {
                "daily_total": daily_total_with_new,
                "limit": profile.daily_limit,
            },
        )

    if blocked:
        raise ComplianceError(
            ComplianceErrorType.THRESHOLD_EXCEEDED,
            (
                f"Transaction of {amount:.2f} EUR blocked: "
                "daily limit exceeded without enhanced KYC."
            ),
            {"amount": amount, "daily_total": daily_total_with_new},
        )

    # ── MiCA mandatory ZK-KYC ────────────────────────────────────────────
    if amount > MICA_THRESHOLD_EUR:
        requires_zk = True
        if "MICA-001" not in triggered:
            triggered.append("MICA-001")

    message_parts: List[str] = []
    if requires_zk:
        message_parts.append("ZK-KYC proof required")
    if triggered:
        message_parts.append(f"triggered rules: {', '.join(triggered)}")

    return TransactionVerificationResult(
        allowed=True,
        requires_zk_proof=requires_zk,
        triggered_rules=triggered,
        message="; ".join(message_parts) if message_parts else "Transaction compliant",
    )


# ──────────────────────────────────────────────────────────────────────────────
# §3 – Suspicious Activity Reporter (SAR)
# ──────────────────────────────────────────────────────────────────────────────
@dataclass
class FreezeAction:
    """Describes a REGULATOR_ROLE freeze triggered by the SAR.

    Attributes:
        user_id:       Address / ID of the frozen account.
        reason:        Why the account was frozen.
        frozen_at:     Timestamp of the freeze.
        report:        The associated :class:`SuspiciousActivityReport`.
        auto_unfreeze: Optional future timestamp when the freeze expires.
    """

    user_id: str
    reason: str
    frozen_at: datetime
    report: SuspiciousActivityReport
    auto_unfreeze: Optional[datetime] = None


class SuspiciousActivityReporter:
    """Monitors transaction velocity and generates SARs.

    The reporter maintains a per-user sliding window of transaction timestamps.
    If a user exceeds ``max_tx_per_window`` within ``window_seconds``, the
    reporter:

    1. Generates a :class:`SuspiciousActivityReport`.
    2. Activates the REGULATOR_ROLE for temporary account freezing.
    3. Returns a :class:`FreezeAction` describing what happened.

    Thread-safety: uses an :class:`asyncio.Lock` per user.
    """

    def __init__(
        self,
        max_tx_per_window: int = MAX_TX_PER_MINUTE,
        window_seconds: int = VELOCITY_WINDOW_SECONDS,
        freeze_duration_minutes: int = 30,
    ) -> None:
        self._max_tx = max_tx_per_window
        self._window = window_seconds
        self._freeze_minutes = freeze_duration_minutes

        # user_id → list of unix-epoch timestamps
        self._tx_timestamps: Dict[str, List[float]] = defaultdict(list)
        # user_id → True if currently frozen
        self._frozen_accounts: Dict[str, bool] = {}
        # All generated SARs
        self._reports: List[SuspiciousActivityReport] = []
        # All freeze actions
        self._freeze_actions: List[FreezeAction] = []
        # Per-user async lock
        self._locks: Dict[str, asyncio.Lock] = defaultdict(asyncio.Lock)

    # ── Public API ────────────────────────────────────────────────────────

    async def record_transaction(
        self, user_id: str, tx: Optional[EuroDigitalTransaction] = None
    ) -> Optional[FreezeAction]:
        """Record a transaction and check velocity.

        Args:
            user_id: The wallet address / user identifier.
            tx:      Optional transaction object (for metadata).

        Returns:
            A :class:`FreezeAction` if the velocity threshold was breached,
            otherwise ``None``.

        Raises:
            ComplianceError: If the account is already frozen.
        """
        async with self._locks[user_id]:
            # ── Check existing freeze ────────────────────────────────────
            if self._frozen_accounts.get(user_id):
                raise ComplianceError(
                    ComplianceErrorType.ACCOUNT_FROZEN,
                    f"Account {user_id} is temporarily frozen by REGULATOR_ROLE.",
                    {"user_id": user_id},
                )

            now = time.time()

            # ── Append & prune window ────────────────────────────────────
            timestamps = self._tx_timestamps[user_id]
            timestamps.append(now)
            cutoff = now - self._window
            self._tx_timestamps[user_id] = [
                ts for ts in timestamps if ts > cutoff
            ]

            # ── Velocity check ───────────────────────────────────────────
            count = len(self._tx_timestamps[user_id])
            if count > self._max_tx:
                return await self._trigger_freeze(user_id, count, tx)

            logger.debug(
                "User %s velocity OK: %d/%d in window",
                user_id,
                count,
                self._max_tx,
            )
            return None

    async def unfreeze_account(self, user_id: str) -> bool:
        """Manually unfreeze an account (REGULATOR_ROLE action).

        Args:
            user_id: The account to unfreeze.

        Returns:
            ``True`` if the account was frozen and is now unfrozen,
            ``False`` if it was not frozen.
        """
        async with self._locks[user_id]:
            if self._frozen_accounts.pop(user_id, False):
                logger.info("Account %s unfrozen by REGULATOR_ROLE", user_id)
                return True
            return False

    def is_frozen(self, user_id: str) -> bool:
        """Check whether an account is currently frozen."""
        return self._frozen_accounts.get(user_id, False)

    @property
    def reports(self) -> List[SuspiciousActivityReport]:
        """All generated Suspicious Activity Reports."""
        return list(self._reports)

    @property
    def freeze_actions(self) -> List[FreezeAction]:
        """All freeze actions taken."""
        return list(self._freeze_actions)

    def get_user_velocity(self, user_id: str) -> int:
        """Return the current tx count in the rolling window for a user."""
        now = time.time()
        cutoff = now - self._window
        return len([ts for ts in self._tx_timestamps.get(user_id, []) if ts > cutoff])

    # ── Internal ─────────────────────────────────────────────────────────

    async def _trigger_freeze(
        self,
        user_id: str,
        tx_count: int,
        tx: Optional[EuroDigitalTransaction],
    ) -> FreezeAction:
        """Generate a SAR and freeze the account."""
        now_dt = datetime.now(tz=timezone.utc)

        report = SuspiciousActivityReport(
            report_id=str(uuid.uuid4()),
            user_id=user_id,
            activity_type="velocity",
            severity="high",
            detected_at=now_dt,
            description=(
                f"Velocity breach: {tx_count} transactions in "
                f"{self._window}s window (limit: {self._max_tx}). "
                "REGULATOR_ROLE activated for temporary freeze."
            ),
            metadata={
                "tx_count": tx_count,
                "window_seconds": self._window,
                "max_allowed": self._max_tx,
                "tx_hash": tx.tx_hash if tx else None,
            },
            flagged=True,
        )
        self._reports.append(report)

        freeze = FreezeAction(
            user_id=user_id,
            reason=report.description,
            frozen_at=now_dt,
            report=report,
            auto_unfreeze=now_dt + timedelta(minutes=self._freeze_minutes),
        )
        self._freeze_actions.append(freeze)
        self._frozen_accounts[user_id] = True

        logger.warning(
            "SAR generated for %s – account FROZEN until %s",
            user_id,
            freeze.auto_unfreeze,
        )

        return freeze


# ──────────────────────────────────────────────────────────────────────────────
# §4 – Convenience: Full Compliance Check
# ──────────────────────────────────────────────────────────────────────────────
async def full_compliance_check(
    tx: EuroDigitalTransaction,
    user_history: List[EuroDigitalTransaction],
    profile: Optional[ComplianceProfile] = None,
    sar: Optional[SuspiciousActivityReporter] = None,
) -> Dict[str, Any]:
    """Run *all* compliance checks for a single transaction.

    Orchestrates :func:`verify_transaction_limits` and
    :class:`SuspiciousActivityReporter` into one call.

    Args:
        tx:           The transaction to check.
        user_history: Recent transaction history for the user.
        profile:      Optional compliance profile.
        sar:          Optional SAR instance (one is created if ``None``).

    Returns:
        A dict with keys:
        - ``limit_result`` – :class:`TransactionVerificationResult`
        - ``freeze_action`` – :class:`FreezeAction` or ``None``
        - ``compliant``     – ``True`` if *all* checks passed without error.

    Raises:
        ComplianceError: Propagated from any sub-check.
    """
    reporter = sar or SuspiciousActivityReporter()

    limit_result = await verify_transaction_limits(
        amount=tx.amount,
        user_history=user_history,
        profile=profile,
    )

    freeze_action = await reporter.record_transaction(
        user_id=tx.sender, tx=tx
    )

    return {
        "limit_result": limit_result,
        "freeze_action": freeze_action,
        "compliant": limit_result.allowed and freeze_action is None,
    }


# ──────────────────────────────────────────────────────────────────────────────
# §5 – Inline Tests
# ──────────────────────────────────────────────────────────────────────────────
async def _run_tests() -> None:
    """Self-contained test suite – run via ``python compliance_engine.py``."""
    import traceback

    passed = 0
    failed = 0

    def _ok(name: str) -> None:
        nonlocal passed
        passed += 1
        print(f"  ✓ {name}")

    def _fail(name: str, err: Exception) -> None:
        nonlocal failed
        failed += 1
        print(f"  ✗ {name}: {err}")
        traceback.print_exc()

    print("\n══════ compliance_engine.py – tests ══════\n")

    # ── 1. build_mica_rules ──────────────────────────────────────────────
    try:
        rules = build_mica_rules()
        assert len(rules) == 4, f"Expected 4 rules, got {len(rules)}"
        assert rules[0].rule_id == "MICA-001"
        _ok("build_mica_rules returns 4 active rules")
    except Exception as e:
        _fail("build_mica_rules", e)

    # ── 2. Small transaction (below threshold) ───────────────────────────
    try:
        result = await verify_transaction_limits(500.0, [])
        assert result.allowed is True
        assert result.requires_zk_proof is False
        assert result.triggered_rules == []
        _ok("500 EUR → no ZK proof required")
    except Exception as e:
        _fail("500 EUR transaction", e)

    # ── 3. Exactly at threshold ──────────────────────────────────────────
    try:
        result = await verify_transaction_limits(1_000.0, [])
        assert result.allowed is True
        assert result.requires_zk_proof is True, "1000€ should require proof"
        _ok("1000 EUR → ZK proof required (MiCA threshold)")
    except Exception as e:
        _fail("1000 EUR transaction", e)

    # ── 4. Above threshold ───────────────────────────────────────────────
    try:
        result = await verify_transaction_limits(2_500.0, [])
        assert result.allowed is True
        assert result.requires_zk_proof is True
        assert "MICA-001" in result.triggered_rules
        _ok("2500 EUR → ZK proof required, MICA-001 triggered")
    except Exception as e:
        _fail("2500 EUR transaction", e)

    # ── 5. Large amount triggers AML rule ────────────────────────────────
    try:
        kyc_profile = ComplianceProfile(
            user_id="0xkyc_user",
            kyc_verified=True,
            aml_screened=True,
            daily_limit=1_000_000.0,
            single_transaction_limit=100_000.0,
        )
        result = await verify_transaction_limits(60_000.0, [], profile=kyc_profile)
        assert result.requires_zk_proof is True
        assert "MICA-004" in result.triggered_rules
        _ok("60000 EUR → AML rule MICA-004 triggered")
    except Exception as e:
        _fail("60000 EUR AML", e)

    # ── 6. Invalid amount ────────────────────────────────────────────────
    try:
        try:
            await verify_transaction_limits(-100.0, [])
            _fail("negative amount should raise", AssertionError("no error"))
        except ComplianceError as ce:
            assert ce.error_type == ComplianceErrorType.RULE_VIOLATION
            _ok("Negative amount raises ComplianceError")
    except Exception as e:
        _fail("negative amount", e)

    # ── 7. Daily limit exceeded ──────────────────────────────────────────
    try:
        profile = ComplianceProfile(
            user_id="0xtest",
            daily_limit=2_000.0,
            single_transaction_limit=5_000.0,
        )
        history = [
            EuroDigitalTransaction(
                tx_hash="0xaaa",
                sender="0xtest",
                recipient_hash="0xbbb",
                amount=1_800.0,
                timestamp=int(time.time()) - 100,
                nonce=0,
            ),
        ]
        try:
            await verify_transaction_limits(500.0, history, profile=profile)
            _fail("daily limit should raise", AssertionError("no error"))
        except ComplianceError as ce:
            assert ce.error_type == ComplianceErrorType.DAILY_LIMIT_EXCEEDED
            _ok("Daily limit exceeded raises ComplianceError")
    except Exception as e:
        _fail("daily limit", e)

    # ── 8. SAR – normal velocity ─────────────────────────────────────────
    try:
        reporter = SuspiciousActivityReporter()
        for _ in range(4):
            result = await reporter.record_transaction("0xuser1")
            assert result is None
        _ok("SAR: 4 tx in window → no freeze")
    except Exception as e:
        _fail("SAR normal velocity", e)

    # ── 9. SAR – velocity breach ─────────────────────────────────────────
    try:
        reporter = SuspiciousActivityReporter(max_tx_per_window=5, window_seconds=60)
        for _ in range(5):
            await reporter.record_transaction("0xuser2")
        freeze = await reporter.record_transaction("0xuser2")
        assert freeze is not None, "6th tx should trigger freeze"
        assert reporter.is_frozen("0xuser2")
        assert len(reporter.reports) >= 1
        _ok("SAR: 6 tx in window → freeze triggered")
    except Exception as e:
        _fail("SAR velocity breach", e)

    # ── 10. SAR – frozen account rejects tx ──────────────────────────────
    try:
        reporter = SuspiciousActivityReporter(max_tx_per_window=1, window_seconds=60)
        await reporter.record_transaction("0xfrozen")
        await reporter.record_transaction("0xfrozen")  # triggers freeze
        try:
            await reporter.record_transaction("0xfrozen")
            _fail("frozen account should raise", AssertionError("no error"))
        except ComplianceError as ce:
            assert ce.error_type == ComplianceErrorType.ACCOUNT_FROZEN
            _ok("SAR: frozen account raises ComplianceError")
    except Exception as e:
        _fail("SAR frozen account", e)

    # ── 11. SAR – unfreeze ───────────────────────────────────────────────
    try:
        reporter = SuspiciousActivityReporter(max_tx_per_window=1, window_seconds=60)
        await reporter.record_transaction("0xunfr")
        await reporter.record_transaction("0xunfr")  # triggers freeze
        assert reporter.is_frozen("0xunfr")
        ok = await reporter.unfreeze_account("0xunfr")
        assert ok is True
        assert not reporter.is_frozen("0xunfr")
        _ok("SAR: unfreeze works correctly")
    except Exception as e:
        _fail("SAR unfreeze", e)

    # ── 12. full_compliance_check (happy path) ───────────────────────────
    try:
        tx = EuroDigitalTransaction(
            tx_hash="0xfull",
            sender="0xsender",
            recipient_hash="0xrecip",
            amount=500.0,
            timestamp=int(time.time()),
            nonce=1,
        )
        result = await full_compliance_check(tx, [])
        assert result["compliant"] is True
        _ok("full_compliance_check: 500 EUR → compliant")
    except Exception as e:
        _fail("full_compliance_check", e)

    # ── Summary ──────────────────────────────────────────────────────────
    total = passed + failed
    print(f"\n══════ {passed}/{total} tests passed ══════\n")
    if failed:
        raise SystemExit(1)


if __name__ == "__main__":
    asyncio.run(_run_tests())
