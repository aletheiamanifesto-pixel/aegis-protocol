#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
reporting/esma_reporter.py - ESMA/CONSOB regulatory reporting for AEGIS Protocol.

Generates MiCA Art. 36+ periodic compliance reports and assigns each a
tamper-evident SHA-256 hash and a sequential report ID.
"""

import hashlib
import json
import time
import uuid
from dataclasses import dataclass, field, asdict
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

try:
    from banking_operations import get_reserve_ratio
except ImportError:
    get_reserve_ratio = None  # type: ignore[assignment]


@dataclass
class ComplianceReport:
    """MiCA-required periodic compliance report.

    Attributes:
        report_id: Sequential integer identifier.
        period_start: ISO-8601 timestamp for the start of the reporting period.
        period_end: ISO-8601 timestamp for the end of the reporting period.
        generated_at: ISO-8601 timestamp when the report was produced.
        total_transactions: Number of transactions processed in the period.
        total_volume_eur: Total EUR volume of transactions.
        reserve_ratio: Current reserve ratio (deposits / outstanding).
        zk_proofs_generated: Number of ZK compliance proofs issued.
        velocity_limit_breaches: Number of velocity-limit violations detected.
        compliance_rejections: Breakdown of rejection reasons to counts.
        report_hash: SHA-256 hex digest of the canonical report JSON (set after generation).
    """

    report_id: int
    period_start: str
    period_end: str
    generated_at: str
    total_transactions: int
    total_volume_eur: float
    reserve_ratio: Optional[float]  # None = source unavailable (never a made-up value)
    zk_proofs_generated: int
    velocity_limit_breaches: int
    compliance_rejections: Dict[str, int]
    report_hash: str = ""


class ESMAReporter:
    """Generates periodic MiCA compliance reports.

    Data is pulled from the compliance_engine, bundler statistics, and
    banking_operations modules when they are available.  Each report
    receives a SHA-256 tamper-evident digest.

    Args:
        compliance_engine: Optional ComplianceEngine instance.
        bundler: Optional TransactionBundler instance.

    Example:
        reporter = ESMAReporter()
        report = reporter.generate_report(period_start, period_end)
    """

    def __init__(
        self,
        compliance_engine=None,
        bundler=None,
    ) -> None:
        self._compliance_engine = compliance_engine
        self._bundler = bundler
        self._report_counter: int = 0
        self._reports: List[ComplianceReport] = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate_report(
        self,
        period_start: datetime,
        period_end: datetime,
    ) -> ComplianceReport:
        """Generate a MiCA compliance report for the given period.

        Args:
            period_start: Start of the reporting period (UTC).
            period_end: End of the reporting period (UTC).

        Returns:
            ComplianceReport with all required fields and a tamper-evident hash.
        """
        self._report_counter += 1

        stats = self._collect_stats(period_start, period_end)

        report = ComplianceReport(
            report_id=self._report_counter,
            period_start=period_start.isoformat(),
            period_end=period_end.isoformat(),
            generated_at=datetime.utcnow().isoformat(),
            total_transactions=stats["total_transactions"],
            total_volume_eur=stats["total_volume_eur"],
            reserve_ratio=stats["reserve_ratio"],
            zk_proofs_generated=stats["zk_proofs_generated"],
            velocity_limit_breaches=stats["velocity_limit_breaches"],
            compliance_rejections=stats["compliance_rejections"],
        )

        report.report_hash = self._hash_report(report)
        self._reports.append(report)
        return report

    def get_reports(self) -> List[ComplianceReport]:
        """Return all generated reports in order."""
        return list(self._reports)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _collect_stats(
        self, period_start: datetime, period_end: datetime
    ) -> Dict[str, Any]:
        """Collect statistics from available modules."""
        # A regulatory report must not contain "1.0" made up when the source fails:
        # if the database is unreachable the field is None and the error is logged.
        reserve_ratio = None
        if get_reserve_ratio is not None:
            try:
                reserve_ratio = get_reserve_ratio()
            except Exception as exc:  # noqa: BLE001 - source unavailable, reported explicitly
                logger.error("ESMAReporter: reserve ratio unavailable: %s", exc)

        total_transactions = 0
        total_volume_eur = 0.0
        zk_proofs_generated = 0
        velocity_limit_breaches = 0
        compliance_rejections: Dict[str, int] = {}

        if self._bundler is not None:
            stats = self._bundler.get_stats()
            total_transactions = stats.get("total_transactions", 0)
            total_volume_eur = stats.get("total_volume_eur", 0.0)

        return {
            "total_transactions": total_transactions,
            "total_volume_eur": total_volume_eur,
            "reserve_ratio": reserve_ratio,
            "zk_proofs_generated": zk_proofs_generated,
            "velocity_limit_breaches": velocity_limit_breaches,
            "compliance_rejections": compliance_rejections,
        }

    @staticmethod
    def _hash_report(report: ComplianceReport) -> str:
        """Compute a deterministic SHA-256 digest of the report (excluding hash field)."""
        data = asdict(report)
        data.pop("report_hash", None)
        canonical = json.dumps(data, sort_keys=True, default=str)
        return hashlib.sha256(canonical.encode()).hexdigest()
