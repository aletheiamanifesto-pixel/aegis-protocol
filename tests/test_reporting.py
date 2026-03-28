#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tests/test_reporting.py - Tests for ESMAReporter and ReserveAttestor.
"""

import hashlib
import json
import time
from dataclasses import asdict
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest

from reporting.esma_reporter import ESMAReporter, ComplianceReport
from reporting.reserve_attestation import ReserveAttestor, ReserveAttestation


# ---------------------------------------------------------------------------
# ESMAReporter tests
# ---------------------------------------------------------------------------

class TestESMAReporterGenerate:
    def _reporter(self) -> ESMAReporter:
        return ESMAReporter()

    def _period(self):
        end = datetime.utcnow()
        start = end - timedelta(days=7)
        return start, end

    def test_returns_compliance_report(self):
        reporter = self._reporter()
        start, end = self._period()
        report = reporter.generate_report(start, end)
        assert isinstance(report, ComplianceReport)

    def test_report_id_increments(self):
        reporter = self._reporter()
        start, end = self._period()
        r1 = reporter.generate_report(start, end)
        r2 = reporter.generate_report(start, end)
        assert r2.report_id == r1.report_id + 1

    def test_period_fields_in_report(self):
        reporter = self._reporter()
        start, end = self._period()
        report = reporter.generate_report(start, end)
        assert report.period_start == start.isoformat()
        assert report.period_end == end.isoformat()

    def test_report_has_hash(self):
        reporter = self._reporter()
        start, end = self._period()
        report = reporter.generate_report(start, end)
        assert report.report_hash
        assert len(report.report_hash) == 64  # SHA-256 hex

    def test_report_stored_in_history(self):
        reporter = self._reporter()
        start, end = self._period()
        reporter.generate_report(start, end)
        reporter.generate_report(start, end)
        assert len(reporter.get_reports()) == 2

    def test_reserve_ratio_from_banking_operations(self):
        """When banking_operations is importable, ratio should come from it."""
        reporter = self._reporter()
        start, end = self._period()
        with patch("reporting.esma_reporter.get_reserve_ratio", return_value=1.05):
            report = reporter.generate_report(start, end)
        assert report.reserve_ratio == pytest.approx(1.05)

    def test_bundler_stats_used_when_provided(self):
        mock_bundler = MagicMock()
        mock_bundler.get_stats.return_value = {
            "total_transactions": 42,
            "total_volume_eur": 9999.0,
        }
        reporter = ESMAReporter(bundler=mock_bundler)
        start, end = self._period()
        report = reporter.generate_report(start, end)
        assert report.total_transactions == 42
        assert report.total_volume_eur == pytest.approx(9999.0)


class TestESMAReporterHash:
    def test_hash_is_deterministic(self):
        reporter = ESMAReporter()
        start, end = datetime(2025, 1, 1), datetime(2025, 1, 31)
        r1 = reporter.generate_report(start, end)
        # Manually recompute hash
        data = asdict(r1)
        data.pop("report_hash", None)
        canonical = json.dumps(data, sort_keys=True, default=str)
        expected = hashlib.sha256(canonical.encode()).hexdigest()
        assert r1.report_hash == expected

    def test_different_periods_different_hashes(self):
        reporter = ESMAReporter()
        r1 = reporter.generate_report(datetime(2025, 1, 1), datetime(2025, 1, 31))
        r2 = reporter.generate_report(datetime(2025, 2, 1), datetime(2025, 2, 28))
        assert r1.report_hash != r2.report_hash


# ---------------------------------------------------------------------------
# ReserveAttestor tests
# ---------------------------------------------------------------------------

class TestReserveAttestorDevMode:
    def _attestor(self) -> ReserveAttestor:
        """Attestor without addresses → dev mode."""
        return ReserveAttestor(
            vault_address="",
            token_address="",
            private_key="",
        )

    def test_returns_attestation(self):
        attestation = self._attestor().attest()
        assert isinstance(attestation, ReserveAttestation)

    def test_fully_backed_in_dev_mode(self):
        attestation = self._attestor().attest()
        assert attestation.is_fully_backed is True

    def test_ratio_is_1_in_dev_mode(self):
        attestation = self._attestor().attest()
        assert attestation.ratio == pytest.approx(1.0)

    def test_attestation_has_hash(self):
        attestation = self._attestor().attest()
        assert attestation.attestation_hash
        assert len(attestation.attestation_hash) == 64

    def test_timestamp_is_recent(self):
        attestation = self._attestor().attest()
        assert abs(attestation.timestamp - int(time.time())) < 5

    def test_on_chain_data_present(self):
        attestation = self._attestor().attest()
        assert "total_eur_deposited" in attestation.on_chain_data
        assert "total_supply" in attestation.on_chain_data


class TestReserveAttestorRatioCalculation:
    def test_fully_backed_when_ratio_gte_1(self):
        attestor = ReserveAttestor(vault_address="", token_address="", private_key="")
        # Override _dev_attestation by patching _build
        result = attestor._build(
            ratio=1.05,
            on_chain_data={"total_eur_deposited": 105.0, "total_supply": 100.0,
                           "total_eur_withdrawn": 0.0, "net_reserves": 105.0},
        )
        assert result.is_fully_backed is True
        assert result.ratio == pytest.approx(1.05)

    def test_not_fully_backed_when_ratio_lt_1(self):
        attestor = ReserveAttestor(vault_address="", token_address="", private_key="")
        result = attestor._build(
            ratio=0.95,
            on_chain_data={"total_eur_deposited": 95.0, "total_supply": 100.0,
                           "total_eur_withdrawn": 0.0, "net_reserves": 95.0},
        )
        assert result.is_fully_backed is False

    def test_attestation_hash_excludes_itself(self):
        """The hash field must not be included in its own computation."""
        attestor = ReserveAttestor(vault_address="", token_address="", private_key="")
        a1 = attestor.attest()
        # Changing report_hash should not affect data equality
        data = asdict(a1)
        data.pop("attestation_hash", None)
        canonical = json.dumps(data, sort_keys=True, default=str)
        expected = hashlib.sha256(canonical.encode()).hexdigest()
        assert a1.attestation_hash == expected

    def test_chain_error_falls_back_to_dev(self):
        """When chain read fails, attest() falls back to dev mode silently."""
        attestor = ReserveAttestor(
            vault_address="0x" + "a" * 40,
            token_address="0x" + "b" * 40,
            private_key="0x" + "c" * 64,
        )
        attestor._chain_attestation = MagicMock(side_effect=RuntimeError("rpc error"))
        result = attestor.attest()
        assert isinstance(result, ReserveAttestation)
        assert result.ratio == pytest.approx(1.0)
