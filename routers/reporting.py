#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
routers/reporting.py - Reporting endpoints for AEGIS Protocol.
"""

from datetime import datetime, timedelta
from typing import Dict, Optional

from fastapi import APIRouter, Depends, HTTPException

from routers.auth import _get_current_user

try:
    from reporting import ESMAReporter, ReserveAttestor
    _reporting_available = True
except ImportError:
    _reporting_available = False

router = APIRouter(tags=["reporting"])


@router.get("/api/v1/reporting/compliance-report")
def reporting_compliance_report(
    period_start: Optional[str] = None,
    period_end: Optional[str] = None,
    current_user: Dict = Depends(_get_current_user),
):
    """Generate a MiCA compliance report for the given time period."""
    if not _reporting_available:
        raise HTTPException(status_code=503, detail="Reporting service not available")

    now = datetime.utcnow()
    try:
        start = datetime.fromisoformat(period_start) if period_start else now - timedelta(days=30)
        end = datetime.fromisoformat(period_end) if period_end else now
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid date format: {exc}")

    reporter = ESMAReporter()
    report = reporter.generate_report(start, end)
    return {
        "report_id": report.report_id,
        "period_start": report.period_start,
        "period_end": report.period_end,
        "generated_at": report.generated_at,
        "total_transactions": report.total_transactions,
        "total_volume_eur": report.total_volume_eur,
        "reserve_ratio": report.reserve_ratio,
        "zk_proofs_generated": report.zk_proofs_generated,
        "velocity_limit_breaches": report.velocity_limit_breaches,
        "compliance_rejections": report.compliance_rejections,
        "report_hash": report.report_hash,
    }


@router.get("/api/v1/reporting/reserve-attestation")
def reporting_reserve_attestation(current_user: Dict = Depends(_get_current_user)):
    """Get the current on-chain reserve attestation."""
    if not _reporting_available:
        raise HTTPException(status_code=503, detail="Reporting service not available")

    attestor = ReserveAttestor()
    attestation = attestor.attest()
    return {
        "ratio": attestation.ratio,
        "is_fully_backed": attestation.is_fully_backed,
        "on_chain_data": attestation.on_chain_data,
        "timestamp": attestation.timestamp,
        "attestation_hash": attestation.attestation_hash,
    }
