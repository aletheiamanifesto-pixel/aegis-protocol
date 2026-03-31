#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
routers/settlement.py - Settlement endpoints for AEGIS Protocol.
"""

from typing import Dict

from fastapi import APIRouter, Depends, HTTPException

from routers.auth import _get_current_user
from schemas import SubmitBundleRequest

try:
    from settlement import OnChainSettler, SettlementConfig, SettlementResult
    _settlement_available = True
except ImportError:
    _settlement_available = False

router = APIRouter(tags=["settlement"])


@router.post("/api/v1/settlement/submit-bundle")
def settlement_submit_bundle(
    req: SubmitBundleRequest,
    current_user: Dict = Depends(_get_current_user),
):
    """Trigger on-chain settlement for a bundle identified by its Merkle root."""
    if not _settlement_available:
        raise HTTPException(status_code=503, detail="Settlement service not available")

    from dataclasses import make_dataclass

    _BundleProxy = make_dataclass(
        "_BundleProxy",
        [("bundle_id", str), ("merkle_root", str), ("transactions", list)],
    )
    proxy = _BundleProxy(
        bundle_id=req.bundle_id,
        merkle_root=req.merkle_root,
        transactions=[{}] * req.tx_count,
    )

    settler = OnChainSettler()
    result = settler.settle(proxy)
    return {
        "bundle_id": result.bundle_id,
        "tx_hash": result.tx_hash,
        "block_number": result.block_number,
        "gas_used": result.gas_used,
        "status": result.status,
        "error": result.error,
    }
