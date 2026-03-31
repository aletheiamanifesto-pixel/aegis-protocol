#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
routers/bridge.py - Cross-chain bridge endpoints for AEGIS Protocol.
"""

from typing import Dict

from fastapi import APIRouter, Depends, HTTPException

from routers.auth import _get_current_user
from schemas import BridgeInitiateRequest

try:
    from bridge import BridgeManager, BridgeRequest, BridgeConfig, BridgeError
    _bridge_available = True
except ImportError:
    _bridge_available = False

try:
    from compliance_engine import ComplianceEngine
    _ce_available = True
except ImportError:
    _ce_available = False

router = APIRouter(tags=["bridge"])


@router.post("/api/v1/bridge/initiate")
def bridge_initiate(req: BridgeInitiateRequest, current_user: Dict = Depends(_get_current_user)):
    """Initiate a cross-chain bridge transfer."""
    if not _bridge_available:
        raise HTTPException(status_code=503, detail="Bridge service not available")

    compliance_engine = None
    if _ce_available:
        compliance_engine = ComplianceEngine()

    manager = BridgeManager(compliance_engine=compliance_engine)
    bridge_req = BridgeRequest(
        source_chain=req.source_chain,
        dest_chain=req.dest_chain,
        token_address=req.token_address,
        amount=req.amount,
        recipient=req.recipient,
        sender=req.sender,
    )
    try:
        result = manager.initiate_bridge(bridge_req)
    except BridgeError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    return {
        "request_id": result.request_id,
        "status": result.status,
        "source_tx_hash": result.source_tx_hash,
        "dest_tx_hash": result.dest_tx_hash,
        "estimated_time": result.estimated_time,
        "error": result.error,
    }


@router.get("/api/v1/bridge/status/{request_id}")
def bridge_status(request_id: str, current_user: Dict = Depends(_get_current_user)):
    """Check the status of a pending bridge transfer."""
    if not _bridge_available:
        raise HTTPException(status_code=503, detail="Bridge service not available")

    raise HTTPException(
        status_code=404,
        detail=(
            f"Bridge request '{request_id}' not found. "
            "Use a persistent BridgeManager instance to query status."
        ),
    )
