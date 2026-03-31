#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
routers/proof.py - ZK proof endpoints for AEGIS Protocol.
"""

from datetime import datetime
from typing import Dict

from fastapi import APIRouter, Depends, HTTPException

from routers.auth import _get_current_user
from schemas import ProofGenerateRequest, ProofVerifyRequest

try:
    from compliance_engine import ComplianceEngine
    _ce_available = True
except ImportError:
    _ce_available = False

router = APIRouter(tags=["proof"])


@router.post("/proof/generate")
def proof_generate(req: ProofGenerateRequest, current_user: Dict = Depends(_get_current_user)):
    if not _ce_available:
        raise HTTPException(status_code=503, detail="Compliance engine not available")
    engine = ComplianceEngine()
    proof = engine.generate_zk_proof_stub(req.sender, req.amount, req.purpose)
    return {
        "proof_hash": proof.proof_hash,
        "public_inputs": proof.public_inputs,
        "valid_until": proof.valid_until,
        "generated_at": proof.generated_at,
    }


@router.post("/proof/verify")
def proof_verify(req: ProofVerifyRequest, current_user: Dict = Depends(_get_current_user)):
    is_valid = req.proof_hash.startswith("0x") and len(req.proof_hash) == 66
    return {
        "proof_hash": req.proof_hash,
        "valid": is_valid,
        "verified_at": datetime.utcnow().isoformat(),
    }
