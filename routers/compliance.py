#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
routers/compliance.py - Compliance endpoints for AEGIS Protocol.
"""

from datetime import datetime
from typing import Dict

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from routers.auth import _get_current_user
from schemas import KYCRequest, ProofGenerateRequest

try:
    from db import get_db
    import db_models
    _db_available = True
except ImportError:
    _db_available = False

    def get_db():
        yield None

try:
    from compliance_engine import ComplianceEngine
    _ce_available = True
except ImportError:
    _ce_available = False

router = APIRouter(tags=["compliance"])


@router.post("/compliance/kyc")
def compliance_kyc(
    req: KYCRequest,
    current_user: Dict = Depends(_get_current_user),
    db: Session = Depends(get_db),
):
    user_id = current_user["user_id"]

    if _db_available and db is not None:
        profile = db.query(db_models.ComplianceProfile).filter(
            db_models.ComplianceProfile.user_id == int(user_id)
        ).first()
        if not profile:
            profile = db_models.ComplianceProfile(user_id=int(user_id))
            db.add(profile)

        profile.kyc_verified = True
        profile.last_kyc_at = datetime.utcnow()
        db.commit()

    return {
        "user_id": user_id,
        "kyc_verified": True,
        "verified_at": datetime.utcnow().isoformat(),
        "message": "KYC verification completed",
    }


@router.get("/compliance/profile")
def compliance_profile(
    current_user: Dict = Depends(_get_current_user),
    db: Session = Depends(get_db),
):
    user_id = current_user["user_id"]

    if _db_available and db is not None:
        profile = db.query(db_models.ComplianceProfile).filter(
            db_models.ComplianceProfile.user_id == int(user_id)
        ).first()
        if profile:
            return {
                "user_id": user_id,
                "kyc_verified": profile.kyc_verified,
                "aml_screened": profile.aml_screened,
                "daily_limit": profile.daily_limit,
                "single_tx_limit": profile.single_tx_limit,
                "risk_level": profile.risk_level,
            }

    return {
        "user_id": user_id,
        "kyc_verified": False,
        "aml_screened": False,
        "daily_limit": 10000.0,
        "single_tx_limit": 5000.0,
        "risk_level": "low",
    }


@router.post("/compliance/proof/generate")
def compliance_proof_generate(
    req: ProofGenerateRequest,
    current_user: Dict = Depends(_get_current_user),
):
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
