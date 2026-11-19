#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
routers/compliance.py - Compliance endpoints for AEGIS Protocol.
"""

import hashlib
import hmac
import os
from datetime import datetime
from typing import Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from routers.auth import _get_current_user
from security import require_roles
from schemas import KYCRequest

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


def _profile(db, user_id: int):
    profile = db.query(db_models.ComplianceProfile).filter(db_models.ComplianceProfile.user_id == user_id).first()
    if not profile:
        profile = db_models.ComplianceProfile(user_id=user_id)
        db.add(profile)
    return profile


@router.post("/compliance/kyc", status_code=202)
def compliance_kyc(
    req: KYCRequest,
    current_user: Dict = Depends(_get_current_user),
    db: Session = Depends(get_db),
):
    """The user SUBMITS their data: the state becomes "pending", never "verified".

    Verification comes only from the compliance team (/compliance/kyc/{user_id}/decision)
    or from the KYC provider via a signed webhook (/compliance/kyc/webhook).
    """
    user_id = int(current_user["user_id"])
    if not _db_available or db is None:
        raise HTTPException(status_code=503, detail="Database unavailable")
    profile = _profile(db, user_id)
    if profile.kyc_status != "approved":
        profile.kyc_status = "pending"
    # Personal data is not stored in clear: only a fingerprint of the document for the audit trail.
    db.add(db_models.AuditLog(user_id=user_id, action="kyc_submitted", resource_type="kyc",
                              details={"country": req.country, "id_document_hash": req.id_document_hash}))
    db.commit()
    return {"user_id": str(user_id), "kyc_status": profile.kyc_status, "kyc_verified": profile.kyc_verified,
            "message": "KYC data received: awaiting verification"}


class KYCDecision(BaseModel):
    approved: bool
    tier: int = Field(default=1, ge=0, le=3)
    provider_ref: Optional[str] = None
    country: Optional[str] = Field(default=None, min_length=2, max_length=2, description="ISO country verified")
    reason: str = ""


def _apply_decision(db, user_id: int, decision: KYCDecision, actor: str) -> Dict:
    if db.get(db_models.User, user_id) is None:
        raise HTTPException(status_code=404, detail="User not found")
    profile = _profile(db, user_id)
    profile.kyc_status = "approved" if decision.approved else "rejected"
    profile.kyc_verified = decision.approved
    profile.kyc_tier = decision.tier if decision.approved else 0
    profile.kyc_provider_ref = decision.provider_ref
    profile.kyc_country = decision.country.upper() if decision.country else profile.kyc_country
    profile.last_kyc_at = datetime.utcnow()
    db.add(db_models.AuditLog(user_id=user_id, action="kyc_decision", resource_type="kyc",
                              details={"by": actor, "approved": decision.approved, "tier": profile.kyc_tier,
                                       "provider_ref": decision.provider_ref, "reason": decision.reason}))
    db.commit()
    return {"user_id": str(user_id), "kyc_status": profile.kyc_status, "kyc_verified": profile.kyc_verified,
            "kyc_tier": profile.kyc_tier}


@router.post("/compliance/kyc/{user_id}/decision")
def compliance_kyc_decision(
    user_id: int,
    decision: KYCDecision,
    officer: Dict = Depends(require_roles("compliance", "admin")),
    db: Session = Depends(get_db),
):
    """Decision of the compliance officer (never by the user themselves)."""
    if str(user_id) == officer["user_id"]:
        raise HTTPException(status_code=403, detail="Nobody can verify their own KYC")
    return _apply_decision(db, user_id, decision, actor=f"user:{officer['user_id']}")


class KYCWebhook(KYCDecision):
    user_id: int


@router.post("/compliance/kyc/webhook")
async def compliance_kyc_webhook(request: Request, db: Session = Depends(get_db)):
    """Result from the KYC provider (Sumsub, Onfido, ...), signed with HMAC-SHA256.

    Header X-KYC-Signature = hex(HMAC_SHA256(KYC_WEBHOOK_SECRET, raw body)).
    """
    secret = os.getenv("KYC_WEBHOOK_SECRET", "")
    if len(secret) < 32:
        raise HTTPException(status_code=503, detail="KYC webhook not configured")
    body = await request.body()
    expected = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, request.headers.get("X-KYC-Signature", "")):
        raise HTTPException(status_code=401, detail="Invalid signature")
    try:
        payload = KYCWebhook.model_validate_json(body)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid payload")
    return _apply_decision(db, payload.user_id, payload, actor="provider")


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
                "kyc_status": profile.kyc_status,
                "kyc_tier": profile.kyc_tier,
                "aml_screened": profile.aml_screened,
                "daily_limit": profile.daily_limit,
                "single_tx_limit": profile.single_tx_limit,
                "risk_level": profile.risk_level,
            }

    return {
        "user_id": user_id,
        "kyc_verified": False,
        "kyc_status": "none",
        "kyc_tier": 0,
        "aml_screened": False,
        "daily_limit": 10000.0,
        "single_tx_limit": 5000.0,
        "risk_level": "low",
    }
