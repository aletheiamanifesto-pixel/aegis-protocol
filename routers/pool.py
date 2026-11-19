#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
routers/pool.py - KYC credentials for the ZK circuit and relayer for the ShieldedPool.

The ZK proof is generated on the user's device (sdk/aegis-core.mjs + Noir/bb.js):
the server never receives secrets or note contents.
"""

from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

import db_models
import pool_service
from routers.auth import _get_current_user
from security import get_db

router = APIRouter(tags=["pool"])


class CredentialRequest(BaseModel):
    pseudonym: str = Field(description="owner_pubkey = Poseidon2(1, spending_secret), hex; computed on the device")


class Point(BaseModel):
    x: str
    y: str


class PoolProof(BaseModel):
    proof: str
    root: str
    nullifiers: List[str] = Field(min_length=2, max_length=2)
    outCommitments: List[str] = Field(min_length=2, max_length=2)
    publicIn: int = Field(ge=0, lt=2**64)
    publicOut: int = Field(ge=0, lt=2**64)
    timestamp: int = Field(ge=0, lt=2**64)
    issuer: Point
    taxEph: Point
    taxCt: List[str] = Field(min_length=4, max_length=4)
    amlEph: Point
    amlCt: List[str] = Field(min_length=8, max_length=8)


class ExtData(BaseModel):
    recipient: str
    relayer: str
    fee: int = Field(ge=0, lt=2**64)
    encryptedOutput0: str = "0x"
    encryptedOutput1: str = "0x"


class RelayRequest(BaseModel):
    proof: PoolProof
    ext: ExtData


@router.get("/pool/issuer")
def pool_issuer() -> Dict[str, Any]:
    """Public key of the KYC issuer (to register with ShieldedPool.setIssuer) and of the relayer."""
    try:
        return {"issuer": pool_service.issuer_public_key(), "relayer": pool_service.relayer_address()}
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=503, detail=str(exc))


@router.post("/pool/credential")
def pool_credential(req: CredentialRequest, current_user: Dict = Depends(_get_current_user), db=Depends(get_db)):
    """Signed KYC credential for the circuit. Only for verified customers; tier and
    jurisdiction come from the verification, not from the request."""
    uid = int(current_user["user_id"])
    profile = db.query(db_models.ComplianceProfile).filter_by(user_id=uid).first()
    if profile is None or not profile.kyc_verified:
        raise HTTPException(status_code=403, detail="KYC not verified")
    try:
        cred = pool_service.issue_credential(req.pseudonym, profile.kyc_tier, profile.kyc_country)
    except pool_service.PoolError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:  # noqa: BLE001 - issuer key not configured
        raise HTTPException(status_code=503, detail=str(exc))

    row = db.query(db_models.PoolPseudonym).filter_by(pseudonym=cred["pseudonym"]).first()
    if row is not None and row.user_id != uid:
        raise HTTPException(status_code=409, detail="Pseudonym already linked to another customer")
    if row is None:
        row = db_models.PoolPseudonym(user_id=uid, pseudonym=cred["pseudonym"], tier=0, jurisdiction=0, credential_expiry=0)
        db.add(row)
    row.tier, row.jurisdiction, row.credential_expiry = cred["tier"], cred["jurisdiction"], cred["expiry"]
    db.add(db_models.AuditLog(user_id=uid, action="pool_credential_issued", resource_type="pool",
                              details={"pseudonym": cred["pseudonym"], "tier": cred["tier"], "expiry": cred["expiry"]}))
    db.commit()
    return cred


@router.post("/pool/relay")
def pool_relay(req: RelayRequest, current_user: Dict = Depends(_get_current_user), db=Depends(get_db)):
    """Forward a transaction already proven on the device. The operator relays only for its own
    customers (with a registered pseudonym) and records the transaction in the register."""
    uid = int(current_user["user_id"])
    if db.query(db_models.PoolPseudonym).filter_by(user_id=uid).first() is None:
        raise HTTPException(status_code=403, detail="No pool credential issued to this account")
    try:
        result = pool_service.relay(req.proof.model_dump(), req.ext.model_dump())
    except pool_service.PoolError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    db.add(db_models.PoolRelay(user_id=uid, tx_hash=result.tx_hash, public_in=req.proof.publicIn,
                               public_out=req.proof.publicOut, status="simulated" if result.simulated else "submitted"))
    db.commit()
    return {"tx_hash": result.tx_hash, "simulated": result.simulated}


@router.get("/pool/relays/mine")
def pool_my_relays(current_user: Dict = Depends(_get_current_user), db=Depends(get_db)):
    rows = db.query(db_models.PoolRelay).filter_by(user_id=int(current_user["user_id"])).all()
    return {"relays": [{"tx_hash": r.tx_hash, "status": r.status, "public_in": r.public_in,
                        "public_out": r.public_out, "created_at": r.created_at.isoformat()} for r in rows]}
