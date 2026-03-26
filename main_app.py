#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
main_app.py – FastAPI application for AEGIS Protocol

Exposes REST endpoints for submitting MiCA-compliant transactions
and querying ZK proof registration status on-chain.
"""

import hashlib
import logging
import time
from typing import Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

import transaction_processor

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="AEGIS Protocol API",
    description="MiCA-compliant digital Euro transaction gateway with ZK privacy.",
    version="0.1.0",
)


# ── Request / Response schemas ───────────────────────────────────────────

class TransactionRequest(BaseModel):
    """Incoming transaction request from the client."""
    sender: str = Field(..., description="Sender wallet address")
    recipient: str = Field(..., description="Recipient wallet address")
    amount: float = Field(..., gt=0, description="Amount in EUR")
    proof_hash: Optional[str] = Field(
        None,
        description="Hex-encoded ZK proof hash (required for amounts >= 1000 EUR)",
    )


class TransactionResponse(BaseModel):
    """Response returned to the client after submission."""
    status: str
    tx_hash: Optional[str] = None
    message: str
    timestamp: int


class ProofStatusResponse(BaseModel):
    """Response for proof registration query."""
    proof_hash: str
    registered: bool


# ── Endpoints ────────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    """Simple liveness check."""
    return {"status": "ok"}


@app.post("/transaction", response_model=TransactionResponse)
async def submit_transaction(req: TransactionRequest):
    """
    Submit a MiCA-compliant transaction.

    For amounts >= 1000 EUR a ZK proof hash must be supplied.
    The proof is registered on-chain via AegisSmartAccount.registerZkProof
    and the resulting blockchain TxHash is returned in the response.
    """
    now = int(time.time())

    # ── MiCA compliance gate ─────────────────────────────────────────
    if req.amount >= 1000 and not req.proof_hash:
        raise HTTPException(
            status_code=400,
            detail="MiCA regulation: ZK proof hash required for amounts >= 1000 EUR.",
        )

    # ── Derive calldata hash ─────────────────────────────────────────
    calldata_payload = f"{req.sender}:{req.recipient}:{req.amount}:{now}"
    calldata_hash = "0x" + hashlib.sha256(calldata_payload.encode()).hexdigest()

    # ── If proof hash supplied, register on-chain ────────────────────
    if req.proof_hash:
        try:
            tx_hash = transaction_processor.submit_compliant_transaction(
                proof_hash=req.proof_hash,
                calldata_hash=calldata_hash,
            )
            return TransactionResponse(
                status="submitted",
                tx_hash=tx_hash,
                message="ZK proof registered on-chain.",
                timestamp=now,
            )
        except Exception as exc:
            logger.error("Blockchain submission failed: %s", exc)
            raise HTTPException(status_code=502, detail=str(exc))

    # ── Small transaction (< 1000 EUR): direct execute ───────────────
    try:
        tx_hash = transaction_processor.execute_transaction(
            to=req.recipient,
            value=0,
            data=b"",
        )
        return TransactionResponse(
            status="submitted",
            tx_hash=tx_hash,
            message="Transaction executed on-chain.",
            timestamp=now,
        )
    except Exception as exc:
        logger.error("Blockchain execution failed: %s", exc)
        raise HTTPException(status_code=502, detail=str(exc))


@app.get("/proof/{proof_hash}", response_model=ProofStatusResponse)
async def check_proof(proof_hash: str):
    """Check whether a ZK proof has been registered on-chain."""
    try:
        registered = transaction_processor.is_proof_registered(proof_hash)
        return ProofStatusResponse(proof_hash=proof_hash, registered=registered)
    except Exception as exc:
        logger.error("Proof check failed: %s", exc)
        raise HTTPException(status_code=502, detail=str(exc))
