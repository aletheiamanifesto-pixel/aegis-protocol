"""
main_app.py - FastAPI application for AEGIS Protocol

Exposes the Aegis server with a POST /transaction endpoint
that validates EUR Digital transactions through the MiCA compliance engine.
"""

import os

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from typing import List

from models import EuroDigitalTransaction, TransactionStatus
from compliance_engine import ComplianceEngine, ComplianceResult

load_dotenv()

app = FastAPI(
    title="AEGIS Protocol",
    description="MiCA-compliant EUR Digital transaction gateway",
    version="0.1.0",
)

engine = ComplianceEngine()


# ---------------------------------------------------------------------------
# Response model
# ---------------------------------------------------------------------------

class TransactionResponse(BaseModel):
    compliant: bool
    status: TransactionStatus
    flags: List[str] = Field(default_factory=list)
    message: str = ""


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/")
def root():
    """Health-check / welcome endpoint."""
    return {
        "service": "AEGIS Protocol",
        "status": "running",
        "docs": "/docs",
    }


@app.get("/health")
def health():
    """Readiness probe for Docker / k8s."""
    return {"status": "ok"}


@app.post("/transaction", response_model=TransactionResponse)
def create_transaction(tx: EuroDigitalTransaction):
    """Accept an EUR Digital transaction and run MiCA compliance checks.

    Returns the compliance result including status, flags, and message.
    """
    result: ComplianceResult = engine.check_transaction(tx)

    if not result.compliant:
        raise HTTPException(
            status_code=422,
            detail={
                "compliant": False,
                "status": result.transaction_status.value,
                "flags": result.flags,
                "message": result.message,
            },
        )

    return TransactionResponse(
        compliant=result.compliant,
        status=result.transaction_status,
        flags=result.flags,
        message=result.message,
    )
