#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
main_app.py — AEGIS Protocol FastAPI server.

Endpoints:
    POST /v1/transaction/initiate  — Validate an EuroDigitalTransaction and
                                     compute its on-chain hash.
    POST /v1/transaction/sign      — Accept an owner EIP-191 signature and
                                     prepare the ERC-4337 UserOperation.
    GET  /v1/compliance/check/{account} — Return the KYC/AML compliance status
                                     for an Ethereum address.

Run locally:
    uvicorn main_app:app --reload --port 8000

Environment variables (see .env.example):
    RPC_URL, ENTRY_POINT_ADDR, SMART_ACCOUNT_ADDR, BUNDLER_PRIVATE_KEY
"""

import hashlib
import logging
import os
from datetime import datetime, timezone
from typing import Optional

from dotenv import load_dotenv
from eth_account import Account
from eth_account.messages import encode_defunct
from fastapi import FastAPI, HTTPException, Path, status
from pydantic import BaseModel, Field
from web3 import Web3

from compliance_engine import ComplianceStatus, check_compliance
from crypto_primitives import EURC_UNITS_MULTIPLIER
from models import EuroDigitalTransaction, TransactionStatus
from transaction_processor import (
    build_user_operation,
    compute_user_op_hash,
    encode_execute_call,
)

load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# FastAPI application
# ---------------------------------------------------------------------------

app = FastAPI(
    title="AEGIS Protocol API",
    version="1.0.0",
    description=(
        "Institutional-grade ERC-4337 Smart Account backend. "
        "Provides transaction initiation, signing, and compliance endpoints."
    ),
)


# ---------------------------------------------------------------------------
# Request / Response schemas
# ---------------------------------------------------------------------------

class InitiateTransactionResponse(BaseModel):
    """Response returned by POST /v1/transaction/initiate."""

    tx_hash: str = Field(..., description="keccak256 hash of the transaction payload")
    status: TransactionStatus = Field(...)
    initiated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    message: str = Field(default="Transaction validated and hash computed")


class SignTransactionRequest(BaseModel):
    """Request body for POST /v1/transaction/sign."""

    tx_hash: str = Field(
        ...,
        description="Transaction hash as returned by /v1/transaction/initiate",
    )
    sender: str = Field(..., description="Ethereum address of the account owner")
    target: str = Field(..., description="Target contract address for the inner call")
    value_wei: int = Field(default=0, ge=0, description="ETH value to forward (wei)")
    inner_calldata_hex: str = Field(
        default="0x",
        description="Hex-encoded calldata for the inner call (e.g. EURC transfer)",
    )
    owner_signature: str = Field(
        ...,
        description=(
            "EIP-191 signature of the tx_hash produced by the account owner's key"
        ),
    )
    amount_eur: float = Field(
        ..., gt=0, description="EUR amount — consumed by the privacy hook"
    )


class SignTransactionResponse(BaseModel):
    """Response returned by POST /v1/transaction/sign."""

    user_op_hash: str = Field(..., description="ERC-4337 userOpHash (bytes32, hex)")
    user_operation: dict = Field(..., description="Full PackedUserOperation ready for relay")
    verified_sender: str = Field(
        ..., description="Ethereum address recovered from the owner signature"
    )
    status: str = Field(default="ready_for_relay")


# ---------------------------------------------------------------------------
# Helper: compute transaction hash
# ---------------------------------------------------------------------------

def _compute_tx_hash(tx: EuroDigitalTransaction) -> str:
    """Compute a deterministic keccak256 hash of the transaction fields.

    The hash covers all immutable fields so that it can be used as a
    commitment and subsequently signed by the account owner.

    Args:
        tx: A validated :class:`~models.EuroDigitalTransaction` instance.

    Returns:
        A ``0x``-prefixed hex string of the 32-byte keccak256 hash.
    """
    from eth_hash.auto import keccak

    payload = (
        tx.sender.lower()
        + tx.recipient_hash.lower()
        + str(int(tx.amount * EURC_UNITS_MULTIPLIER))  # EURC smallest unit
        + str(tx.timestamp)
        + str(tx.nonce)
    )
    digest = keccak(payload.encode("utf-8"))
    return "0x" + digest.hex()


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.post(
    "/v1/transaction/initiate",
    response_model=InitiateTransactionResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Initiate a new EUR Digital transaction",
    tags=["Transaction"],
)
async def initiate_transaction(tx: EuroDigitalTransaction) -> InitiateTransactionResponse:
    """Validate an :class:`~models.EuroDigitalTransaction` and compute its hash.

    - Validates all Pydantic field constraints (amount > 0, valid nonce, etc.).
    - Computes the deterministic keccak256 hash of the transaction payload.
    - Returns the hash so the client can sign it with their owner key before
      calling ``/v1/transaction/sign``.
    """
    try:
        tx_hash = _compute_tx_hash(tx)
    except Exception as exc:
        logger.exception("Failed to compute transaction hash")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Hash computation failed: {exc}",
        ) from exc

    return InitiateTransactionResponse(
        tx_hash=tx_hash,
        status=TransactionStatus.PENDING,
    )


@app.post(
    "/v1/transaction/sign",
    response_model=SignTransactionResponse,
    summary="Sign a transaction and build the ERC-4337 UserOperation",
    tags=["Transaction"],
)
async def sign_transaction(req: SignTransactionRequest) -> SignTransactionResponse:
    """Accept an owner EIP-191 signature and build the ERC-4337 UserOperation.

    Workflow:
    1. Recover the signer from the owner EIP-191 signature over ``tx_hash``.
    2. Confirm the recovered address matches ``sender``.
    3. ABI-encode ``AegisSmartAccount.execute(target, value, innerCalldata)``
       as the UserOperation ``callData``.
    4. Build the full ``PackedUserOperation`` (fetch nonce from EntryPoint).
    5. Compute and return the ``userOpHash`` for optional off-chain relay.

    The returned ``user_operation`` can be submitted directly to a bundler or
    relayed by calling the backend's internal ``relay_transaction`` helper.
    """
    # 1. Recover the signer from the EIP-191 signature.
    try:
        tx_hash_bytes = bytes.fromhex(req.tx_hash.removeprefix("0x"))
        message = encode_defunct(tx_hash_bytes)
        recovered = Account.recover_message(message, signature=req.owner_signature)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Signature recovery failed: {exc}",
        ) from exc

    # 2. Verify sender matches recovered address.
    if recovered.lower() != req.sender.lower():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=(
                f"Signature mismatch: expected signer {req.sender}, "
                f"recovered {recovered}"
            ),
        )

    # 3. Encode the inner execute call.
    try:
        inner_data = bytes.fromhex(req.inner_calldata_hex.removeprefix("0x"))
        call_data = encode_execute_call(
            target=req.target,
            value=req.value_wei,
            data=inner_data,
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Calldata encoding failed: {exc}",
        ) from exc

    # 4. Build the UserOperation (fetches nonce from the chain).
    try:
        user_op = build_user_operation(
            sender=req.sender,
            call_data=call_data,
        )
    except ConnectionError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"RPC connection failed: {exc}",
        ) from exc
    except Exception as exc:
        logger.exception("Failed to build UserOperation")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"UserOperation build failed: {exc}",
        ) from exc

    # 5. Compute the userOpHash.
    try:
        user_op_hash_bytes = compute_user_op_hash(user_op)
        user_op_hash_hex = "0x" + user_op_hash_bytes.hex()
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"userOpHash computation failed: {exc}",
        ) from exc

    # Serialise binary fields for JSON transport.
    serialisable_op = {
        k: ("0x" + v.hex() if isinstance(v, (bytes, bytearray)) else v)
        for k, v in user_op.items()
    }

    return SignTransactionResponse(
        user_op_hash=user_op_hash_hex,
        user_operation=serialisable_op,
        verified_sender=recovered,
    )


@app.get(
    "/v1/compliance/check/{account}",
    response_model=ComplianceStatus,
    summary="Query KYC/AML compliance status for an Ethereum address",
    tags=["Compliance"],
)
async def get_compliance_status(
    account: str = Path(
        ...,
        description="Ethereum address to check (hex, with 0x prefix)",
        examples=["0xAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAa"],
    )
) -> ComplianceStatus:
    """Return the KYC/AML compliance status for *account*.

    Queries the :mod:`compliance_engine` which aggregates:
    - KYC verification state
    - AML screening result
    - Risk tier (low / medium / high / critical)
    - Applicable daily and single-transaction EUR limits
    """
    try:
        return check_compliance(account)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------

@app.get("/healthz", include_in_schema=False)
async def health() -> dict:
    """Liveness probe — returns 200 OK when the server is running."""
    return {"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()}


# ---------------------------------------------------------------------------
# Entry point (direct execution)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main_app:app", host="0.0.0.0", port=8000, reload=True)

