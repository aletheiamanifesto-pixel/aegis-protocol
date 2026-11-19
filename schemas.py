#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
schemas.py - Pydantic request/response models for AEGIS Protocol API.
"""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class RegisterRequest(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    email: str = Field(min_length=3, max_length=255)
    password: str = Field(min_length=12, max_length=128)


class LoginRequest(BaseModel):
    username: str
    password: str
    totp_code: Optional[str] = None


class WalletLinkRequest(BaseModel):
    address: str
    nonce: str
    signature: str  # EIP-191 signature of the challenge message, made on the device


class SendTransactionRequest(BaseModel):
    """Transaction ALREADY SIGNED on the device (EIP-1559 raw tx): the key never travels."""
    signed_tx: str
    proof_hash: Optional[str] = None
    totp_code: Optional[str] = None


class KYCRequest(BaseModel):
    full_name: str
    date_of_birth: str
    country: str
    id_document_hash: str


class ViewingKeyCreateRequest(BaseModel):
    owner_address: str
    scope: str = "balance_only"
    duration_days: int = 30


class ViewingKeyGrantRequest(BaseModel):
    owner_address: str
    grantee: str
    scope: str = "balance_only"
    duration_days: int = 30


class ViewingKeyRedeemRequest(BaseModel):
    grantee: str


class DepositRequest(BaseModel):
    amount: float
    wallet_address: str


class WithdrawRequest(BaseModel):
    amount: float
    wallet_address: str
    iban: str
    totp_code: str  # withdrawals always require the second factor


class SchedulePaymentRequest(BaseModel):
    from_address: str
    to_address: str
    amount: float
    scheduled_at: datetime


class RecurringPaymentRequest(BaseModel):
    from_address: str
    to_address: str
    amount: float
    frequency: str
    start_date: Optional[datetime] = None


class SubmitBundleRequest(BaseModel):
    bundle_id: str
    merkle_root: str
    tx_count: int = 0


class ComplianceReportRequest(BaseModel):
    period_start: datetime
    period_end: datetime


class BridgeInitiateRequest(BaseModel):
    source_chain: str
    dest_chain: str
    token_address: str
    amount: float
    recipient: str
    sender: str


# ---------------------------------------------------------------------------
# Viewing Keys V2
# ---------------------------------------------------------------------------

class ViewingKeyV2CreateRequest(BaseModel):
    address: str


class ViewingKeyV2DeriveRequest(BaseModel):
    master_key_id: str
    scope: str = "balance_only"
    context: str = ""
    expires_in: Optional[int] = None   # seconds
    max_uses: Optional[int] = None


class ViewingKeyV2DecryptRequest(BaseModel):
    key_id: str
    ciphertext: str
    nonce: str
    tag: str


class ViewingKeyV2RevokeRequest(BaseModel):
    key_id: str


# ---------------------------------------------------------------------------
# Regulatory Access Flow
# ---------------------------------------------------------------------------

class RegulatoryRequestCreate(BaseModel):
    requester_id: str
    requester_type: str   # "uif", "guardia_finanza", "esma", "tax_authority", "aml_authority"
    owner_address: str
    tx_hash: str
    scope: str = "single_tx"
    duration_days: int = 30
    legal_reference: str   # mandatory, e.g. "Decreto 231/2007 Art. 35"
    reason: str


class RegulatoryRequestApprove(BaseModel):
    owner_address: str
    scope: str        # scope actually granted (may be more restrictive than requested)
    duration_days: int   # duration actually granted (may be shorter than requested)


class RegulatoryRequestDeny(BaseModel):
    owner_address: str
    reason: str = ""


class RegulatoryRequestRevoke(BaseModel):
    owner_address: str
