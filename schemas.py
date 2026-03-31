#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
schemas.py - Pydantic request/response models for AEGIS Protocol API.
"""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel


class RegisterRequest(BaseModel):
    username: str
    email: str
    password: str


class LoginRequest(BaseModel):
    username: str
    password: str


class WalletCreateRequest(BaseModel):
    password: str


class WalletImportRequest(BaseModel):
    mnemonic_or_private_key: str
    password: str


class SendTransactionRequest(BaseModel):
    from_address: str
    to_address: str
    amount: float
    encrypted_key: str
    password: str
    proof_hash: Optional[str] = None


class KYCRequest(BaseModel):
    full_name: str
    date_of_birth: str
    country: str
    id_document_hash: str


class ProofGenerateRequest(BaseModel):
    sender: str
    amount: float
    purpose: str = "transfer"


class ProofVerifyRequest(BaseModel):
    proof_hash: str
    sender: str
    amount: float


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
