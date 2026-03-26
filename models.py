#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
models.py - Pydantic schemas for AEGIS Protocol

Definisce tutti i modelli di dati per:
- Transazioni con privacy ZK
- Certificati di merito creditizio
- Viewing keys
- Compliance rules
"""

from enum import Enum
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, validator, root_validator


# ============================================================================
# ENUMS
# ============================================================================

class ProofPurpose(str, Enum):
    """Propositi autorizzati per le prove ZK"""
    CREDIT_CHECK = "credit_check"
    TAX_AUDIT = "tax_audit"
    AML = "aml"
    KYC = "kyc"
    LENDING = "lending"


class TransactionStatus(str, Enum):
    """Stato di una transazione"""
    PENDING = "pending"
    VERIFIED = "verified"
    CONFIRMED = "confirmed"
    FAILED = "failed"


class ScopeType(str, Enum):
    """Tipi di scope per viewing keys"""
    FULL_ACCESS = "full_access"
    BALANCE_ONLY = "balance_only"
    TRANSACTIONS_ONLY = "transactions_only"
    LIMITED = "limited"


# ============================================================================
# TRANSACTION MODELS
# ============================================================================

class EuroDigitalTransaction(BaseModel):
    """Rappresentazione di una transazione EUR Digital"""
    
    tx_hash: str = Field(..., description="Hash univoco della transazione")
    sender: str = Field(..., description="Indirizzo del mittente")
    recipient_hash: str = Field(..., description="Hash crittografico del destinatario (privacy)")
    amount: float = Field(..., gt=0, description="Importo in EUR")
    timestamp: int = Field(..., description="Unix timestamp della transazione")
    nonce: int = Field(..., ge=0, description="Nonce anti-replay")
    proof_hash: Optional[str] = Field(None, description="Hash della prova ZK associata")
    status: TransactionStatus = Field(default=TransactionStatus.PENDING)
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict)
    
    class Config:
        json_schema_extra = {
            "example": {
                "tx_hash": "0xabcd1234...",
                "sender": "0x1234567890...",
                "recipient_hash": "keccak256(recipient_address)",
                "amount": 1500.50,
                "timestamp": 1700000000,
                "nonce": 42,
                "status": "verified"
            }
        }


class TransactionBatch(BaseModel):
    """Batch di transazioni per processing"""
    
    transactions: List[EuroDigitalTransaction] = Field(..., min_items=1)
    batch_id: str = Field(default_factory=lambda: str(__import__('uuid').uuid4()))
    created_at: datetime = Field(default_factory=datetime.now)
    
    @validator('transactions')
    def validate_batch_size(cls, v):
        if len(v) > 1000:
            raise ValueError("Batch size exceeded (max 1000 transactions)")
        return v


# ============================================================================
# PROOF & VERIFICATION MODELS
# ============================================================================

class ZKProofComponent(BaseModel):
    """Componente di una prova ZK"""
    
    name: str = Field(..., description="Nome del componente (es: balance_commitment)")
    value: str = Field(..., description="Valore in hex")
    commitment_type: str = Field(..., description="Tipo di commitment (pedersen, mimc)")


class ZKProof(BaseModel):
    """Prova ZK completa"""
    
    proof_hash: str = Field(..., description="Hash della prova")
    components: List[ZKProofComponent] = Field(..., description="Componenti della prova")
    public_inputs: Dict[str, Any] = Field(..., description="Input pubblici")
    merkle_root: str = Field(..., description="Root dell'albero Merkle")
    timestamp: int = Field(..., description="Timestamp della generazione")
    valid_until: int = Field(..., description="Timestamp di scadenza")
    
    @validator('valid_until')
    def validate_expiry(cls, v, values):
        if 'timestamp' in values:
            if v <= values['timestamp']:
                raise ValueError("valid_until must be after timestamp")
        return v


class CreditWorthinessCertificate(BaseModel):
    """Certificato di merito creditizio (Selective Disclosure)"""
    
    certificate_id: str = Field(default_factory=lambda: str(__import__('uuid').uuid4()))
    holder: str = Field(..., description="Indirizzo del proprietario")
    minimum_balance: float = Field(..., ge=0, description="Minimo importo attestato")
    issued_at: datetime = Field(default_factory=datetime.now)
    expires_at: datetime = Field(...)
    proof_hash: str = Field(..., description="Hash della prova che sottende il certificato")
    issuer: str = Field(..., description="Chi ha emesso il certificato (es: smart contract)")
    active: bool = Field(default=True)
    
    @validator('expires_at')
    def validate_expiry_date(cls, v, values):
        if 'issued_at' in values:
            if v <= values['issued_at']:
                raise ValueError("expires_at must be after issued_at")
            max_duration = values['issued_at'] + timedelta(days=365)
            if v > max_duration:
                raise ValueError("Certificate validity cannot exceed 1 year")
        return v
    
    class Config:
        json_schema_extra = {
            "example": {
                "holder": "0x1234567890...",
                "minimum_balance": 50000.0,
                "expires_at": "2024-03-24T10:00:00",
                "proof_hash": "0x..."
            }
        }


# ============================================================================
# VIEWING KEY MODELS
# ============================================================================

class ViewingKeyRequest(BaseModel):
    """Richiesta di viewing key da parte di un ente"""
    
    request_id: str = Field(default_factory=lambda: str(__import__('uuid').uuid4()))
    requester_id: str = Field(..., description="ID dell'ente che richiede accesso")
    requester_type: str = Field(..., description="Tipo di ente (bank, tax_authority, aml)")
    scope: ScopeType = Field(..., description="Ambito di accesso richiesto")
    duration_days: int = Field(default=30, ge=1, le=90)
    reason: str = Field(..., description="Motivo della richiesta")
    required_merit: Optional[float] = Field(None, description="Se richiede selective disclosure")
    
    @validator('requester_type')
    def validate_requester_type(cls, v):
        valid_types = ['bank', 'tax_authority', 'aml', 'credit_agency', 'other']
        if v not in valid_types:
            raise ValueError(f"Invalid requester_type: {v}")
        return v


class ViewingKeyPermission(BaseModel):
    """Permesso di viewing key concesso"""
    
    permission_id: str = Field(default_factory=lambda: str(__import__('uuid').uuid4()))
    owner: str = Field(..., description="Proprietario del wallet")
    grantee: str = Field(..., description="Ente che ha ricevuto il permesso")
    scope: ScopeType = Field(...)
    data_hash: str = Field(..., description="Hash dei dati visualizzabili")
    granted_at: datetime = Field(default_factory=datetime.now)
    expires_at: datetime = Field(...)
    active: bool = Field(default=True)
    revoked_at: Optional[datetime] = Field(None)
    
    @root_validator(skip_on_failure=True)
    def check_expiry_after_grant(cls, values):
        if 'granted_at' in values and 'expires_at' in values:
            if values['expires_at'] <= values['granted_at']:
                raise ValueError("expires_at must be after granted_at")
        return values
    
    class Config:
        json_schema_extra = {
            "example": {
                "owner": "0x1234...",
                "grantee": "0x5678...",
                "scope": "balance_only",
                "expires_at": "2024-04-24T10:00:00",
                "active": True
            }
        }


class AccessLog(BaseModel):
    """Log di un accesso con viewing key"""
    
    log_id: str = Field(default_factory=lambda: str(__import__('uuid').uuid4()))
    permission_id: str = Field(..., description="ID del permesso utilizzato")
    accessed_at: datetime = Field(default_factory=datetime.now)
    data_accessed: str = Field(..., description="Tipo di dato consultato")
    ip_address: Optional[str] = Field(None, description="IP di accesso")
    approved: bool = Field(default=True)
    notes: Optional[str] = Field(None)


# ============================================================================
# COMPLIANCE MODELS
# ============================================================================

class ComplianceRule(BaseModel):
    """Regola di compliance MiCA"""
    
    rule_id: str = Field(..., description="ID univoco della regola")
    rule_type: str = Field(..., description="Tipo di regola (aml, kyc, transaction_limit)")
    trigger_amount: float = Field(..., ge=0, description="Importo che attiva la regola")
    action: str = Field(..., description="Azione da intraprendere (block, require_proof, notify)")
    description: str = Field(...)
    effective_from: datetime = Field(default_factory=datetime.now)
    effective_until: Optional[datetime] = Field(None)
    active: bool = Field(default=True)
    
    @validator('effective_until')
    def validate_effective_period(cls, v, values):
        if 'effective_from' in values and v:
            if v <= values['effective_from']:
                raise ValueError("effective_until must be after effective_from")
        return v


class ComplianceProfile(BaseModel):
    """Profilo di compliance di un utente"""
    
    user_id: str = Field(...)
    kyc_verified: bool = Field(default=False, description="KYC completato")
    aml_screened: bool = Field(default=False, description="Screening AML completato")
    daily_limit: float = Field(..., ge=0, description="Limite transazioni giornaliere")
    single_transaction_limit: float = Field(..., ge=0)
    last_risk_assessment: Optional[datetime] = Field(None)
    risk_level: str = Field(default="low", description="low, medium, high, critical")
    
    class Config:
        json_schema_extra = {
            "example": {
                "kyc_verified": True,
                "aml_screened": True,
                "daily_limit": 1000000,
                "single_transaction_limit": 100000,
                "risk_level": "low"
            }
        }


class SuspiciousActivityReport(BaseModel):
    """Report di attività sospetta"""
    
    report_id: str = Field(default_factory=lambda: str(__import__('uuid').uuid4()))
    user_id: str = Field(...)
    activity_type: str = Field(..., description="Tipo di attività (velocity, amount_anomaly, pattern)")
    severity: str = Field(..., description="low, medium, high, critical")
    detected_at: datetime = Field(default_factory=datetime.now)
    description: str = Field(...)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    flagged: bool = Field(default=True)


# ============================================================================
# API REQUEST/RESPONSE MODELS
# ============================================================================

class ProofGenerationRequest(BaseModel):
    """Richiesta di generazione di prova"""
    
    requester_id: str = Field(...)
    required_merit: float = Field(..., ge=0)
    purpose: ProofPurpose = Field(...)
    duration_days: int = Field(default=30, ge=1, le=90)


class ProofGenerationResponse(BaseModel):
    """Risposta con prova generata"""
    
    status: str = Field(..., description="success, failed")
    proof: Optional[ZKProof] = Field(None)
    proof_hash: Optional[str] = Field(None)
    error: Optional[str] = Field(None)
    generated_at: datetime = Field(default_factory=datetime.now)


class WalletStatusResponse(BaseModel):
    """Status del wallet"""
    
    address: str = Field(...)
    balance: float = Field(...)
    nonce: int = Field(...)
    balance_commitment: str = Field(...)
    active_viewing_keys_count: int = Field(...)
    recent_transactions: List[EuroDigitalTransaction] = Field(default_factory=list)
    compliance_level: str = Field(..., description="verified, pending, failed")
    verified_until: Optional[datetime] = Field(None)


# ============================================================================
# ATTESTATION & BADGE MODELS
# ============================================================================

class VerificationBadge(BaseModel):
    """Badge di verificazione da mostrare nel frontend"""
    
    badge_type: str = Field(..., description="zk_verified, kyc_verified, certified")
    label: str = Field(..., description="Testo del badge")
    icon_url: Optional[str] = Field(None)
    verified_at: datetime = Field(...)
    expires_at: Optional[datetime] = Field(None)
    issuer: str = Field(..., description="Chi ha emesso il badge")
    
    class Config:
        json_schema_extra = {
            "example": {
                "badge_type": "zk_verified",
                "label": "Cryptographically Verified",
                "verified_at": "2024-03-24T10:00:00",
                "issuer": "AEGIS Protocol"
            }
        }