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
from pydantic import BaseModel, Field, field_validator, model_validator


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
    
    transactions: List[EuroDigitalTransaction] = Field(..., min_length=1)
    batch_id: str = Field(default_factory=lambda: str(__import__('uuid').uuid4()))
    created_at: datetime = Field(default_factory=datetime.now)

    @field_validator('transactions')
    @classmethod
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
    
    @field_validator('valid_until')
    @classmethod
    def validate_expiry(cls, v, info):
        if 'timestamp' in (info.data if hasattr(info, 'data') else {}):
            if v <= info.data['timestamp']:
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
    
    @field_validator('expires_at')
    @classmethod
    def validate_expiry_date(cls, v, info):
        data = info.data if hasattr(info, 'data') else {}
        if 'issued_at' in data:
            if v <= data['issued_at']:
                raise ValueError("expires_at must be after issued_at")
            max_duration = data['issued_at'] + timedelta(days=365)
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
    
    @field_validator('requester_type')
    @classmethod
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
    
    @model_validator(mode='after')
    def check_expiry_after_grant(self):
        if self.expires_at <= self.granted_at:
            raise ValueError("expires_at must be after granted_at")
        return self
    
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
    
    @field_validator('effective_until')
    @classmethod
    def validate_effective_period(cls, v, info):
        data = info.data if hasattr(info, 'data') else {}
        if 'effective_from' in data and v:
            if v <= data['effective_from']:
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

# ============================================================================
# VIEWING KEYS V2 MODELS
# ============================================================================

from viewing_keys.scope_filter import KeyScope, KeyStatus  # noqa: E402


class ViewingKeyV2Create(BaseModel):
    """Request body for creating a master viewing key."""
    address: str = Field(..., description="Wallet address")


class ViewingKeyV2Response(BaseModel):
    """Response with key info (no secret exposed)."""
    key_id: str
    address: str
    scope: str
    status: str
    parent_id: Optional[str] = None
    children_ids: List[str] = Field(default_factory=list)
    created_at: float
    expires_at: Optional[float] = None
    max_uses: Optional[int] = None
    use_count: int = 0
    revoked_at: Optional[float] = None


class SubKeyDerive(BaseModel):
    """Request body for deriving a sub-key from a master key."""
    master_key_id: str = Field(..., description="ID of the parent master key")
    scope: str = Field(..., description="KeyScope value")
    context: str = Field(default="", description="HKDF derivation context")
    expires_in: Optional[int] = Field(None, description="Seconds until expiry")
    max_uses: Optional[int] = Field(None, description="Maximum decrypt uses")


class DecryptRequest(BaseModel):
    """Request body for decrypting a transaction."""
    key_id: str = Field(..., description="Viewing key ID to use")
    ciphertext: str = Field(..., description="Hex-encoded ciphertext")
    nonce: str = Field(..., description="Hex-encoded nonce")
    tag: str = Field(..., description="Hex-encoded authentication tag")


class RegulatoryEscrowResponse(BaseModel):
    """Response model for a regulatory escrow record."""
    escrow_id: str
    tx_hash: str
    ephemeral_public_hex: str
    ciphertext_hex: str
    nonce_hex: str
    tag_hex: str
    created_at: float


class BundleModel(BaseModel):
    """Represents a bundled transaction set (PR #1 compatibility)."""
    bundle_id: str = Field(..., description="Unique bundle identifier")
    transactions: List[Dict[str, Any]] = Field(default_factory=list)
    merkle_root: Optional[str] = Field(None)
    created_at: Optional[float] = Field(None)
    status: str = Field(default="pending")
