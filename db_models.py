#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
db_models.py - SQLAlchemy ORM models for AEGIS Protocol
"""

from datetime import datetime
from sqlalchemy import (
    Boolean, Column, DateTime, Float, ForeignKey, Integer,
    JSON, Numeric, String, Text, UniqueConstraint,
)

# Money: exact decimal (never float). 18 digits, 2 decimal places.
Money = Numeric(18, 2, asdecimal=True)
from sqlalchemy.orm import relationship

from db import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    # "user" | "compliance" | "authority" | "admin". Changed only by an admin, never at registration.
    role = Column(String(20), default="user", nullable=False)
    # For role "authority": "uif", "guardia_finanza", "tax_authority", "judicial_authority", ...
    authority_type = Column(String(50), nullable=True)
    # Bumped on logout / password change: every token issued before becomes invalid.
    token_version = Column(Integer, default=0, nullable=False)
    # Two factors (TOTP). The secret is encrypted at rest; last step used against replay.
    totp_secret = Column(Text, nullable=True)
    totp_enabled = Column(Boolean, default=False, nullable=False)
    totp_last_step = Column(Integer, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    wallets = relationship("Wallet", back_populates="user")
    compliance_profile = relationship("ComplianceProfile", back_populates="user", uselist=False)
    audit_logs = relationship("AuditLog", back_populates="user")
    scheduled_payments = relationship("ScheduledPayment", back_populates="user")


class Wallet(Base):
    __tablename__ = "wallets"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    address = Column(String(42), unique=True, nullable=False, index=True)
    # LEGACY: the server no longer stores private keys (signing happens on the device).
    encrypted_key = Column(Text, nullable=True)
    balance_eurc = Column(Money, default=0, nullable=False)
    nonce = Column(Integer, default=0, nullable=False)
    is_frozen = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    user = relationship("User", back_populates="wallets")
    sent_transactions = relationship(
        "Transaction", foreign_keys="Transaction.sender_address", back_populates="sender_wallet"
    )


class Transaction(Base):
    __tablename__ = "transactions"

    id = Column(Integer, primary_key=True, index=True)
    tx_hash = Column(String(66), unique=True, nullable=False, index=True)
    sender_address = Column(String(42), ForeignKey("wallets.address"), nullable=False)
    recipient_address = Column(String(42), nullable=False)
    amount = Column(Money, nullable=False)
    status = Column(String(20), default="pending", nullable=False)
    proof_hash = Column(String(66), nullable=True)
    requires_zk_proof = Column(Boolean, default=False, nullable=False)
    block_number = Column(Integer, nullable=True)
    gas_used = Column(Integer, nullable=True)
    tx_metadata = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    confirmed_at = Column(DateTime, nullable=True)

    sender_wallet = relationship("Wallet", foreign_keys=[sender_address], back_populates="sent_transactions")


class ComplianceProfile(Base):
    __tablename__ = "compliance_profiles"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), unique=True, nullable=False)
    kyc_verified = Column(Boolean, default=False, nullable=False)
    # "none" | "pending" | "approved" | "rejected": only compliance or the provider moves it to approved.
    kyc_status = Column(String(20), default="none", nullable=False)
    kyc_tier = Column(Integer, default=0, nullable=False)
    kyc_provider_ref = Column(String(255), nullable=True)
    kyc_country = Column(String(2), nullable=True)  # ISO 3166-1 alpha-2, from the verification
    aml_screened = Column(Boolean, default=False, nullable=False)
    daily_limit = Column(Money, default=10000, nullable=False)
    single_tx_limit = Column(Money, default=5000, nullable=False)
    risk_level = Column(String(20), default="low", nullable=False)
    last_risk_assessment = Column(DateTime, nullable=True)
    last_kyc_at = Column(DateTime, nullable=True)
    zk_proof_hash = Column(String(66), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    user = relationship("User", back_populates="compliance_profile")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    action = Column(String(100), nullable=False)
    resource_type = Column(String(50), nullable=True)
    resource_id = Column(String(100), nullable=True)
    ip_address = Column(String(45), nullable=True)
    details = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    user = relationship("User", back_populates="audit_logs")


class ViewingKey(Base):
    __tablename__ = "viewing_keys"

    id = Column(Integer, primary_key=True, index=True)
    owner_address = Column(String(42), nullable=False, index=True)
    grantee = Column(String(255), nullable=False)
    scope = Column(String(30), nullable=False)
    encrypted_data = Column(Text, nullable=True)
    granted_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    active = Column(Boolean, default=True, nullable=False)
    revoked_at = Column(DateTime, nullable=True)


class ScheduledPayment(Base):
    __tablename__ = "scheduled_payments"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    from_address = Column(String(42), nullable=False)
    to_address = Column(String(42), nullable=False)
    amount = Column(Money, nullable=False)
    scheduled_at = Column(DateTime, nullable=False)
    is_recurring = Column(Boolean, default=False, nullable=False)
    frequency = Column(String(20), nullable=True)
    status = Column(String(20), default="pending", nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_executed_at = Column(DateTime, nullable=True)

    user = relationship("User", back_populates="scheduled_payments")


# ============================================================================
# VIEWING KEYS V2 DB MODELS
# ============================================================================

class ViewingKeyV2DB(Base):
    __tablename__ = "viewing_keys_v2"

    key_id = Column(String(36), primary_key=True, index=True)
    address = Column(String(255), nullable=False, index=True)
    scope = Column(String(30), nullable=False)
    status = Column(String(20), nullable=False, default="active")
    parent_id = Column(String(36), nullable=True)
    created_at = Column(Float, nullable=False)
    expires_at = Column(Float, nullable=True)
    max_uses = Column(Integer, nullable=True)
    use_count = Column(Integer, nullable=False, default=0)
    revoked_at = Column(Float, nullable=True)


class RegulatoryEscrowDB(Base):
    __tablename__ = "regulatory_escrows"

    escrow_id = Column(String(36), primary_key=True, index=True)
    tx_hash = Column(String(255), nullable=False, index=True)
    ephemeral_public_hex = Column(Text, nullable=False)
    ciphertext_hex = Column(Text, nullable=False)
    nonce_hex = Column(String(64), nullable=False)
    tag_hex = Column(String(64), nullable=False)
    created_at = Column(Float, nullable=False)
    decrypted_at = Column(Float, nullable=True)
    legal_reference = Column(String(500), nullable=True)


# ============================================================================
# REGULATORY ACCESS REQUESTS DB MODEL
# ============================================================================

class RegulatoryAccessRequestDB(Base):
    __tablename__ = "regulatory_access_requests"

    request_id = Column(String(36), primary_key=True, index=True)
    requester_id = Column(String(255), nullable=False, index=True)
    requester_type = Column(String(50), nullable=False)
    owner_address = Column(String(42), nullable=False, index=True)
    tx_hash = Column(String(66), nullable=False, index=True)
    scope_requested = Column(String(30), nullable=False)
    duration_days_requested = Column(Integer, nullable=False)
    legal_reference = Column(String(500), nullable=False)
    reason = Column(Text, nullable=False)
    status = Column(String(30), nullable=False, default="pending_user_approval")
    scope_granted = Column(String(30), nullable=True)
    duration_days_granted = Column(Integer, nullable=True)
    viewing_key_id = Column(String(36), nullable=True)
    denied_reason = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    responded_at = Column(DateTime, nullable=True)
    expires_at = Column(DateTime, nullable=True)


class LoginAttempt(Base):
    """Login attempts, used to lock out brute force (per username and per IP)."""

    __tablename__ = "login_attempts"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), nullable=False, index=True)
    ip_address = Column(String(45), nullable=True, index=True)
    success = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)


class PersistentState(Base):
    """Encrypted state of the viewing-key / regulatory-request managers (see viewing_keys/persistence.py)."""

    __tablename__ = "aegis_state"
    __table_args__ = (UniqueConstraint("namespace", "key", name="uq_aegis_state_ns_key"),)

    id = Column(Integer, primary_key=True)
    namespace = Column(String(64), nullable=False, index=True)
    key = Column(String(128), nullable=False)
    value = Column(Text, nullable=False)  # Fernet token of the JSON record
    updated_at = Column(Float, nullable=False)


class PoolPseudonym(Base):
    """Operator register: pseudonym (owner_pubkey of the ZK notes) → KYC'd customer.

    It is the link that makes graduated disclosure possible (L4 identity) and lets the
    operator know whose transactions it relays, without decrypting anything.
    """

    __tablename__ = "pool_pseudonyms"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    pseudonym = Column(String(66), unique=True, nullable=False, index=True)
    tier = Column(Integer, nullable=False)
    jurisdiction = Column(Integer, nullable=False)
    credential_expiry = Column(Integer, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class PoolRelay(Base):
    """Transactions relayed to the ShieldedPool on behalf of customers (AML record keeping)."""

    __tablename__ = "pool_relays"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    tx_hash = Column(String(66), unique=True, nullable=False, index=True)
    public_in = Column(Integer, nullable=False, default=0)
    public_out = Column(Integer, nullable=False, default=0)
    status = Column(String(20), nullable=False, default="submitted")
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class WalletLinkChallenge(Base):
    """One-time challenge to prove control of an address by signing it (EIP-191)."""

    __tablename__ = "wallet_link_challenges"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    nonce = Column(String(64), unique=True, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    used = Column(Boolean, default=False, nullable=False)


class BankOperation(Base):
    """EUR deposits and withdrawals: one state in the DB for all workers, idempotent."""

    __tablename__ = "bank_operations"
    __table_args__ = (UniqueConstraint("user_id", "kind", "idempotency_key", name="uq_bank_op_idempotency"),)

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    kind = Column(String(20), nullable=False)  # deposit | withdrawal
    amount = Column(Money, nullable=False)
    wallet_address = Column(String(42), nullable=False)
    status = Column(String(30), nullable=False)
    reference = Column(String(32), unique=True, nullable=False, index=True)
    idempotency_key = Column(String(128), nullable=True)
    iban_masked = Column(String(12), nullable=True)
    payout_ref_hash = Column(String(66), nullable=True)
    bank_tx_id = Column(String(128), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
