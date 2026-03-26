#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
db_models.py - SQLAlchemy ORM models for AEGIS Protocol

Tables:
  - users
  - wallets
  - transactions
  - compliance_profiles
  - audit_logs
"""

import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    JSON,
)
from sqlalchemy.orm import relationship

from db import Base


def _new_uuid() -> str:
    return str(uuid.uuid4())


# ---------------------------------------------------------------------------
# User
# ---------------------------------------------------------------------------


class User(Base):
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=_new_uuid)
    username = Column(String(64), unique=True, nullable=False, index=True)
    email = Column(String(256), unique=True, nullable=False, index=True)
    hashed_password = Column(String(256), nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    wallets = relationship("Wallet", back_populates="user", cascade="all, delete-orphan")
    compliance_profile = relationship(
        "ComplianceProfile", back_populates="user", uselist=False, cascade="all, delete-orphan"
    )
    audit_logs = relationship("AuditLog", back_populates="user", cascade="all, delete-orphan")


# ---------------------------------------------------------------------------
# Wallet
# ---------------------------------------------------------------------------


class Wallet(Base):
    __tablename__ = "wallets"

    id = Column(String(36), primary_key=True, default=_new_uuid)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False, index=True)
    address = Column(String(42), unique=True, nullable=False, index=True)
    # Encrypted private key — never stored in plaintext
    encrypted_key = Column(Text, nullable=True)
    balance_eurc = Column(Float, default=0.0, nullable=False)
    nonce = Column(Integer, default=0, nullable=False)
    is_frozen = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    user = relationship("User", back_populates="wallets")
    transactions_sent = relationship(
        "Transaction", foreign_keys="Transaction.sender_address", back_populates="sender_wallet"
    )


# ---------------------------------------------------------------------------
# Transaction
# ---------------------------------------------------------------------------


class Transaction(Base):
    __tablename__ = "transactions"

    id = Column(String(36), primary_key=True, default=_new_uuid)
    tx_hash = Column(String(66), unique=True, nullable=True, index=True)
    sender_address = Column(String(42), ForeignKey("wallets.address"), nullable=False, index=True)
    recipient_address = Column(String(42), nullable=False, index=True)
    amount = Column(Float, nullable=False)
    status = Column(String(20), default="pending", nullable=False)
    proof_hash = Column(String(66), nullable=True)
    requires_zk_proof = Column(Boolean, default=False, nullable=False)
    block_number = Column(Integer, nullable=True)
    gas_used = Column(Integer, nullable=True)
    tx_metadata = Column("tx_metadata", JSON, default=dict)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    confirmed_at = Column(DateTime, nullable=True)

    sender_wallet = relationship(
        "Wallet", foreign_keys=[sender_address], back_populates="transactions_sent"
    )


# ---------------------------------------------------------------------------
# ComplianceProfile
# ---------------------------------------------------------------------------


class ComplianceProfile(Base):
    __tablename__ = "compliance_profiles"

    id = Column(String(36), primary_key=True, default=_new_uuid)
    user_id = Column(String(36), ForeignKey("users.id"), unique=True, nullable=False, index=True)
    kyc_verified = Column(Boolean, default=False, nullable=False)
    aml_screened = Column(Boolean, default=False, nullable=False)
    daily_limit = Column(Float, default=1000.0, nullable=False)
    single_tx_limit = Column(Float, default=500.0, nullable=False)
    risk_level = Column(String(20), default="low", nullable=False)
    last_risk_assessment = Column(DateTime, nullable=True)
    last_kyc_at = Column(DateTime, nullable=True)
    zk_proof_hash = Column(String(66), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    user = relationship("User", back_populates="compliance_profile")


# ---------------------------------------------------------------------------
# AuditLog
# ---------------------------------------------------------------------------


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(String(36), primary_key=True, default=_new_uuid)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=True, index=True)
    action = Column(String(128), nullable=False)
    resource_type = Column(String(64), nullable=True)
    resource_id = Column(String(36), nullable=True)
    ip_address = Column(String(45), nullable=True)
    details = Column(JSON, default=dict)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    user = relationship("User", back_populates="audit_logs")
