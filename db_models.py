#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
db_models.py - SQLAlchemy ORM models for AEGIS Protocol
"""

from datetime import datetime
from sqlalchemy import (
    Boolean, Column, DateTime, Float, ForeignKey, Integer,
    JSON, String, Text, UniqueConstraint,
)
from sqlalchemy.orm import relationship

from db import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
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
    encrypted_key = Column(Text, nullable=False)
    balance_eurc = Column(Float, default=0.0, nullable=False)
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
    amount = Column(Float, nullable=False)
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
    aml_screened = Column(Boolean, default=False, nullable=False)
    daily_limit = Column(Float, default=10000.0, nullable=False)
    single_tx_limit = Column(Float, default=5000.0, nullable=False)
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
    amount = Column(Float, nullable=False)
    scheduled_at = Column(DateTime, nullable=False)
    is_recurring = Column(Boolean, default=False, nullable=False)
    frequency = Column(String(20), nullable=True)
    status = Column(String(20), default="pending", nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_executed_at = Column(DateTime, nullable=True)

    user = relationship("User", back_populates="scheduled_payments")
