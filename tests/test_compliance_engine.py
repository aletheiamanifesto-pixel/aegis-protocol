#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for compliance_engine.py"""

import pytest
from compliance_engine import (
    ComplianceEngine,
    ComplianceResult,
    ZKProofStub,
    MICA_ZK_THRESHOLD_EUR,
    MAX_DAILY_DEFAULT,
    MAX_SINGLE_DEFAULT,
    _velocity_tracker,
)
from bundler.config import BundlerConfig

_DEFAULT_SINGLE_TX_LIMIT = BundlerConfig().velocity_limits["single_tx"]


@pytest.fixture
def engine():
    return ComplianceEngine()


class TestComplianceEngine:
    def test_valid_small_transaction(self, engine):
        result = engine.check_transaction("0xsender", 100.0)
        assert result.approved
        assert not result.requires_zk_proof
        assert result.risk_level == "low"

    def test_negative_amount_rejected(self, engine):
        result = engine.check_transaction("0xsender", -10.0)
        assert not result.approved

    def test_zero_amount_rejected(self, engine):
        result = engine.check_transaction("0xsender", 0)
        assert not result.approved

    def test_amount_exceeds_single_tx_limit(self, engine):
        result = engine.check_transaction(
            "0xsender", MAX_SINGLE_DEFAULT + 1
        )
        assert not result.approved
        assert "SINGLE_TX_LIMIT_EXCEEDED" in result.flags
        assert result.risk_level == "high"

    def test_daily_limit_exceeded(self, engine):
        result = engine.check_transaction(
            "0xsender2",
            amount=5000.0,
            daily_spent=9000.0,
            daily_limit=10000.0,
        )
        assert not result.approved
        assert "DAILY_LIMIT_EXCEEDED" in result.flags
        assert result.risk_level == "medium"

    def test_zk_proof_required_for_large_amount(self, engine):
        result = engine.check_transaction(
            "0xsender3",
            amount=MICA_ZK_THRESHOLD_EUR,
            kyc_verified=True,
        )
        assert result.approved
        assert result.requires_zk_proof
        assert "ZK_PROOF_REQUIRED" in result.flags

    def test_large_amount_without_kyc_rejected(self, engine):
        result = engine.check_transaction(
            "0xsender4",
            amount=MICA_ZK_THRESHOLD_EUR,
            kyc_verified=False,
        )
        assert not result.approved
        assert result.requires_zk_proof

    def test_mica_threshold(self, engine):
        assert engine.get_mica_threshold() == MICA_ZK_THRESHOLD_EUR

    def test_generate_zk_proof_stub(self, engine):
        proof = engine.generate_zk_proof_stub("0xsender", 1500.0, "transfer")
        assert isinstance(proof, ZKProofStub)
        assert proof.proof_hash.startswith("0x")
        assert proof.valid_until > proof.generated_at
        assert "sender_hash" in proof.public_inputs
        assert "amount_range" in proof.public_inputs

    def test_proof_amount_range_flag(self, engine):
        proof_large = engine.generate_zk_proof_stub("0xaddr", 2000.0)
        proof_small = engine.generate_zk_proof_stub("0xaddr", 500.0)
        assert proof_large.public_inputs["amount_range"] is True
        assert proof_small.public_inputs["amount_range"] is False


class TestVelocityLimit:
    def test_velocity_limit_blocks_after_max(self, engine):
        """Sending _DEFAULT_SINGLE_TX_LIMIT transactions should trigger velocity limit on the next."""
        sender = "0xvelocity_test_unique_address_abc123"
        # Reset any prior state for this address
        _velocity_tracker.reset(sender)

        for _ in range(_DEFAULT_SINGLE_TX_LIMIT):
            r = engine.check_transaction(sender, 1.0)
            assert r.approved

        # Next transaction should be blocked
        blocked = engine.check_transaction(sender, 1.0)
        assert not blocked.approved
        assert "VELOCITY_LIMIT_EXCEEDED" in blocked.flags
