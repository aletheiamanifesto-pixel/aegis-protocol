#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tests/test_bridge.py - Tests for the cross-chain BridgeManager.
"""

import pytest
from unittest.mock import MagicMock, patch

from bridge.config import BridgeConfig, SUPPORTED_CHAINS
from bridge.bridge_manager import BridgeManager, BridgeRequest, BridgeResult, BridgeError


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_request(
    source_chain: str = "polygon_amoy",
    dest_chain: str = "ethereum_sepolia",
    amount: float = 100.0,
    sender: str = "0xSender",
    recipient: str = "0xRecipient",
    token_address: str = "0xToken",
) -> BridgeRequest:
    return BridgeRequest(
        source_chain=source_chain,
        dest_chain=dest_chain,
        token_address=token_address,
        amount=amount,
        recipient=recipient,
        sender=sender,
    )


def _dev_manager(compliance_engine=None) -> BridgeManager:
    cfg = BridgeConfig(dev_mode=True)
    return BridgeManager(config=cfg, compliance_engine=compliance_engine)


# ---------------------------------------------------------------------------
# Config tests
# ---------------------------------------------------------------------------

class TestBridgeConfig:
    def test_supported_chains_present(self):
        assert "polygon_amoy" in SUPPORTED_CHAINS
        assert "ethereum_sepolia" in SUPPORTED_CHAINS
        assert "base_sepolia" in SUPPORTED_CHAINS

    def test_polygon_amoy_chain_id(self):
        assert SUPPORTED_CHAINS["polygon_amoy"] == 80002

    def test_ethereum_sepolia_chain_id(self):
        assert SUPPORTED_CHAINS["ethereum_sepolia"] == 11155111

    def test_base_sepolia_chain_id(self):
        assert SUPPORTED_CHAINS["base_sepolia"] == 84532

    def test_default_config_has_supported_chains(self):
        cfg = BridgeConfig()
        assert len(cfg.supported_chains) == 3


# ---------------------------------------------------------------------------
# Request validation tests
# ---------------------------------------------------------------------------

class TestBridgeRequestValidation:
    def test_unsupported_source_chain_raises(self):
        manager = _dev_manager()
        req = _make_request(source_chain="invalid_chain")
        with pytest.raises(BridgeError, match="Unsupported source chain"):
            manager.initiate_bridge(req)

    def test_unsupported_dest_chain_raises(self):
        manager = _dev_manager()
        req = _make_request(dest_chain="invalid_chain")
        with pytest.raises(BridgeError, match="Unsupported destination chain"):
            manager.initiate_bridge(req)

    def test_same_chain_raises(self):
        manager = _dev_manager()
        req = _make_request(source_chain="polygon_amoy", dest_chain="polygon_amoy")
        with pytest.raises(BridgeError, match="must be different"):
            manager.initiate_bridge(req)

    def test_zero_amount_raises(self):
        manager = _dev_manager()
        req = _make_request(amount=0.0)
        with pytest.raises(BridgeError, match="must be positive"):
            manager.initiate_bridge(req)

    def test_negative_amount_raises(self):
        manager = _dev_manager()
        req = _make_request(amount=-50.0)
        with pytest.raises(BridgeError, match="must be positive"):
            manager.initiate_bridge(req)

    def test_missing_recipient_raises(self):
        manager = _dev_manager()
        req = _make_request(recipient="")
        with pytest.raises(BridgeError, match="Recipient"):
            manager.initiate_bridge(req)

    def test_missing_sender_raises(self):
        manager = _dev_manager()
        req = _make_request(sender="")
        with pytest.raises(BridgeError, match="Sender"):
            manager.initiate_bridge(req)


# ---------------------------------------------------------------------------
# MiCA compliance integration tests
# ---------------------------------------------------------------------------

class TestBridgeComplianceIntegration:
    def test_amount_over_mica_limit_raises(self):
        manager = _dev_manager()
        req = _make_request(amount=6000.0)  # > 5000 EUR limit
        with pytest.raises(BridgeError, match="MiCA single-tx limit"):
            manager.initiate_bridge(req)

    def test_compliance_engine_rejection_raises(self):
        mock_engine = MagicMock()
        mock_engine.check_transaction.return_value = MagicMock(
            approved=False, message="Velocity limit exceeded"
        )
        manager = _dev_manager(compliance_engine=mock_engine)
        req = _make_request(amount=100.0)
        with pytest.raises(BridgeError, match="Compliance check failed"):
            manager.initiate_bridge(req)

    def test_compliance_engine_approval_succeeds(self):
        mock_engine = MagicMock()
        mock_engine.check_transaction.return_value = MagicMock(
            approved=True, message="OK"
        )
        manager = _dev_manager(compliance_engine=mock_engine)
        req = _make_request(amount=100.0)
        result = manager.initiate_bridge(req)
        assert result.status == "completed"


# ---------------------------------------------------------------------------
# Dev mode simulation tests
# ---------------------------------------------------------------------------

class TestBridgeDevMode:
    def test_initiate_returns_bridge_result(self):
        manager = _dev_manager()
        result = manager.initiate_bridge(_make_request())
        assert isinstance(result, BridgeResult)

    def test_dev_mode_status_completed(self):
        manager = _dev_manager()
        result = manager.initiate_bridge(_make_request())
        assert result.status == "completed"

    def test_dev_mode_has_request_id(self):
        manager = _dev_manager()
        result = manager.initiate_bridge(_make_request())
        assert result.request_id
        assert len(result.request_id) > 0

    def test_dev_mode_has_tx_hashes(self):
        manager = _dev_manager()
        result = manager.initiate_bridge(_make_request())
        assert result.source_tx_hash.startswith("0x")
        assert result.dest_tx_hash.startswith("0x")

    def test_dev_mode_different_requests_different_ids(self):
        manager = _dev_manager()
        r1 = manager.initiate_bridge(_make_request(amount=50.0))
        r2 = manager.initiate_bridge(_make_request(amount=75.0))
        assert r1.request_id != r2.request_id

    def test_all_chain_combinations_work(self):
        manager = _dev_manager()
        chains = list(SUPPORTED_CHAINS.keys())
        for src in chains:
            for dst in chains:
                if src != dst:
                    req = _make_request(source_chain=src, dest_chain=dst)
                    result = manager.initiate_bridge(req)
                    assert result.status == "completed"


# ---------------------------------------------------------------------------
# Status checking tests
# ---------------------------------------------------------------------------

class TestBridgeStatusChecking:
    def test_check_status_returns_result(self):
        manager = _dev_manager()
        initiated = manager.initiate_bridge(_make_request())
        status = manager.check_bridge_status(initiated.request_id)
        assert status.request_id == initiated.request_id

    def test_check_status_unknown_id_raises(self):
        manager = _dev_manager()
        with pytest.raises(BridgeError, match="not found"):
            manager.check_bridge_status("nonexistent-id")

    def test_status_is_consistent_with_initiated(self):
        manager = _dev_manager()
        initiated = manager.initiate_bridge(_make_request())
        status = manager.check_bridge_status(initiated.request_id)
        assert status.status == initiated.status
        assert status.source_tx_hash == initiated.source_tx_hash
