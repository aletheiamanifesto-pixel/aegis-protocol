#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tests/test_settlement.py - Tests for the OnChainSettler settlement package.
"""

import pytest
from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, patch

from settlement.config import SettlementConfig
from settlement.on_chain_settler import OnChainSettler, SettlementResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

@dataclass
class _FakeBundle:
    """Minimal TransactionBundle substitute for testing."""
    bundle_id: str
    merkle_root: str
    transactions: List[Dict[str, Any]]
    status: str = "pending"


def _make_bundle(
    bundle_id: str = "abc123" + "0" * 58,
    merkle_root: str = "0x" + "d" * 64,
    tx_count: int = 3,
) -> _FakeBundle:
    return _FakeBundle(
        bundle_id=bundle_id,
        merkle_root=merkle_root,
        transactions=[{"sender": f"0xA{i}", "amount": str(i)} for i in range(tx_count)],
    )


# ---------------------------------------------------------------------------
# Config tests
# ---------------------------------------------------------------------------

class TestSettlementConfig:
    def test_defaults(self):
        """Config reads from env or uses sensible defaults."""
        cfg = SettlementConfig()
        assert cfg.chain_id == 80002
        assert cfg.max_retries == 3
        assert cfg.confirmation_blocks == 2
        assert cfg.gas_multiplier == 1.2

    def test_custom_values(self):
        cfg = SettlementConfig(
            rpc_url="http://localhost:8545",
            private_key="0x" + "a" * 64,
            bundle_verifier_address="0x" + "b" * 40,
            chain_id=1337,
            max_retries=5,
            confirmation_blocks=3,
            gas_multiplier=1.5,
        )
        assert cfg.chain_id == 1337
        assert cfg.max_retries == 5
        assert cfg.gas_multiplier == 1.5


# ---------------------------------------------------------------------------
# Dev mode tests
# ---------------------------------------------------------------------------

class TestOnChainSettlerDevMode:
    def _settler(self) -> OnChainSettler:
        """Settler without a private key → dev mode."""
        cfg = SettlementConfig(private_key="", rpc_url="http://localhost:8545")
        return OnChainSettler(config=cfg)

    def test_dev_mode_flag_set(self):
        settler = self._settler()
        assert settler._dev_mode is True

    def test_settle_returns_dev_logged_status(self):
        settler = self._settler()
        bundle = _make_bundle()
        result = settler.settle(bundle)
        assert isinstance(result, SettlementResult)
        assert result.status == "dev_logged"
        assert result.bundle_id == bundle.bundle_id

    def test_settle_dev_mode_no_tx_hash(self):
        settler = self._settler()
        result = settler.settle(_make_bundle())
        assert result.tx_hash == ""
        assert result.block_number == 0
        assert result.gas_used == 0

    def test_settle_dev_mode_no_error(self):
        settler = self._settler()
        result = settler.settle(_make_bundle())
        assert result.error == ""

    def test_settle_different_bundles_preserve_bundle_id(self):
        settler = self._settler()
        b1 = _make_bundle(bundle_id="aaa" + "0" * 61)
        b2 = _make_bundle(bundle_id="bbb" + "0" * 61)
        r1 = settler.settle(b1)
        r2 = settler.settle(b2)
        assert r1.bundle_id != r2.bundle_id
        assert r1.bundle_id == b1.bundle_id
        assert r2.bundle_id == b2.bundle_id


# ---------------------------------------------------------------------------
# SettlementResult dataclass tests
# ---------------------------------------------------------------------------

class TestSettlementResult:
    def test_all_fields(self):
        r = SettlementResult(
            bundle_id="test123",
            tx_hash="0xabc",
            block_number=42,
            gas_used=21000,
            status="confirmed",
            error="",
        )
        assert r.bundle_id == "test123"
        assert r.tx_hash == "0xabc"
        assert r.block_number == 42
        assert r.gas_used == 21000
        assert r.status == "confirmed"
        assert r.error == ""

    def test_failed_result_carries_error(self):
        r = SettlementResult(
            bundle_id="x",
            tx_hash="",
            block_number=0,
            gas_used=0,
            status="failed",
            error="connection refused",
        )
        assert r.status == "failed"
        assert "connection refused" in r.error


# ---------------------------------------------------------------------------
# Retry logic tests
# ---------------------------------------------------------------------------

class TestOnChainSettlerRetry:
    def test_retry_exhausted_returns_failed(self):
        """When all retry attempts raise, status should be 'failed'."""
        cfg = SettlementConfig(
            private_key="0x" + "a" * 64,
            rpc_url="http://localhost:8545",
            bundle_verifier_address="0x" + "b" * 40,
            max_retries=2,
        )
        settler = OnChainSettler(config=cfg)
        # Patch _submit to always raise
        settler._submit = MagicMock(side_effect=RuntimeError("network error"))

        # Also patch time.sleep to avoid waiting
        with patch("settlement.on_chain_settler.time.sleep"):
            result = settler.settle(_make_bundle())

        assert result.status == "failed"
        assert "network error" in result.error
        assert settler._submit.call_count == cfg.max_retries

    def test_retry_succeeds_on_second_attempt(self):
        """Settler should return 'confirmed' if second attempt succeeds."""
        cfg = SettlementConfig(
            private_key="0x" + "a" * 64,
            rpc_url="http://localhost:8545",
            bundle_verifier_address="0x" + "b" * 40,
            max_retries=3,
        )
        settler = OnChainSettler(config=cfg)
        success_result = SettlementResult(
            bundle_id="test",
            tx_hash="0xdeadbeef",
            block_number=10,
            gas_used=50000,
            status="confirmed",
        )
        settler._submit = MagicMock(
            side_effect=[RuntimeError("first failure"), success_result]
        )

        with patch("settlement.on_chain_settler.time.sleep"):
            result = settler.settle(_make_bundle())

        assert result.status == "confirmed"
        assert result.tx_hash == "0xdeadbeef"
        assert settler._submit.call_count == 2
