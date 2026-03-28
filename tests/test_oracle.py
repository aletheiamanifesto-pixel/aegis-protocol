#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tests/test_oracle.py - Tests for the Chainlink EUR/USD price feed oracle.
"""

import time
import pytest
from unittest.mock import MagicMock, patch

from oracle.config import OracleConfig
from oracle.chainlink_feed import ChainlinkPriceFeed, PriceData
from oracle.abi import AGGREGATOR_V3_ABI


# ---------------------------------------------------------------------------
# Config tests
# ---------------------------------------------------------------------------

class TestOracleConfig:
    def test_defaults(self):
        cfg = OracleConfig()
        assert cfg.cache_ttl_seconds == 60
        assert cfg.max_staleness_seconds == 3600
        assert cfg.default_price == 1.08

    def test_custom_values(self):
        cfg = OracleConfig(
            feed_address="0x" + "c" * 40,
            rpc_url="http://localhost:8545",
            cache_ttl_seconds=30,
            max_staleness_seconds=7200,
            dev_mode=True,
            default_price=1.10,
        )
        assert cfg.cache_ttl_seconds == 30
        assert cfg.default_price == 1.10


# ---------------------------------------------------------------------------
# ABI tests
# ---------------------------------------------------------------------------

class TestChainlinkABI:
    def test_abi_has_latest_round_data(self):
        names = [entry["name"] for entry in AGGREGATOR_V3_ABI]
        assert "latestRoundData" in names

    def test_abi_has_decimals(self):
        names = [entry["name"] for entry in AGGREGATOR_V3_ABI]
        assert "decimals" in names

    def test_latest_round_data_output_count(self):
        entry = next(e for e in AGGREGATOR_V3_ABI if e["name"] == "latestRoundData")
        assert len(entry["outputs"]) == 5


# ---------------------------------------------------------------------------
# Dev mode tests
# ---------------------------------------------------------------------------

class TestChainlinkPriceFeedDevMode:
    def _feed(self, default_price: float = 1.08) -> ChainlinkPriceFeed:
        cfg = OracleConfig(dev_mode=True, default_price=default_price)
        return ChainlinkPriceFeed(config=cfg)

    def test_returns_price_data(self):
        data = self._feed().get_eur_usd_price()
        assert isinstance(data, PriceData)

    def test_default_price_returned(self):
        data = self._feed(default_price=1.09).get_eur_usd_price()
        assert data.price == pytest.approx(1.09)

    def test_not_stale_in_dev_mode(self):
        data = self._feed().get_eur_usd_price()
        assert data.is_stale is False

    def test_round_id_zero_in_dev_mode(self):
        data = self._feed().get_eur_usd_price()
        assert data.round_id == 0

    def test_updated_at_is_recent(self):
        data = self._feed().get_eur_usd_price()
        assert abs(data.updated_at - int(time.time())) < 5


# ---------------------------------------------------------------------------
# Cache tests
# ---------------------------------------------------------------------------

class TestPriceFeedCache:
    def _feed_with_mock_fetch(self, price: float = 1.08) -> ChainlinkPriceFeed:
        cfg = OracleConfig(dev_mode=False, cache_ttl_seconds=60)
        feed = ChainlinkPriceFeed(config=cfg)
        feed._fetch_from_chain = MagicMock(
            return_value=PriceData(
                price=price,
                decimals=8,
                updated_at=int(time.time()),
                round_id=42,
                is_stale=False,
            )
        )
        return feed

    def test_first_call_fetches_from_chain(self):
        feed = self._feed_with_mock_fetch()
        feed.get_eur_usd_price()
        feed._fetch_from_chain.assert_called_once()

    def test_second_call_uses_cache(self):
        feed = self._feed_with_mock_fetch()
        feed.get_eur_usd_price()
        feed.get_eur_usd_price()
        # Should only call fetch once due to cache
        feed._fetch_from_chain.assert_called_once()

    def test_cache_invalidation_triggers_refetch(self):
        feed = self._feed_with_mock_fetch()
        feed.get_eur_usd_price()
        feed.invalidate_cache()
        feed.get_eur_usd_price()
        assert feed._fetch_from_chain.call_count == 2

    def test_expired_cache_refetches(self):
        cfg = OracleConfig(dev_mode=False, cache_ttl_seconds=0)
        feed = ChainlinkPriceFeed(config=cfg)
        feed._fetch_from_chain = MagicMock(
            return_value=PriceData(
                price=1.08, decimals=8, updated_at=int(time.time()), round_id=1, is_stale=False
            )
        )
        feed.get_eur_usd_price()
        feed.get_eur_usd_price()
        # TTL=0 means cache is always expired
        assert feed._fetch_from_chain.call_count == 2


# ---------------------------------------------------------------------------
# Staleness tests
# ---------------------------------------------------------------------------

class TestPriceStaleness:
    def test_stale_price_detected(self):
        cfg = OracleConfig(dev_mode=False, max_staleness_seconds=3600, cache_ttl_seconds=0)
        feed = ChainlinkPriceFeed(config=cfg)
        old_timestamp = int(time.time()) - 7200  # 2 hours ago
        feed._fetch_from_chain = MagicMock(
            return_value=PriceData(
                price=1.05,
                decimals=8,
                updated_at=old_timestamp,
                round_id=10,
                is_stale=True,
            )
        )
        data = feed.get_eur_usd_price()
        assert data.is_stale is True

    def test_fresh_price_not_stale(self):
        cfg = OracleConfig(dev_mode=False, max_staleness_seconds=3600, cache_ttl_seconds=0)
        feed = ChainlinkPriceFeed(config=cfg)
        feed._fetch_from_chain = MagicMock(
            return_value=PriceData(
                price=1.08,
                decimals=8,
                updated_at=int(time.time()),
                round_id=11,
                is_stale=False,
            )
        )
        data = feed.get_eur_usd_price()
        assert data.is_stale is False


# ---------------------------------------------------------------------------
# Fallback tests
# ---------------------------------------------------------------------------

class TestPriceFeedFallback:
    def test_fallback_on_rpc_error(self):
        """When RPC call fails, dev fallback price is returned."""
        cfg = OracleConfig(dev_mode=False, default_price=1.07, cache_ttl_seconds=0)
        feed = ChainlinkPriceFeed(config=cfg)
        feed._fetch_from_chain = MagicMock(side_effect=RuntimeError("connection refused"))
        data = feed.get_eur_usd_price()
        assert data.price == pytest.approx(1.07)
