#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
oracle/chainlink_feed.py - Chainlink EUR/USD price feed integration for AEGIS Protocol.
"""

import logging
import time
from dataclasses import dataclass
from typing import Optional

from oracle.config import OracleConfig
from oracle.abi import AGGREGATOR_V3_ABI

logger = logging.getLogger(__name__)


@dataclass
class PriceData:
    """EUR/USD price snapshot from Chainlink.

    Attributes:
        price: EUR/USD exchange rate as a float (e.g. 1.08 means 1 EUR = 1.08 USD).
        decimals: Number of decimals used by the feed contract (typically 8).
        updated_at: Unix timestamp of the last on-chain price update.
        round_id: Chainlink round ID for this data point.
        is_stale: True when the price is older than max_staleness_seconds.
    """

    price: float
    decimals: int
    updated_at: int
    round_id: int
    is_stale: bool


class ChainlinkPriceFeed:
    """Reads EUR/USD price from a Chainlink AggregatorV3 contract on Polygon Amoy.

    Prices are cached for ``config.cache_ttl_seconds`` to reduce RPC load.
    In dev mode (or when the RPC is unreachable), a configurable default price
    is returned so the rest of the system keeps working without a live node.

    Args:
        config: OracleConfig instance.  Defaults to a config sourced from
                environment variables.

    Example:
        feed = ChainlinkPriceFeed()
        data = feed.get_eur_usd_price()
        print(data.price)  # e.g. 1.0823
    """

    def __init__(self, config: Optional[OracleConfig] = None) -> None:
        self._config = config or OracleConfig()
        self._cached_price: Optional[PriceData] = None
        self._cache_updated_at: float = 0.0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_eur_usd_price(self) -> PriceData:
        """Return the current EUR/USD price, using cache when still fresh.

        Returns:
            PriceData with the latest available price.  In dev mode, or when
            the RPC is unreachable, the configured ``default_price`` is returned.
        """
        if self._is_cache_valid():
            return self._cached_price  # type: ignore[return-value]

        if self._config.dev_mode:
            return self._dev_price()

        try:
            data = self._fetch_from_chain()
            self._cached_price = data
            self._cache_updated_at = time.monotonic()
            return data
        except Exception as exc:  # noqa: BLE001
            # A made-up price is worse than no price: only in development.
            from aegis_env import require_mocks

            logger.error("ChainlinkPriceFeed: failed to fetch price: %s", exc)
            require_mocks("EUR/USD price (oracle unreachable)")
            return self._dev_price()

    def invalidate_cache(self) -> None:
        """Force the next call to re-fetch from chain."""
        self._cached_price = None
        self._cache_updated_at = 0.0

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _is_cache_valid(self) -> bool:
        if self._cached_price is None:
            return False
        age = time.monotonic() - self._cache_updated_at
        return age < self._config.cache_ttl_seconds

    def _fetch_from_chain(self) -> PriceData:
        """Call latestRoundData and decimals on the Chainlink feed contract."""
        try:
            from web3 import Web3
        except ImportError as exc:
            raise RuntimeError("web3 package is required for Chainlink oracle") from exc

        w3 = Web3(Web3.HTTPProvider(self._config.rpc_url))
        if not w3.is_connected():
            raise RuntimeError(f"Cannot connect to RPC endpoint: {self._config.rpc_url}")

        contract = w3.eth.contract(
            address=Web3.to_checksum_address(self._config.feed_address),
            abi=AGGREGATOR_V3_ABI,
        )

        round_id, answer, _started_at, updated_at, _answered_in = (
            contract.functions.latestRoundData().call()
        )
        decimals: int = contract.functions.decimals().call()

        price = float(answer) / (10 ** decimals)
        now = int(time.time())
        is_stale = (now - updated_at) > self._config.max_staleness_seconds

        return PriceData(
            price=price,
            decimals=decimals,
            updated_at=updated_at,
            round_id=round_id,
            is_stale=is_stale,
        )

    def _dev_price(self) -> PriceData:
        """Return a synthetic price for dev / offline mode."""
        now = int(time.time())
        return PriceData(
            price=self._config.default_price,
            decimals=8,
            updated_at=now,
            round_id=0,
            is_stale=False,
        )
