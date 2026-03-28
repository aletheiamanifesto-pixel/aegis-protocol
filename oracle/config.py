#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
oracle/config.py - Configuration dataclass for Chainlink price feed integration.
"""

import os
from dataclasses import dataclass, field


@dataclass
class OracleConfig:
    """Configuration for ChainlinkPriceFeed.

    Attributes:
        feed_address: Chainlink AggregatorV3 contract address for EUR/USD on Polygon Amoy.
        rpc_url: JSON-RPC endpoint (default from RPC_URL env var).
        cache_ttl_seconds: How long to cache a price before re-fetching (default 60 s).
        max_staleness_seconds: Reject prices whose updatedAt is older than this (default 3600 s).
        dev_mode: When True, fall back to default_price instead of calling RPC.
        default_price: EUR/USD price returned in dev mode (default 1.08).
    """

    feed_address: str = field(
        default_factory=lambda: os.getenv(
            "EUR_USD_FEED_ADDRESS",
            "0x0000000000000000000000000000000000000000",
        )
    )
    rpc_url: str = field(
        default_factory=lambda: os.getenv("RPC_URL", "https://rpc-amoy.polygon.technology")
    )
    cache_ttl_seconds: int = 60
    max_staleness_seconds: int = 3600
    dev_mode: bool = field(
        default_factory=lambda: not bool(os.getenv("PRIVATE_KEY", ""))
    )
    default_price: float = 1.08
