#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
oracle/__init__.py - Public API for the AEGIS Protocol oracle package.
"""

from oracle.abi import AGGREGATOR_V3_ABI
from oracle.config import OracleConfig
from oracle.chainlink_feed import ChainlinkPriceFeed, PriceData

__all__ = [
    "ChainlinkPriceFeed",
    "OracleConfig",
    "PriceData",
    "AGGREGATOR_V3_ABI",
]
