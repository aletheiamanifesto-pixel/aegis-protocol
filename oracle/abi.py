#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
oracle/abi.py - Minimal Chainlink AggregatorV3Interface ABI for AEGIS Protocol.

Only the two functions required for price consumption are included:
  - latestRoundData(): returns round metadata and the current price
  - decimals(): returns the number of decimal places in the price
"""

AGGREGATOR_V3_ABI = [
    {
        "name": "latestRoundData",
        "type": "function",
        "inputs": [],
        "outputs": [
            {"name": "roundId", "type": "uint80"},
            {"name": "answer", "type": "int256"},
            {"name": "startedAt", "type": "uint256"},
            {"name": "updatedAt", "type": "uint256"},
            {"name": "answeredInRound", "type": "uint80"},
        ],
        "stateMutability": "view",
    },
    {
        "name": "decimals",
        "type": "function",
        "inputs": [],
        "outputs": [{"name": "", "type": "uint8"}],
        "stateMutability": "view",
    },
]
