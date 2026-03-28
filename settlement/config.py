#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
settlement/config.py - Configuration dataclass for on-chain settlement.
"""

import os
from dataclasses import dataclass, field


@dataclass
class SettlementConfig:
    """Configuration for the OnChainSettler.

    Attributes:
        rpc_url: JSON-RPC endpoint for Polygon Amoy (default from RPC_URL env var).
        private_key: Signing key for submitting transactions (from PRIVATE_KEY env var).
        bundle_verifier_address: AegisBundleVerifier contract address on-chain.
        chain_id: EVM chain ID (default 80002 = Polygon Amoy).
        max_retries: Maximum retry attempts on transient failures (default 3).
        confirmation_blocks: Blocks to wait before considering a tx confirmed (default 2).
        gas_multiplier: Multiplier applied to estimated gas limit (default 1.2).
    """

    rpc_url: str = field(
        default_factory=lambda: os.getenv("RPC_URL", "https://rpc-amoy.polygon.technology")
    )
    private_key: str = field(
        default_factory=lambda: os.getenv("PRIVATE_KEY", "")
    )
    bundle_verifier_address: str = field(
        default_factory=lambda: os.getenv("BUNDLE_VERIFIER_ADDRESS", "")
    )
    chain_id: int = 80002
    max_retries: int = 3
    confirmation_blocks: int = 2
    gas_multiplier: float = 1.2
