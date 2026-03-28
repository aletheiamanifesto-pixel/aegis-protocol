#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
bridge/config.py - Configuration for the cross-chain bridge abstraction.
"""

import os
from dataclasses import dataclass, field
from typing import Dict


# Supported chains and their EVM chain IDs
SUPPORTED_CHAINS: Dict[str, int] = {
    "polygon_amoy": 80002,
    "ethereum_sepolia": 11155111,
    "base_sepolia": 84532,
}


@dataclass
class BridgeConfig:
    """Configuration for BridgeManager.

    Attributes:
        supported_chains: Mapping of chain name → chain ID.
        rpc_urls: Per-chain JSON-RPC endpoints (from env or defaults).
        contract_addresses: Per-chain bridge contract addresses.
        lock_timeout_seconds: How long to wait for a lock tx to confirm (default 300 s).
        dev_mode: When True, bridge operations are simulated without real RPC calls.
    """

    supported_chains: Dict[str, int] = field(default_factory=lambda: dict(SUPPORTED_CHAINS))
    rpc_urls: Dict[str, str] = field(
        default_factory=lambda: {
            "polygon_amoy": os.getenv("RPC_URL", "https://rpc-amoy.polygon.technology"),
            "ethereum_sepolia": os.getenv(
                "ETH_SEPOLIA_RPC_URL", "https://rpc.sepolia.org"
            ),
            "base_sepolia": os.getenv(
                "BASE_SEPOLIA_RPC_URL", "https://sepolia.base.org"
            ),
        }
    )
    contract_addresses: Dict[str, str] = field(
        default_factory=lambda: {
            "polygon_amoy": os.getenv("BRIDGE_CONTRACT_POLYGON", ""),
            "ethereum_sepolia": os.getenv("BRIDGE_CONTRACT_ETH_SEPOLIA", ""),
            "base_sepolia": os.getenv("BRIDGE_CONTRACT_BASE_SEPOLIA", ""),
        }
    )
    lock_timeout_seconds: int = 300
    dev_mode: bool = field(
        default_factory=lambda: not bool(os.getenv("PRIVATE_KEY", ""))
    )
