#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
bundler/config.py - Configuration dataclass for the AEGIS Transaction Bundler.
"""

from dataclasses import dataclass, field
from typing import Dict


@dataclass
class BundlerConfig:
    """Configuration for the TransactionBundler.

    Attributes:
        max_bundle_size: Maximum number of transactions per bundle.
        bundle_window_seconds: Time window before a partial bundle is flushed.
        max_gas_per_bundle: Gas limit hint for on-chain bundle submission.
        min_bundle_size: Minimum transactions required to flush a bundle.
        velocity_limits: Per-operation-type velocity limits (events per 60 s).
    """

    max_bundle_size: int = 500
    bundle_window_seconds: float = 30.0
    max_gas_per_bundle: int = 3_000_000
    min_bundle_size: int = 1
    velocity_limits: Dict[str, int] = field(
        default_factory=lambda: {
            "single_tx": 30,
            "batch_reconcile": 500,
            "bundled": 5000,
            "api_relay": 100,
        }
    )
