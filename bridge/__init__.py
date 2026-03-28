#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
bridge/__init__.py - Public API for the AEGIS Protocol bridge package.
"""

from bridge.config import BridgeConfig, SUPPORTED_CHAINS
from bridge.bridge_manager import BridgeManager, BridgeRequest, BridgeResult, BridgeError

__all__ = [
    "BridgeManager",
    "BridgeRequest",
    "BridgeResult",
    "BridgeError",
    "BridgeConfig",
    "SUPPORTED_CHAINS",
]
