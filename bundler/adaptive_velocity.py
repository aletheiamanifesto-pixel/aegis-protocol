#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
bundler/adaptive_velocity.py - Adaptive velocity tracking for AEGIS Protocol.

Replaces the fixed MAX_TX_PER_MINUTE limit with a per-operation-type
velocity tracker using collections.deque for O(1) cleanup.
"""

import time
from collections import deque
from typing import Deque, Dict, Optional


class VelocityTracker:
    """Per-address, per-operation-type velocity tracker with O(1) cleanup.

    Uses a deque per (address, op_type) key so that expired timestamps are
    efficiently dropped from the left end rather than rebuilt on every access.

    Example:
        tracker = VelocityTracker()
        tracker.record("0xAlice", "single_tx")
        ok = tracker.check("0xAlice", "single_tx", limit=30)
    """

    _WINDOW_SECONDS: float = 60.0

    def __init__(self) -> None:
        """Initialize an empty velocity store."""
        self._store: Dict[str, Deque[float]] = {}

    def _key(self, address: str, op_type: str) -> str:
        """Build the store key for an address and operation type.

        Args:
            address: Wallet or sender address.
            op_type: Operation type string (e.g. "single_tx").

        Returns:
            Composite key string.
        """
        return f"{address}:{op_type}"

    def _evict_expired(self, dq: Deque[float]) -> None:
        """Remove timestamps older than the velocity window from the left.

        Args:
            dq: Deque of timestamps to clean up in-place.
        """
        cutoff = time.time() - self._WINDOW_SECONDS
        while dq and dq[0] < cutoff:
            dq.popleft()

    def record(self, address: str, op_type: str = "single_tx") -> int:
        """Record a transaction event and return the count in the last minute.

        Args:
            address: Sender or wallet address.
            op_type: Operation type (default "single_tx").

        Returns:
            Number of recorded events for this key in the last 60 seconds
            (including the one just recorded).
        """
        key = self._key(address, op_type)
        if key not in self._store:
            self._store[key] = deque()
        dq = self._store[key]
        self._evict_expired(dq)
        dq.append(time.time())
        return len(dq)

    def check(self, address: str, op_type: str, limit: int) -> bool:
        """Check whether a new event would be within the velocity limit.

        Does not record an event. Call record() separately after approval.

        Args:
            address: Sender or wallet address.
            op_type: Operation type to check.
            limit: Maximum number of events allowed per 60-second window.

        Returns:
            True if the current count is strictly below the limit (i.e. a new
            event would not exceed it), False otherwise.
        """
        key = self._key(address, op_type)
        dq = self._store.get(key)
        if dq is None:
            return True
        self._evict_expired(dq)
        return len(dq) < limit

    def get_count(self, address: str, op_type: str) -> int:
        """Return the current event count for an address/op_type in the last minute.

        Args:
            address: Sender or wallet address.
            op_type: Operation type.

        Returns:
            Number of events recorded in the last 60 seconds.
        """
        key = self._key(address, op_type)
        dq = self._store.get(key)
        if dq is None:
            return 0
        self._evict_expired(dq)
        return len(dq)

    def reset(self, address: Optional[str] = None) -> None:
        """Reset velocity state for testing purposes.

        Args:
            address: If provided, removes all op_type entries for this address.
                If None, clears the entire store.
        """
        if address is None:
            self._store.clear()
        else:
            keys_to_delete = [k for k in self._store if k.startswith(f"{address}:")]
            for k in keys_to_delete:
                del self._store[k]
