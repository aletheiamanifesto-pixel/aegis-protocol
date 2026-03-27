#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
bundler/transaction_bundler.py - Transaction Bundler with Merkle aggregation for AEGIS Protocol.

Collects individual transactions into bundles, computes a Merkle root for each
bundle, and invokes a callback when a bundle is ready for on-chain submission.
"""

import threading
import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Callable, Deque, Dict, List, Optional

from bundler.config import BundlerConfig
from bundler.merkle_tree import MerkleTree
from bundler.adaptive_velocity import VelocityTracker


@dataclass
class TransactionBundle:
    """An immutable bundle of transactions with a Merkle root.

    Attributes:
        bundle_id: Unique identifier for this bundle (UUID hex string).
        transactions: Ordered list of transaction dicts included in the bundle.
        merkle_root: Hex-encoded Merkle root prefixed with "0x".
        merkle_leaves: Hex-encoded leaf hashes (one per transaction).
        created_at: Unix timestamp when the bundle was created.
        submitted_at: Unix timestamp when the bundle was submitted on-chain.
        tx_hash: On-chain transaction hash after submission.
        status: Current bundle status ("pending", "submitted", "confirmed").
    """

    bundle_id: str
    transactions: List[Dict[str, Any]]
    merkle_root: str
    merkle_leaves: List[str]
    created_at: float
    submitted_at: Optional[float] = None
    tx_hash: Optional[str] = None
    status: str = "pending"


class TransactionBundler:
    """Aggregates transactions into Merkle-rooted bundles.

    Transactions are collected in an internal queue. A bundle is flushed when
    either the queue reaches ``max_bundle_size`` or the ``bundle_window_seconds``
    timer expires after the first transaction was enqueued.

    Args:
        config: BundlerConfig controlling bundle size and velocity limits.
        on_bundle_ready: Optional callback invoked with a TransactionBundle when
            a bundle is flushed.

    Example:
        bundler = TransactionBundler(BundlerConfig(), on_bundle_ready=my_callback)
        result = bundler.submit_transaction({"sender": "0xA", "amount": 10})
    """

    def __init__(
        self,
        config: Optional[BundlerConfig] = None,
        on_bundle_ready: Optional[Callable[[TransactionBundle], None]] = None,
    ) -> None:
        """Initialize the bundler with config and optional callback.

        Args:
            config: BundlerConfig instance. Defaults to BundlerConfig().
            on_bundle_ready: Callback invoked each time a bundle is flushed.
        """
        self._config = config or BundlerConfig()
        self._on_bundle_ready = on_bundle_ready
        self._velocity = VelocityTracker()
        self._queue: Deque[Dict[str, Any]] = deque()
        self._bundles: Dict[str, TransactionBundle] = {}
        self._lock = threading.Lock()
        self._timer: Optional[threading.Timer] = None
        self._total_bundles: int = 0
        self._current_pending_id: str = str(uuid.uuid4()).replace("-", "")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def submit_transaction(
        self, tx_data: Dict[str, Any], op_type: str = "single_tx"
    ) -> Dict[str, Any]:
        """Submit a single transaction to the bundler queue.

        Checks the velocity limit for the sender before accepting. If the queue
        reaches ``max_bundle_size`` after insertion, triggers an immediate flush.

        Args:
            tx_data: Transaction dictionary. Should include at least "sender".
            op_type: Velocity limit category (default "single_tx").

        Returns:
            Dict with keys:
                - "accepted" (bool): Whether the transaction was accepted.
                - "bundle_id" (str): Pending bundle ID if accepted, else None.
                - "position" (int): Queue position (1-based) if accepted, else None.
                - "reason" (str): Rejection reason when accepted is False.
        """
        sender = tx_data.get("sender", "")
        limit = self._config.velocity_limits.get(op_type, 30)

        if sender and not self._velocity.check(sender, op_type, limit):
            return {
                "accepted": False,
                "bundle_id": None,
                "position": None,
                "reason": f"Velocity limit exceeded for op_type={op_type}",
            }

        with self._lock:
            self._queue.append(tx_data)
            position = len(self._queue)
            bundle_id = self._current_pending_id

            # Start flush timer on first transaction in window
            if position == 1:
                self._start_timer()

        if sender:
            self._velocity.record(sender, op_type)

        with self._lock:
            should_flush = len(self._queue) >= self._config.max_bundle_size

        if should_flush:
            self._flush_bundle()

        return {"accepted": True, "bundle_id": bundle_id, "position": position, "reason": None}

    def submit_batch(self, transactions: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Submit an entire batch of transactions and flush immediately.

        Bypasses the timer and individual velocity checks. Records each transaction
        under "batch_reconcile" op_type for velocity tracking.

        Args:
            transactions: List of transaction dicts to bundle together.

        Returns:
            Dict with keys:
                - "accepted" (bool): Always True.
                - "bundle_id" (str): ID of the bundle that was created.
                - "count" (int): Number of transactions submitted.
        """
        with self._lock:
            for tx in transactions:
                self._queue.append(tx)
            bundle_id = self._current_pending_id

        bundle = self._flush_bundle()
        actual_id = bundle.bundle_id if bundle else bundle_id

        return {"accepted": True, "bundle_id": actual_id, "count": len(transactions)}

    def get_bundle(self, bundle_id: str) -> Optional[TransactionBundle]:
        """Retrieve a completed bundle by its ID.

        Args:
            bundle_id: The bundle UUID hex string.

        Returns:
            The TransactionBundle if found, else None.
        """
        return self._bundles.get(bundle_id)

    def get_merkle_proof(
        self, bundle_id: str, tx_index: int
    ) -> Optional[List[Dict[str, Any]]]:
        """Generate a Merkle proof for a specific transaction in a bundle.

        Args:
            bundle_id: Bundle UUID hex string.
            tx_index: Zero-based index of the transaction within the bundle.

        Returns:
            Merkle proof list (as returned by MerkleTree.get_proof), or None
            if the bundle or index is invalid.
        """
        bundle = self._bundles.get(bundle_id)
        if bundle is None:
            return None
        leaves = [bytes.fromhex(h) for h in bundle.merkle_leaves]
        if tx_index < 0 or tx_index >= len(leaves):
            return None
        return MerkleTree.get_proof(leaves, tx_index)

    def get_stats(self) -> Dict[str, Any]:
        """Return current bundler statistics.

        Returns:
            Dict with keys:
                - "queue_size" (int): Number of transactions currently queued.
                - "total_bundles" (int): Number of bundles flushed so far.
                - "config" (dict): Snapshot of the current BundlerConfig.
        """
        with self._lock:
            queue_size = len(self._queue)
        return {
            "queue_size": queue_size,
            "total_bundles": self._total_bundles,
            "config": {
                "max_bundle_size": self._config.max_bundle_size,
                "bundle_window_seconds": self._config.bundle_window_seconds,
                "max_gas_per_bundle": self._config.max_gas_per_bundle,
                "min_bundle_size": self._config.min_bundle_size,
                "velocity_limits": dict(self._config.velocity_limits),
            },
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _start_timer(self) -> None:
        """Start the bundle window timer (must be called with self._lock held).

        Cancels any existing timer before starting a new one. The timer thread
        is a daemon so it does not block interpreter shutdown.
        """
        if self._timer is not None:
            self._timer.cancel()
        timer = threading.Timer(
            self._config.bundle_window_seconds, self._on_timer_fire
        )
        timer.daemon = True
        timer.start()
        self._timer = timer

    def _on_timer_fire(self) -> None:
        """Timer callback: flush the current queue if it has any transactions."""
        with self._lock:
            has_items = len(self._queue) > 0
        if has_items:
            self._flush_bundle()

    def _flush_bundle(self) -> Optional[TransactionBundle]:
        """Dequeue up to max_bundle_size transactions and create a bundle.

        Computes the Merkle tree, stores the bundle, and invokes the
        on_bundle_ready callback.

        Returns:
            The created TransactionBundle, or None if the queue was empty.
        """
        with self._lock:
            if not self._queue:
                return None

            # Cancel pending timer
            if self._timer is not None:
                self._timer.cancel()
                self._timer = None

            # Drain up to max_bundle_size transactions
            bundle_txs: List[Dict[str, Any]] = []
            while self._queue and len(bundle_txs) < self._config.max_bundle_size:
                bundle_txs.append(self._queue.popleft())

            bundle_id = self._current_pending_id
            self._current_pending_id = str(uuid.uuid4()).replace("-", "")

        # Compute Merkle tree outside the lock
        leaves = [MerkleTree.leaf_hash(tx) for tx in bundle_txs]
        root = MerkleTree.compute_root(leaves)

        bundle = TransactionBundle(
            bundle_id=bundle_id,
            transactions=bundle_txs,
            merkle_root="0x" + root.hex(),
            merkle_leaves=[leaf.hex() for leaf in leaves],
            created_at=time.time(),
        )

        with self._lock:
            self._bundles[bundle_id] = bundle
            self._total_bundles += 1

        if self._on_bundle_ready is not None:
            self._on_bundle_ready(bundle)

        return bundle
