#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tests/test_bundler.py - Tests for the AEGIS Protocol transaction bundler package.

Covers MerkleTree, VelocityTracker, TransactionBundler, and compliance engine
integration with the new adaptive velocity system.
"""

import time
import threading
from typing import Any, Dict, List
from unittest.mock import patch

import pytest

from bundler.merkle_tree import MerkleTree
from bundler.adaptive_velocity import VelocityTracker
from bundler.config import BundlerConfig
from bundler.transaction_bundler import TransactionBundle, TransactionBundler


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _make_tx(i: int) -> Dict[str, Any]:
    """Create a deterministic test transaction dict."""
    return {
        "sender": f"0xSender{i}",
        "recipient": f"0xRecipient{i}",
        "amount": str(i + 1),
        "nonce": str(i),
        "proof_hash": f"0xproof{i:064x}",
    }


# ─────────────────────────────────────────────────────────────────────────────
# MerkleTree tests
# ─────────────────────────────────────────────────────────────────────────────

class TestMerkleTree:
    def test_merkle_tree_single_leaf(self):
        """Single leaf: root equals the leaf hash itself."""
        tx = _make_tx(0)
        leaf = MerkleTree.leaf_hash(tx)
        root = MerkleTree.compute_root([leaf])
        assert root == leaf

    def test_merkle_tree_two_leaves(self):
        """Two leaves: root is sha3_256 of the canonically ordered pair."""
        import hashlib

        tx0 = _make_tx(0)
        tx1 = _make_tx(1)
        leaf0 = MerkleTree.leaf_hash(tx0)
        leaf1 = MerkleTree.leaf_hash(tx1)
        root = MerkleTree.compute_root([leaf0, leaf1])

        # Canonical order: smaller bytes first
        left, right = (leaf0, leaf1) if leaf0 <= leaf1 else (leaf1, leaf0)
        expected = hashlib.sha3_256(left + right).digest()
        assert root == expected

    def test_merkle_tree_500_leaves(self):
        """500 leaves: root is computed in under 1 second."""
        leaves = [MerkleTree.leaf_hash(_make_tx(i)) for i in range(500)]
        start = time.monotonic()
        root = MerkleTree.compute_root(leaves)
        elapsed = time.monotonic() - start
        assert isinstance(root, bytes)
        assert len(root) == 32
        assert elapsed < 1.0

    def test_merkle_proof_valid(self):
        """Proofs for leaves 0, 249, 499 verify correctly against the root."""
        leaves = [MerkleTree.leaf_hash(_make_tx(i)) for i in range(500)]
        root = MerkleTree.compute_root(leaves)

        for idx in (0, 249, 499):
            proof = MerkleTree.get_proof(leaves, idx)
            assert MerkleTree.verify_proof(leaves[idx], proof, root), (
                f"Proof for leaf {idx} failed to verify"
            )

    def test_merkle_proof_invalid(self):
        """A proof for leaf 0 does not verify if presented with leaf 1."""
        leaves = [MerkleTree.leaf_hash(_make_tx(i)) for i in range(10)]
        root = MerkleTree.compute_root(leaves)

        proof_for_0 = MerkleTree.get_proof(leaves, 0)
        # Verify leaf 1 against proof for leaf 0 → must be False
        assert not MerkleTree.verify_proof(leaves[1], proof_for_0, root)


# ─────────────────────────────────────────────────────────────────────────────
# VelocityTracker tests
# ─────────────────────────────────────────────────────────────────────────────

class TestVelocityTracker:
    def test_velocity_tracker_single_type(self):
        """30 records of type 'single_tx' → check returns False at the 31st."""
        tracker = VelocityTracker()
        address = "0xTestSingle"
        for _ in range(30):
            tracker.record(address, "single_tx")
        # After 30 events the tracker should be at the limit
        assert tracker.get_count(address, "single_tx") == 30
        assert not tracker.check(address, "single_tx", limit=30)

    def test_velocity_tracker_multi_type(self):
        """30 'single_tx' at limit, but 'batch_reconcile' for same address is still under."""
        tracker = VelocityTracker()
        address = "0xTestMulti"
        for _ in range(30):
            tracker.record(address, "single_tx")
        # single_tx is at limit
        assert not tracker.check(address, "single_tx", limit=30)
        # batch_reconcile is a different key → still under its limit (500)
        assert tracker.check(address, "batch_reconcile", limit=500)

    def test_velocity_tracker_expiry(self):
        """Records older than 60 seconds are evicted on next check."""
        tracker = VelocityTracker()
        address = "0xTestExpiry"

        # Inject a timestamp 61 seconds in the past directly into the deque
        key = f"{address}:single_tx"
        import collections
        tracker._store[key] = collections.deque([time.time() - 61])

        # After expiry, count should be 0 and check should pass
        assert tracker.get_count(address, "single_tx") == 0
        assert tracker.check(address, "single_tx", limit=30)

    def test_velocity_tracker_reset_all(self):
        """reset() with no argument clears all state."""
        tracker = VelocityTracker()
        tracker.record("0xA", "single_tx")
        tracker.record("0xB", "single_tx")
        tracker.reset()
        assert tracker.get_count("0xA", "single_tx") == 0
        assert tracker.get_count("0xB", "single_tx") == 0

    def test_velocity_tracker_reset_address(self):
        """reset(address) clears only that address."""
        tracker = VelocityTracker()
        tracker.record("0xA", "single_tx")
        tracker.record("0xB", "single_tx")
        tracker.reset("0xA")
        assert tracker.get_count("0xA", "single_tx") == 0
        assert tracker.get_count("0xB", "single_tx") == 1


# ─────────────────────────────────────────────────────────────────────────────
# TransactionBundler tests
# ─────────────────────────────────────────────────────────────────────────────

class TestTransactionBundler:
    def test_bundler_submit_single(self):
        """Submitting 1 transaction queues it but does not flush."""
        received: List[TransactionBundle] = []
        config = BundlerConfig(max_bundle_size=500, bundle_window_seconds=60.0)
        bundler = TransactionBundler(config, on_bundle_ready=received.append)

        result = bundler.submit_transaction(_make_tx(0))

        assert result["accepted"] is True
        assert result["bundle_id"] is not None
        assert result["position"] == 1
        assert len(received) == 0  # No flush yet
        stats = bundler.get_stats()
        assert stats["queue_size"] == 1
        assert stats["total_bundles"] == 0

    def test_bundler_submit_fills_bundle(self):
        """Submitting max_bundle_size transactions triggers an automatic flush."""
        received: List[TransactionBundle] = []
        config = BundlerConfig(max_bundle_size=10, bundle_window_seconds=60.0)
        bundler = TransactionBundler(config, on_bundle_ready=received.append)

        for i in range(10):
            bundler.submit_transaction(_make_tx(i))

        # Give the flush a moment to complete (it runs synchronously in submit)
        assert len(received) == 1
        bundle = received[0]
        assert bundle.merkle_root.startswith("0x")
        assert len(bundle.transactions) == 10
        assert len(bundle.merkle_leaves) == 10
        assert bundler.get_stats()["total_bundles"] == 1

    def test_bundler_batch_immediate_flush(self):
        """submit_batch() flushes immediately without waiting for the timer."""
        received: List[TransactionBundle] = []
        config = BundlerConfig(max_bundle_size=500, bundle_window_seconds=60.0)
        bundler = TransactionBundler(config, on_bundle_ready=received.append)

        txs = [_make_tx(i) for i in range(5)]
        result = bundler.submit_batch(txs)

        assert result["accepted"] is True
        assert result["count"] == 5
        assert len(received) == 1
        bundle = received[0]
        assert bundle.bundle_id == result["bundle_id"]
        assert len(bundle.transactions) == 5

    def test_bundler_stats(self):
        """get_stats() reports queue_size and total_bundles accurately."""
        received: List[TransactionBundle] = []
        config = BundlerConfig(max_bundle_size=5, bundle_window_seconds=60.0)
        bundler = TransactionBundler(config, on_bundle_ready=received.append)

        # Queue 3 transactions (no flush yet)
        for i in range(3):
            bundler.submit_transaction(_make_tx(i))

        stats = bundler.get_stats()
        assert stats["queue_size"] == 3
        assert stats["total_bundles"] == 0

        # Fill to trigger flush
        for i in range(3, 5):
            bundler.submit_transaction(_make_tx(i))

        stats = bundler.get_stats()
        assert stats["total_bundles"] == 1
        assert stats["queue_size"] == 0

    def test_bundler_get_bundle(self):
        """get_bundle() returns the bundle by ID after flush."""
        received: List[TransactionBundle] = []
        config = BundlerConfig(max_bundle_size=3, bundle_window_seconds=60.0)
        bundler = TransactionBundler(config, on_bundle_ready=received.append)

        for i in range(3):
            bundler.submit_transaction(_make_tx(i))

        assert len(received) == 1
        bundle_id = received[0].bundle_id
        fetched = bundler.get_bundle(bundle_id)
        assert fetched is not None
        assert fetched.bundle_id == bundle_id

    def test_bundler_get_merkle_proof(self):
        """get_merkle_proof() returns a valid proof for a flushed bundle."""
        received: List[TransactionBundle] = []
        config = BundlerConfig(max_bundle_size=4, bundle_window_seconds=60.0)
        bundler = TransactionBundler(config, on_bundle_ready=received.append)

        for i in range(4):
            bundler.submit_transaction(_make_tx(i))

        bundle = received[0]
        leaves = [bytes.fromhex(h) for h in bundle.merkle_leaves]
        root = bytes.fromhex(bundle.merkle_root[2:])  # strip "0x"

        for idx in range(4):
            proof = bundler.get_merkle_proof(bundle.bundle_id, idx)
            assert proof is not None
            assert MerkleTree.verify_proof(leaves[idx], proof, root)

    def test_bundler_velocity_rejection(self):
        """Transactions exceeding the velocity limit are rejected."""
        config = BundlerConfig(
            max_bundle_size=500,
            bundle_window_seconds=60.0,
            velocity_limits={"single_tx": 3},
        )
        bundler = TransactionBundler(config)
        sender = "0xVelocitySender"

        for i in range(3):
            r = bundler.submit_transaction({"sender": sender, "amount": str(i)})
            assert r["accepted"] is True

        blocked = bundler.submit_transaction({"sender": sender, "amount": "99"})
        assert blocked["accepted"] is False


# ─────────────────────────────────────────────────────────────────────────────
# ComplianceEngine integration tests
# ─────────────────────────────────────────────────────────────────────────────

class TestComplianceEngineAdaptiveVelocity:
    def test_compliance_engine_adaptive_velocity(self):
        """op_type='single_tx' blocks after 30; 'batch_reconcile' allows up to 500."""
        from compliance_engine import ComplianceEngine, _velocity_tracker

        engine = ComplianceEngine()
        sender = "0xAdaptiveVelocity_unique_sender_abc"
        _velocity_tracker.reset(sender)

        # single_tx: limit is 30
        for _ in range(30):
            r = engine.check_transaction(sender, 1.0, op_type="single_tx")
            assert r.approved

        blocked = engine.check_transaction(sender, 1.0, op_type="single_tx")
        assert not blocked.approved
        assert "VELOCITY_LIMIT_EXCEEDED" in blocked.flags

        # batch_reconcile for the same address: limit is 500
        for _ in range(5):
            r = engine.check_transaction(sender, 1.0, op_type="batch_reconcile")
            assert r.approved

    def test_compliance_engine_backward_compat(self):
        """check_transaction() without op_type works as before (defaults to 'single_tx')."""
        from compliance_engine import ComplianceEngine, _velocity_tracker

        engine = ComplianceEngine()
        sender = "0xBackCompatSender_unique_xyz"
        _velocity_tracker.reset(sender)

        # Should accept a basic transaction without op_type argument
        result = engine.check_transaction(sender, 50.0)
        assert result.approved
        assert result.risk_level == "low"

    def test_compliance_engine_op_type_in_message(self):
        """Velocity rejection message includes the op_type."""
        from compliance_engine import ComplianceEngine, _velocity_tracker
        from bundler.config import BundlerConfig

        engine = ComplianceEngine()
        sender = "0xOpTypeMsg_unique_sender_lmn"
        _velocity_tracker.reset(sender)
        limit = BundlerConfig().velocity_limits["single_tx"]

        for _ in range(limit):
            engine.check_transaction(sender, 1.0, op_type="single_tx")

        result = engine.check_transaction(sender, 1.0, op_type="single_tx")
        assert not result.approved
        assert "single_tx" in result.message
