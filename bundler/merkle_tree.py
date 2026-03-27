#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
bundler/merkle_tree.py - Merkle Tree implementation for AEGIS Protocol transaction bundling.

Provides leaf hashing, root computation, proof generation, and proof verification
using sha3_256 (keccak-like) for off-chain bundling logic.
"""

import hashlib
from typing import Any, Dict, List


class MerkleTree:
    """Merkle Tree with canonical ordering and sha3_256 hashing.

    Uses sha3_256 as a keccak-like function for off-chain transaction bundling.
    Canonical ordering: when hashing a pair, the smaller (bytes) node goes left.
    """

    @staticmethod
    def leaf_hash(tx_data: Dict[str, Any]) -> bytes:
        """Compute the leaf hash for a transaction.

        Args:
            tx_data: Dictionary with transaction fields. Expected keys:
                sender, recipient, amount, nonce, proof_hash.
                Missing keys default to empty string.

        Returns:
            32-byte sha3_256 hash of the canonical transaction string.
        """
        sender = tx_data.get("sender", "")
        recipient = tx_data.get("recipient", "")
        amount = tx_data.get("amount", "")
        nonce = tx_data.get("nonce", "")
        proof_hash = tx_data.get("proof_hash", "")
        canonical = f"{sender}:{recipient}:{amount}:{nonce}:{proof_hash}"
        return hashlib.sha3_256(canonical.encode()).digest()

    @staticmethod
    def _hash_pair(left: bytes, right: bytes) -> bytes:
        """Hash two nodes together with canonical ordering.

        Args:
            left: Left node bytes.
            right: Right node bytes.

        Returns:
            sha3_256 hash of min(left, right) + max(left, right).
        """
        if left > right:
            left, right = right, left
        return hashlib.sha3_256(left + right).digest()

    @staticmethod
    def compute_root(leaves: List[bytes]) -> bytes:
        """Compute the Merkle root for a list of leaf hashes.

        Pads the leaf list to the next power of 2 using b'\\x00' * 32.
        Uses canonical ordering (smaller bytes value goes left) when hashing pairs.

        Args:
            leaves: List of 32-byte leaf hashes.

        Returns:
            32-byte Merkle root.

        Raises:
            ValueError: If leaves list is empty.
        """
        if not leaves:
            raise ValueError("Cannot compute Merkle root of empty leaf list")

        if len(leaves) == 1:
            return leaves[0]

        # Pad to next power of 2
        n = len(leaves)
        size = 1
        while size < n:
            size <<= 1
        padded = list(leaves) + [b"\x00" * 32] * (size - n)

        layer = padded
        while len(layer) > 1:
            next_layer = []
            for i in range(0, len(layer), 2):
                next_layer.append(MerkleTree._hash_pair(layer[i], layer[i + 1]))
            layer = next_layer

        return layer[0]

    @staticmethod
    def get_proof(leaves: List[bytes], index: int) -> List[Dict[str, Any]]:
        """Generate a Merkle proof for the leaf at the given index.

        Args:
            leaves: List of 32-byte leaf hashes.
            index: Zero-based index of the leaf to prove.

        Returns:
            List of proof steps, each a dict with:
                - "sibling": hex string of the sibling node
                - "position": "left" if sibling is to the left, "right" if to the right

        Raises:
            ValueError: If leaves is empty or index is out of range.
        """
        if not leaves:
            raise ValueError("Cannot generate proof for empty leaf list")
        if index < 0 or index >= len(leaves):
            raise ValueError(f"Index {index} out of range for {len(leaves)} leaves")

        # Pad to next power of 2
        n = len(leaves)
        size = 1
        while size < n:
            size <<= 1
        padded = list(leaves) + [b"\x00" * 32] * (size - n)

        proof: List[Dict[str, Any]] = []
        layer = padded
        idx = index

        while len(layer) > 1:
            if idx % 2 == 0:
                sibling_idx = idx + 1
                position = "right"
            else:
                sibling_idx = idx - 1
                position = "left"

            sibling = layer[sibling_idx]
            proof.append({"sibling": sibling.hex(), "position": position})

            # Move to parent layer
            next_layer = []
            for i in range(0, len(layer), 2):
                next_layer.append(MerkleTree._hash_pair(layer[i], layer[i + 1]))
            layer = next_layer
            idx //= 2

        return proof

    @staticmethod
    def verify_proof(leaf: bytes, proof: List[Dict[str, Any]], root: bytes) -> bool:
        """Verify a Merkle proof for a given leaf and root.

        Args:
            leaf: 32-byte leaf hash to verify.
            proof: List of proof steps (as returned by get_proof).
            root: Expected 32-byte Merkle root.

        Returns:
            True if the proof is valid, False otherwise.
        """
        current = leaf
        for step in proof:
            sibling = bytes.fromhex(step["sibling"])
            current = MerkleTree._hash_pair(current, sibling)
        return current == root
