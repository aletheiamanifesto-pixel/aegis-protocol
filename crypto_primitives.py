#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
crypto_primitives.py - Cryptographic Primitives for AEGIS Protocol

Implements:
- Pedersen Commitment (hiding transaction amounts)
- MiMC Hashing (ZK-friendly hash function)
- Viewing Key derivation (selective disclosure)
- Merkle Tree with inclusion proofs
"""

import hashlib
import hmac
import os
from typing import List, Optional, Tuple


# ============================================================================
# CONSTANTS
# ============================================================================

# A large safe prime for Pedersen commitments (2048-bit NIST prime)
# In production, use a prime from a trusted setup ceremony.
PEDERSEN_PRIME = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF",
    16,
)

# Generators for Pedersen commitments (derived deterministically)
PEDERSEN_G = pow(2, 2, PEDERSEN_PRIME)
PEDERSEN_H = int(
    hashlib.sha256(b"aegis-pedersen-generator-h").hexdigest(), 16
) % PEDERSEN_PRIME
# Ensure H != 1 and H != G
if PEDERSEN_H < 2:
    PEDERSEN_H = PEDERSEN_H + 2

# MiMC constants
# secp256k1 field prime
MIMC_PRIME = (
    (1 << 256) - (1 << 32) - (1 << 9) - (1 << 8)
    - (1 << 7) - (1 << 6) - (1 << 4) - 1
)
MIMC_ROUNDS = 220
MIMC_ROUND_CONSTANTS: List[int] = []


def _init_mimc_round_constants() -> List[int]:
    """Derive MiMC round constants deterministically from a seed."""
    constants = []
    for i in range(MIMC_ROUNDS):
        seed = f"aegis-mimc-round-{i}".encode("utf-8")
        h = hashlib.sha256(seed).hexdigest()
        constants.append(int(h, 16) % MIMC_PRIME)
    return constants


MIMC_ROUND_CONSTANTS = _init_mimc_round_constants()


# ============================================================================
# PEDERSEN COMMITMENT
# ============================================================================

def generate_commitment(value: int, blinding_factor: int) -> str:
    """
    Generate a Pedersen commitment for a given value.

    C = g^value * h^blinding_factor mod p

    Args:
        value: The integer value to commit to (e.g. transaction amount in cents).
        blinding_factor: A random integer used to hide the value.

    Returns:
        Hex string of the commitment.
    """
    if not isinstance(value, int) or not isinstance(blinding_factor, int):
        raise TypeError("value and blinding_factor must be integers")
    if value < 0:
        raise ValueError("value must be non-negative")

    g_v = pow(PEDERSEN_G, value, PEDERSEN_PRIME)
    h_r = pow(PEDERSEN_H, blinding_factor, PEDERSEN_PRIME)
    commitment = (g_v * h_r) % PEDERSEN_PRIME
    return format(commitment, "x")


def verify_commitment(commitment_hex: str, value: int, blinding_factor: int) -> bool:
    """
    Verify a Pedersen commitment by recomputing it.

    Args:
        commitment_hex: The commitment as a hex string.
        value: The claimed value.
        blinding_factor: The blinding factor used during commitment.

    Returns:
        True if the commitment matches, False otherwise.
    """
    expected = generate_commitment(value, blinding_factor)
    return commitment_hex == expected


def generate_random_blinding_factor() -> int:
    """Generate a cryptographically secure random blinding factor."""
    return int.from_bytes(os.urandom(32), "big") % PEDERSEN_PRIME


def verify_commitment_sum(
    commitments: List[str],
    values: List[int],
    blinding_factors: List[int],
) -> bool:
    """
    Verify that the sum of committed values matches the sum commitment.

    The homomorphic property of Pedersen commitments means:
    C(v1, r1) * C(v2, r2) = C(v1+v2, r1+r2)

    Args:
        commitments: List of commitment hex strings.
        values: List of corresponding values.
        blinding_factors: List of corresponding blinding factors.

    Returns:
        True if the product of commitments equals the commitment
        of the sum of values/blinding factors.
    """
    if len(commitments) != len(values) or len(values) != len(blinding_factors):
        raise ValueError("All lists must have the same length")

    total_value = sum(values)
    total_blinding = sum(blinding_factors)
    sum_commitment = generate_commitment(total_value, total_blinding)

    product = 1
    for c_hex in commitments:
        product = (product * int(c_hex, 16)) % PEDERSEN_PRIME
    product_hex = format(product, "x")

    return product_hex == sum_commitment


# ============================================================================
# MiMC HASHING
# ============================================================================

def mimc_hash(left: int, right: int) -> str:
    """
    MiMC-based hash function (Feistel variant, ZK-friendly).

    Computes the MiMC permutation over the prime field.

    Args:
        left: First input as integer.
        right: Second input as integer (used as the key).

    Returns:
        Hex string of the hash output.
    """
    x = left % MIMC_PRIME
    k = right % MIMC_PRIME

    for i in range(MIMC_ROUNDS):
        t = (x + k + MIMC_ROUND_CONSTANTS[i]) % MIMC_PRIME
        x = pow(t, 3, MIMC_PRIME)

    result = (x + k) % MIMC_PRIME
    return format(result, "064x")


def mimc_hash_bytes(data: bytes) -> str:
    """
    Hash arbitrary bytes using MiMC by splitting into 31-byte chunks.

    Args:
        data: Arbitrary bytes to hash.

    Returns:
        Hex string of the hash.
    """
    # Split data into 31-byte chunks (to fit within the field)
    chunks = []
    for i in range(0, len(data), 31):
        chunk = data[i : i + 31]
        chunks.append(int.from_bytes(chunk, "big"))

    if not chunks:
        chunks = [0]

    # Hash using a sponge-like construction
    state = 0
    for chunk in chunks:
        state = int(mimc_hash(state, chunk), 16)

    return format(state, "064x")


# ============================================================================
# VIEWING KEY DERIVATION
# ============================================================================

def derive_viewing_key(private_key: bytes, transaction_id: str) -> str:
    """
    Derive a symmetric viewing key from the user's private key and a
    transaction ID. This enables selective disclosure of transaction metadata.

    Uses HMAC-SHA256 with domain separation.

    Args:
        private_key: The user's private key as bytes.
        transaction_id: The transaction identifier string.

    Returns:
        Hex string of the derived 256-bit viewing key.
    """
    if not isinstance(private_key, bytes) or len(private_key) == 0:
        raise ValueError("private_key must be non-empty bytes")
    if not isinstance(transaction_id, str) or len(transaction_id) == 0:
        raise ValueError("transaction_id must be a non-empty string")

    domain_tag = b"aegis-viewing-key-v1"
    message = domain_tag + b":" + transaction_id.encode("utf-8")
    vk = hmac.new(private_key, message, hashlib.sha256).digest()
    return vk.hex()


def encrypt_metadata(viewing_key_hex: str, plaintext: bytes) -> bytes:
    """
    Encrypt metadata using a viewing key (XOR stream cipher via SHA-256 CTR).

    WARNING: This is a simplified reference implementation for development and
    testing only. It does NOT provide authenticated encryption and MUST NOT be
    used in production. Replace with AES-256-GCM for any deployed system.

    Args:
        viewing_key_hex: The viewing key as hex string.
        plaintext: The data to encrypt.

    Returns:
        Encrypted bytes (nonce + ciphertext).
    """
    key = bytes.fromhex(viewing_key_hex)
    nonce = os.urandom(16)

    keystream = b""
    counter = 0
    while len(keystream) < len(plaintext):
        block_input = key + nonce + counter.to_bytes(4, "big")
        keystream += hashlib.sha256(block_input).digest()
        counter += 1

    ciphertext = bytes(a ^ b for a, b in zip(plaintext, keystream))
    return nonce + ciphertext


def decrypt_metadata(viewing_key_hex: str, encrypted: bytes) -> bytes:
    """
    Decrypt metadata using a viewing key.

    Args:
        viewing_key_hex: The viewing key as hex string.
        encrypted: The encrypted data (nonce + ciphertext).

    Returns:
        Decrypted plaintext bytes.
    """
    if len(encrypted) < 16:
        raise ValueError("Encrypted data too short")

    key = bytes.fromhex(viewing_key_hex)
    nonce = encrypted[:16]
    ciphertext = encrypted[16:]

    keystream = b""
    counter = 0
    while len(keystream) < len(ciphertext):
        block_input = key + nonce + counter.to_bytes(4, "big")
        keystream += hashlib.sha256(block_input).digest()
        counter += 1

    plaintext = bytes(a ^ b for a, b in zip(ciphertext, keystream))
    return plaintext


# ============================================================================
# MERKLE TREE
# ============================================================================

class AegisMerkleTree:
    """
    A Merkle tree for storing transaction hashes and generating
    inclusion proofs.

    Uses MiMC as the hash function (ZK-friendly) for internal nodes.
    Leaves are stored as integer representations of hex hashes.
    """

    def __init__(self, depth: int = 20):
        """
        Initialize the Merkle tree.

        Args:
            depth: Maximum depth of the tree (supports 2^depth leaves).
        """
        if depth < 1 or depth > 32:
            raise ValueError("depth must be between 1 and 32")
        self.depth = depth
        self.max_leaves = 1 << depth
        self.leaves: List[int] = []
        self._zero_values = self._compute_zero_values()

    def _compute_zero_values(self) -> List[int]:
        """Precompute the 'empty' hash at each level of the tree."""
        zeros = [0] * (self.depth + 1)
        zeros[0] = 0  # empty leaf
        for i in range(1, self.depth + 1):
            zeros[i] = int(mimc_hash(zeros[i - 1], zeros[i - 1]), 16)
        return zeros

    def insert(self, leaf_hex: str) -> int:
        """
        Insert a transaction hash into the tree.

        Args:
            leaf_hex: The transaction hash as a hex string.

        Returns:
            The index at which the leaf was inserted.
        """
        if len(self.leaves) >= self.max_leaves:
            raise OverflowError("Merkle tree is full")
        index = len(self.leaves)
        self.leaves.append(int(leaf_hex, 16))
        return index

    def get_root(self) -> str:
        """
        Compute and return the current Merkle root.

        Returns:
            Hex string of the Merkle root.
        """
        if not self.leaves:
            return format(self._zero_values[self.depth], "064x")

        current_level = list(self.leaves)

        for level in range(self.depth):
            next_level: List[int] = []
            level_size = len(current_level)
            zero_val = self._zero_values[level]

            i = 0
            while i < max(level_size, 1):
                left = current_level[i] if i < level_size else zero_val
                right = current_level[i + 1] if (i + 1) < level_size else zero_val
                parent = int(mimc_hash(left, right), 16)
                next_level.append(parent)
                i += 2

            current_level = next_level

        return format(current_level[0], "064x")

    def generate_proof(self, index: int) -> List[Tuple[str, str]]:
        """
        Generate an inclusion proof (Merkle path) for the leaf at the
        given index.

        Args:
            index: The index of the leaf to prove.

        Returns:
            A list of (sibling_hash_hex, direction) tuples where direction
            is 'left' or 'right', indicating which side the sibling is on.

        Raises:
            IndexError: If the index is out of range.
        """
        if index < 0 or index >= len(self.leaves):
            raise IndexError(f"Leaf index {index} out of range [0, {len(self.leaves)})")

        proof: List[Tuple[str, str]] = []
        current_level = list(self.leaves)

        for level in range(self.depth):
            level_size = len(current_level)
            zero_val = self._zero_values[level]

            # Determine sibling
            if index % 2 == 0:
                sibling = current_level[index + 1] if (index + 1) < level_size else zero_val
                proof.append((format(sibling, "064x"), "right"))
            else:
                sibling = current_level[index - 1] if (index - 1) >= 0 else zero_val
                proof.append((format(sibling, "064x"), "left"))

            # Move to next level
            next_level: List[int] = []
            i = 0
            while i < max(level_size, 1):
                left = current_level[i] if i < level_size else zero_val
                right = current_level[i + 1] if (i + 1) < level_size else zero_val
                parent = int(mimc_hash(left, right), 16)
                next_level.append(parent)
                i += 2

            index = index // 2
            current_level = next_level

        return proof

    @staticmethod
    def verify_proof(
        leaf_hex: str,
        proof: List[Tuple[str, str]],
        root_hex: str,
    ) -> bool:
        """
        Verify a Merkle inclusion proof.

        Args:
            leaf_hex: The leaf hash as a hex string.
            proof: The proof path as returned by generate_proof.
            root_hex: The expected Merkle root hex string.

        Returns:
            True if the proof is valid, False otherwise.
        """
        current = int(leaf_hex, 16)

        for sibling_hex, direction in proof:
            sibling = int(sibling_hex, 16)
            if direction == "right":
                current = int(mimc_hash(current, sibling), 16)
            else:
                current = int(mimc_hash(sibling, current), 16)

        return format(current, "064x") == root_hex


# ============================================================================
# UNIT TESTS
# ============================================================================

if __name__ == "__main__":
    import unittest

    class TestPedersenCommitment(unittest.TestCase):
        """Tests for Pedersen commitment functions."""

        def test_generate_commitment_returns_hex(self):
            c = generate_commitment(1000, 42)
            self.assertIsInstance(c, str)
            int(c, 16)  # Must be valid hex

        def test_verify_commitment_success(self):
            value, bf = 5000, 9999
            c = generate_commitment(value, bf)
            self.assertTrue(verify_commitment(c, value, bf))

        def test_verify_commitment_wrong_value(self):
            value, bf = 5000, 9999
            c = generate_commitment(value, bf)
            self.assertFalse(verify_commitment(c, value + 1, bf))

        def test_verify_commitment_wrong_blinding(self):
            value, bf = 5000, 9999
            c = generate_commitment(value, bf)
            self.assertFalse(verify_commitment(c, value, bf + 1))

        def test_different_values_produce_different_commitments(self):
            c1 = generate_commitment(100, 1)
            c2 = generate_commitment(200, 1)
            self.assertNotEqual(c1, c2)

        def test_different_blinding_factors_produce_different_commitments(self):
            c1 = generate_commitment(100, 1)
            c2 = generate_commitment(100, 2)
            self.assertNotEqual(c1, c2)

        def test_homomorphic_property(self):
            v1, r1 = 1000, 111
            v2, r2 = 2000, 222
            c1 = generate_commitment(v1, r1)
            c2 = generate_commitment(v2, r2)
            self.assertTrue(verify_commitment_sum([c1, c2], [v1, v2], [r1, r2]))

        def test_negative_value_raises(self):
            with self.assertRaises(ValueError):
                generate_commitment(-1, 42)

        def test_non_integer_raises(self):
            with self.assertRaises(TypeError):
                generate_commitment(1.5, 42)

        def test_zero_value_commitment(self):
            c = generate_commitment(0, 42)
            self.assertTrue(verify_commitment(c, 0, 42))

    class TestMiMCHash(unittest.TestCase):
        """Tests for MiMC hash functions."""

        def test_mimc_hash_returns_hex(self):
            h = mimc_hash(123, 456)
            self.assertIsInstance(h, str)
            self.assertEqual(len(h), 64)
            int(h, 16)

        def test_mimc_hash_deterministic(self):
            h1 = mimc_hash(100, 200)
            h2 = mimc_hash(100, 200)
            self.assertEqual(h1, h2)

        def test_mimc_hash_different_inputs(self):
            h1 = mimc_hash(100, 200)
            h2 = mimc_hash(100, 201)
            self.assertNotEqual(h1, h2)

        def test_mimc_hash_bytes(self):
            h = mimc_hash_bytes(b"hello aegis protocol")
            self.assertIsInstance(h, str)
            self.assertEqual(len(h), 64)

        def test_mimc_hash_bytes_deterministic(self):
            h1 = mimc_hash_bytes(b"test data")
            h2 = mimc_hash_bytes(b"test data")
            self.assertEqual(h1, h2)

        def test_mimc_hash_bytes_empty(self):
            h = mimc_hash_bytes(b"")
            self.assertIsInstance(h, str)
            self.assertEqual(len(h), 64)

    class TestViewingKey(unittest.TestCase):
        """Tests for viewing key derivation."""

        def test_derive_viewing_key_returns_hex(self):
            pk = os.urandom(32)
            vk = derive_viewing_key(pk, "tx-001")
            self.assertIsInstance(vk, str)
            self.assertEqual(len(vk), 64)  # 256-bit key = 64 hex chars

        def test_derive_viewing_key_deterministic(self):
            pk = b"\x01" * 32
            vk1 = derive_viewing_key(pk, "tx-001")
            vk2 = derive_viewing_key(pk, "tx-001")
            self.assertEqual(vk1, vk2)

        def test_different_tx_ids_produce_different_keys(self):
            pk = b"\x01" * 32
            vk1 = derive_viewing_key(pk, "tx-001")
            vk2 = derive_viewing_key(pk, "tx-002")
            self.assertNotEqual(vk1, vk2)

        def test_different_private_keys_produce_different_keys(self):
            vk1 = derive_viewing_key(b"\x01" * 32, "tx-001")
            vk2 = derive_viewing_key(b"\x02" * 32, "tx-001")
            self.assertNotEqual(vk1, vk2)

        def test_encrypt_decrypt_roundtrip(self):
            pk = os.urandom(32)
            vk = derive_viewing_key(pk, "tx-001")
            plaintext = b"Amount: 1500.50 EUR, Recipient: Alice"
            encrypted = encrypt_metadata(vk, plaintext)
            decrypted = decrypt_metadata(vk, encrypted)
            self.assertEqual(plaintext, decrypted)

        def test_wrong_key_fails_decryption(self):
            pk1 = os.urandom(32)
            pk2 = os.urandom(32)
            vk1 = derive_viewing_key(pk1, "tx-001")
            vk2 = derive_viewing_key(pk2, "tx-001")
            plaintext = b"secret data"
            encrypted = encrypt_metadata(vk1, plaintext)
            decrypted = decrypt_metadata(vk2, encrypted)
            self.assertNotEqual(plaintext, decrypted)

        def test_empty_private_key_raises(self):
            with self.assertRaises(ValueError):
                derive_viewing_key(b"", "tx-001")

        def test_empty_tx_id_raises(self):
            with self.assertRaises(ValueError):
                derive_viewing_key(b"\x01" * 32, "")

    class TestAegisMerkleTree(unittest.TestCase):
        """Tests for the Aegis Merkle tree."""

        def test_empty_tree_root(self):
            tree = AegisMerkleTree(depth=4)
            root = tree.get_root()
            self.assertIsInstance(root, str)
            self.assertEqual(len(root), 64)

        def test_insert_returns_index(self):
            tree = AegisMerkleTree(depth=4)
            idx = tree.insert("abcdef1234567890" * 4)
            self.assertEqual(idx, 0)
            idx2 = tree.insert("1234567890abcdef" * 4)
            self.assertEqual(idx2, 1)

        def test_root_changes_on_insert(self):
            tree = AegisMerkleTree(depth=4)
            root0 = tree.get_root()
            tree.insert("abcdef1234567890" * 4)
            root1 = tree.get_root()
            self.assertNotEqual(root0, root1)

        def test_generate_and_verify_proof(self):
            tree = AegisMerkleTree(depth=4)
            leaf = "abcdef1234567890" * 4
            idx = tree.insert(leaf)
            tree.insert("1111111111111111" * 4)
            tree.insert("2222222222222222" * 4)

            root = tree.get_root()
            proof = tree.generate_proof(idx)

            self.assertTrue(AegisMerkleTree.verify_proof(leaf, proof, root))

        def test_verify_proof_wrong_leaf_fails(self):
            tree = AegisMerkleTree(depth=4)
            leaf = "abcdef1234567890" * 4
            tree.insert(leaf)
            root = tree.get_root()
            proof = tree.generate_proof(0)

            wrong_leaf = "0000000000000000" * 4
            self.assertFalse(AegisMerkleTree.verify_proof(wrong_leaf, proof, root))

        def test_verify_proof_wrong_root_fails(self):
            tree = AegisMerkleTree(depth=4)
            leaf = "abcdef1234567890" * 4
            tree.insert(leaf)
            proof = tree.generate_proof(0)
            wrong_root = "ff" * 32
            self.assertFalse(AegisMerkleTree.verify_proof(leaf, proof, wrong_root))

        def test_proof_for_multiple_leaves(self):
            tree = AegisMerkleTree(depth=8)
            leaves = [format(i, "064x") for i in range(10)]
            for leaf in leaves:
                tree.insert(leaf)

            root = tree.get_root()

            for i, leaf in enumerate(leaves):
                proof = tree.generate_proof(i)
                self.assertTrue(
                    AegisMerkleTree.verify_proof(leaf, proof, root),
                    f"Proof verification failed for leaf at index {i}",
                )

        def test_out_of_range_index_raises(self):
            tree = AegisMerkleTree(depth=4)
            tree.insert("abcdef1234567890" * 4)
            with self.assertRaises(IndexError):
                tree.generate_proof(5)

        def test_tree_overflow_raises(self):
            tree = AegisMerkleTree(depth=2)  # 4 leaves max
            for i in range(4):
                tree.insert(format(i, "064x"))
            with self.assertRaises(OverflowError):
                tree.insert(format(99, "064x"))

    # Run all tests
    unittest.main(verbosity=2)
