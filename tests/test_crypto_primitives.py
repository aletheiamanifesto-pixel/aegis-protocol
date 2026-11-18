#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for crypto_primitives.py"""

import pytest
from crypto_primitives import (
    pedersen_commit,
    pedersen_verify,
    pedersen_commit_bytes,
    mimc_hash,
    mimc_hash_bytes,
    mimc_hash_int,
    MerkleTree,
    derive_viewing_key,
    encrypt_for_grantee,
    decrypt_from_owner,
    NoirCircuitInterface,
    CryptoError,
    FIELD_PRIME,
)


class TestPedersenCommitments:
    def test_commit_and_verify(self):
        value = 1000
        commitment, bf = pedersen_commit(value)
        assert pedersen_verify(value, bf, commitment)

    def test_wrong_value_fails(self):
        value = 1000
        commitment, bf = pedersen_commit(value)
        assert not pedersen_verify(999, bf, commitment)

    def test_wrong_blinding_fails(self):
        value = 1000
        commitment, bf = pedersen_commit(value)
        assert not pedersen_verify(value, bf + 1, commitment)

    def test_deterministic_with_fixed_blinding(self):
        value = 500
        bf = 12345
        c1, _ = pedersen_commit(value, bf)
        c2, _ = pedersen_commit(value, bf)
        assert c1 == c2

    def test_commit_bytes_returns_32_bytes(self):
        commitment_bytes, bf = pedersen_commit_bytes(100)
        assert len(commitment_bytes) == 32

    def test_zero_value(self):
        commitment, bf = pedersen_commit(0)
        assert pedersen_verify(0, bf, commitment)

    def test_commitment_in_field(self):
        value = 999999
        commitment, bf = pedersen_commit(value)
        assert 0 <= commitment < FIELD_PRIME


class TestMiMCHash:
    def test_basic_hash(self):
        result = mimc_hash(1, 2)
        assert isinstance(result, int)
        assert 0 <= result < FIELD_PRIME

    def test_deterministic(self):
        assert mimc_hash(42, 99) == mimc_hash(42, 99)

    def test_different_inputs_differ(self):
        assert mimc_hash(1, 2) != mimc_hash(2, 1)
        assert mimc_hash(1, 2) != mimc_hash(1, 3)

    def test_hash_bytes_empty(self):
        result = mimc_hash_bytes(b"")
        assert result == b"\x00" * 32

    def test_hash_bytes_nonempty(self):
        result = mimc_hash_bytes(b"hello world")
        assert len(result) == 32
        assert result != b"\x00" * 32

    def test_hash_bytes_deterministic(self):
        data = b"aegis protocol test"
        assert mimc_hash_bytes(data) == mimc_hash_bytes(data)

    def test_hash_int(self):
        result = mimc_hash_int(42)
        assert isinstance(result, int)
        assert 0 <= result < FIELD_PRIME


class TestMerkleTree:
    def test_empty_tree_root(self):
        tree = MerkleTree()
        assert tree.get_root() == b"\x00" * 32

    def test_insert_single_leaf(self):
        tree = MerkleTree()
        idx = tree.insert(b"leaf1")
        assert idx == 0
        assert len(tree) == 1

    def test_insert_multiple_leaves(self):
        tree = MerkleTree()
        for i in range(5):
            tree.insert(f"leaf{i}".encode())
        assert len(tree) == 5

    def test_root_changes_on_insert(self):
        tree = MerkleTree()
        root_empty = tree.get_root()
        tree.insert(b"leaf1")
        root_after = tree.get_root()
        assert root_empty != root_after

    def test_get_root_hex(self):
        tree = MerkleTree()
        tree.insert(b"data")
        root_hex = tree.get_root_hex()
        assert root_hex.startswith("0x")
        assert len(root_hex) == 66  # "0x" + 64 hex chars

    def test_proof_and_verify(self):
        tree = MerkleTree()
        data = b"secret transaction"
        idx = tree.insert(data)
        tree.insert(b"another leaf")

        proof = tree.get_proof(idx)
        assert tree.verify_proof(data, idx, proof)

    def test_invalid_proof_fails(self):
        tree = MerkleTree()
        idx = tree.insert(b"real data")
        proof = tree.get_proof(idx)
        assert not tree.verify_proof(b"wrong data", idx, proof)

    def test_out_of_range_proof_raises(self):
        tree = MerkleTree()
        tree.insert(b"leaf")
        with pytest.raises(CryptoError):
            tree.get_proof(99)


class TestViewingKeyDerivation:
    def test_derive_viewing_key(self):
        private_key_bytes = b"\x01" * 32
        viewing_private, viewing_public = derive_viewing_key(private_key_bytes)
        assert len(viewing_private) == 32
        assert len(viewing_public) == 32

    def test_deterministic_with_salt(self):
        pk = b"\x02" * 32
        salt = b"\x03" * 32
        vp1, vpub1 = derive_viewing_key(pk, salt)
        vp2, vpub2 = derive_viewing_key(pk, salt)
        assert vp1 == vp2
        assert vpub1 == vpub2

    def test_different_keys_differ(self):
        vp1, _ = derive_viewing_key(b"\x01" * 32)
        vp2, _ = derive_viewing_key(b"\x02" * 32)
        assert vp1 != vp2

    def test_encrypt_decrypt_roundtrip(self):
        private_key, public_key = derive_viewing_key(b"\x04" * 32)
        message = b"secret balance data"
        header, ciphertext = encrypt_for_grantee(message, public_key)
        decrypted = decrypt_from_owner(ciphertext, header, private_key)
        assert decrypted == message

    def test_public_key_alone_cannot_decrypt(self):
        """The old scheme derived the key from the public key: anyone could decrypt."""
        from crypto_primitives import CryptoError

        _, public_key = derive_viewing_key(b"\x06" * 32)
        other_private, _ = derive_viewing_key(b"\x07" * 32)
        header, ciphertext = encrypt_for_grantee(b"secret", public_key)
        with pytest.raises(CryptoError):
            decrypt_from_owner(ciphertext, header, public_key)
        with pytest.raises(CryptoError):
            decrypt_from_owner(ciphertext, header, other_private)

    def test_encrypt_changes_data(self):
        _, public_key = derive_viewing_key(b"\x05" * 32)
        message = b"plaintext"
        nonce, ciphertext = encrypt_for_grantee(message, public_key)
        assert ciphertext != message


class TestNoirCircuitInterface:
    def test_mock_proof_generation(self):
        interface = NoirCircuitInterface()
        proof = interface.generate_proof(
            "balance_proof",
            {"balance": 5000, "blinding": 12345},
            {"threshold": 1000, "commitment": "0xabc"},
        )
        assert proof.is_mock
        assert proof.circuit_name == "balance_proof"
        assert len(proof.proof_bytes) == 32

    def test_mock_proof_verification(self):
        interface = NoirCircuitInterface()
        proof = interface._mock_proof(
            "test_circuit",
            {"secret": 1},
            {"public": 2},
        )
        assert interface._verify_mock_proof(proof)

    def test_deterministic_mock_proof(self):
        interface = NoirCircuitInterface()
        p1 = interface._mock_proof("circuit", {"a": 1}, {"b": 2})
        p2 = interface._mock_proof("circuit", {"a": 1}, {"b": 2})
        assert p1.proof_bytes == p2.proof_bytes
