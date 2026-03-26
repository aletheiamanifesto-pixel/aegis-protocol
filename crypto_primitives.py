#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
crypto_primitives.py - Cryptographic primitives for AEGIS Protocol ZK system.

Implements:
- Pedersen Commitments (over secp256k1-like field, simplified)
- MiMC Hash (ZK-friendly hash function)
- Merkle Tree (for private transaction aggregation)
- Viewing Key Derivation (ECDH-based selective disclosure)
- Noir Circuit Interface (bridge to Noir proof system)
"""

import hashlib
import hmac
import json
import os
import struct
from dataclasses import dataclass, field
from typing import List, Optional, Tuple, Dict, Any


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Field prime (BN254 scalar field order, used in Noir/Groth16)
FIELD_PRIME = 0x30644e72e131a029b85045b68181585d2833e84879b9709142e1f988d8906901
PEDERSEN_G = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
PEDERSEN_H = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
MIMC_ROUNDS = 220
MIMC_SEED = b"mimc"


class CryptoError(Exception):
    pass


# ---------------------------------------------------------------------------
# Pedersen Commitments
# ---------------------------------------------------------------------------

def _field_mod(x: int) -> int:
    return x % FIELD_PRIME


def pedersen_commit(value: int, blinding_factor: Optional[int] = None) -> Tuple[int, int]:
    """
    Compute a Pedersen commitment: C = v*G + r*H (mod FIELD_PRIME).

    Args:
        value: The secret value to commit to.
        blinding_factor: Random blinding factor. Generated if not provided.

    Returns:
        (commitment, blinding_factor) tuple.
    """
    if blinding_factor is None:
        blinding_factor = int.from_bytes(os.urandom(32), "big") % FIELD_PRIME

    commitment = _field_mod(
        _field_mod(value * PEDERSEN_G) + _field_mod(blinding_factor * PEDERSEN_H)
    )
    return commitment, blinding_factor


def pedersen_verify(value: int, blinding_factor: int, commitment: int) -> bool:
    """Verify that commitment = v*G + r*H."""
    expected, _ = pedersen_commit(value, blinding_factor)
    return expected == commitment


def pedersen_commit_bytes(value: int, blinding_factor: Optional[int] = None) -> Tuple[bytes, int]:
    """Return commitment as 32-byte big-endian bytes."""
    commitment, bf = pedersen_commit(value, blinding_factor)
    return commitment.to_bytes(32, "big"), bf


# ---------------------------------------------------------------------------
# MiMC Hash
# ---------------------------------------------------------------------------

def _mimc_round_constants() -> List[int]:
    """Generate MiMC round constants deterministically from seed."""
    constants = []
    for i in range(MIMC_ROUNDS):
        h = hashlib.sha256(MIMC_SEED + i.to_bytes(4, "big")).digest()
        constants.append(int.from_bytes(h, "big") % FIELD_PRIME)
    return constants


_MIMC_CONSTANTS: List[int] = _mimc_round_constants()


def mimc_hash(left: int, right: int) -> int:
    """
    MiMC hash function (ZK-friendly).

    Args:
        left: Left input (field element).
        right: Right input (field element).

    Returns:
        Hash output as field element.
    """
    xl = _field_mod(left)
    xr = _field_mod(right)

    for i in range(MIMC_ROUNDS):
        t = _field_mod(xl + _MIMC_CONSTANTS[i] + xr)
        t_cubed = _field_mod(t * t * t)
        xl, xr = t_cubed, xl

    return _field_mod(xl + xr)


def mimc_hash_bytes(data: bytes) -> bytes:
    """Hash arbitrary bytes using MiMC, returns 32 bytes."""
    if not data:
        return b"\x00" * 32

    chunks = [data[i:i+32] for i in range(0, len(data), 32)]
    state = 0
    for chunk in chunks:
        padded = chunk.ljust(32, b"\x00")
        val = int.from_bytes(padded, "big") % FIELD_PRIME
        state = mimc_hash(state, val)

    return state.to_bytes(32, "big")


def mimc_hash_int(value: int) -> int:
    """Hash a single integer."""
    return mimc_hash(value % FIELD_PRIME, 0)


# ---------------------------------------------------------------------------
# Merkle Tree
# ---------------------------------------------------------------------------

def _merkle_hash(left: bytes, right: bytes) -> bytes:
    """Hash two Merkle nodes together."""
    combined = left + right
    return mimc_hash_bytes(combined)


@dataclass
class MerkleTree:
    """
    Append-only Merkle tree using MiMC hash for ZK compatibility.
    """
    depth: int = 32
    _leaves: List[bytes] = field(default_factory=list)
    _nodes: Dict[Tuple[int, int], bytes] = field(default_factory=dict)

    _ZERO_VALUE = b"\x00" * 32

    def insert(self, leaf_data: bytes) -> int:
        """
        Insert a leaf and return its index.

        Args:
            leaf_data: Raw data for the leaf (will be hashed with MiMC).

        Returns:
            Leaf index.
        """
        leaf_hash = mimc_hash_bytes(leaf_data)
        index = len(self._leaves)
        self._leaves.append(leaf_hash)
        self._update_path(index)
        return index

    def _update_path(self, index: int) -> None:
        """Update all nodes on the path from leaf to root."""
        level = 0
        idx = index
        node = self._leaves[idx]
        self._nodes[(level, idx)] = node

        while level < self.depth:
            sibling_idx = idx ^ 1
            sibling = self._nodes.get((level, sibling_idx), self._ZERO_VALUE)
            if idx % 2 == 0:
                parent = _merkle_hash(node, sibling)
            else:
                parent = _merkle_hash(sibling, node)
            level += 1
            idx //= 2
            self._nodes[(level, idx)] = parent
            node = parent

    def get_root(self) -> bytes:
        """Return current Merkle root."""
        if not self._leaves:
            return self._ZERO_VALUE
        top_level = max(lvl for lvl, _ in self._nodes.keys()) if self._nodes else 0
        return self._nodes.get((top_level, 0), self._ZERO_VALUE)

    def get_root_hex(self) -> str:
        """Return root as hex string."""
        return "0x" + self.get_root().hex()

    def get_proof(self, index: int) -> List[Tuple[bytes, str]]:
        """
        Generate a Merkle inclusion proof for the leaf at index.

        Returns:
            List of (sibling_hash, direction) tuples. Direction: 'left' or 'right'.
        """
        if index >= len(self._leaves):
            raise CryptoError(f"Leaf index {index} out of range")

        proof = []
        idx = index
        for level in range(self.depth):
            sibling_idx = idx ^ 1
            sibling = self._nodes.get((level, sibling_idx), self._ZERO_VALUE)
            direction = "right" if idx % 2 == 0 else "left"
            proof.append((sibling, direction))
            idx //= 2

        return proof

    def verify_proof(self, leaf_data: bytes, index: int, proof: List[Tuple[bytes, str]]) -> bool:
        """
        Verify a Merkle inclusion proof.

        Args:
            leaf_data: Original leaf data.
            index: Leaf index.
            proof: List of (sibling_hash, direction) tuples.

        Returns:
            True if proof is valid.
        """
        current = mimc_hash_bytes(leaf_data)
        for sibling, direction in proof:
            if direction == "right":
                current = _merkle_hash(current, sibling)
            else:
                current = _merkle_hash(sibling, current)

        return current == self.get_root()

    def __len__(self) -> int:
        return len(self._leaves)


# ---------------------------------------------------------------------------
# Viewing Key Derivation (ECDH-based)
# ---------------------------------------------------------------------------

def derive_viewing_key(wallet_private_key_bytes: bytes, salt: Optional[bytes] = None) -> Tuple[bytes, bytes]:
    """
    Derive a viewing key pair from a wallet private key.

    Uses HKDF-SHA256 to derive a deterministic key pair for selective disclosure.

    Args:
        wallet_private_key_bytes: Raw private key bytes (32 bytes).
        salt: Optional salt for HKDF. Generated randomly if not provided.

    Returns:
        (viewing_private_key, viewing_public_key) as bytes.
    """
    if salt is None:
        salt = os.urandom(32)

    prk = hmac.new(salt, wallet_private_key_bytes, hashlib.sha256).digest()

    info = b"aegis-viewing-key-v1"
    viewing_private = hmac.new(prk, info + b"\x01", hashlib.sha256).digest()
    viewing_public = hashlib.sha256(b"pub:" + viewing_private).digest()

    return viewing_private, viewing_public


def encrypt_for_grantee(data: bytes, grantee_public_key: bytes) -> Tuple[bytes, bytes]:
    """
    Encrypt data for a grantee using their public key (ECDH-like).

    Args:
        data: Data to encrypt.
        grantee_public_key: Grantee's public key bytes.

    Returns:
        (nonce, ciphertext) tuple.
    """
    nonce = os.urandom(12)
    shared_secret = hmac.new(grantee_public_key, nonce, hashlib.sha256).digest()

    key_stream = b""
    counter = 0
    while len(key_stream) < len(data):
        block = hashlib.sha256(shared_secret + counter.to_bytes(4, "big")).digest()
        key_stream += block
        counter += 1

    ciphertext = bytes(a ^ b for a, b in zip(data, key_stream[:len(data)]))
    return nonce, ciphertext


def decrypt_from_owner(ciphertext: bytes, nonce: bytes, grantee_public_key: bytes) -> bytes:
    """Decrypt data encrypted with encrypt_for_grantee."""
    shared_secret = hmac.new(grantee_public_key, nonce, hashlib.sha256).digest()

    key_stream = b""
    counter = 0
    while len(key_stream) < len(ciphertext):
        block = hashlib.sha256(shared_secret + counter.to_bytes(4, "big")).digest()
        key_stream += block
        counter += 1

    return bytes(a ^ b for a, b in zip(ciphertext, key_stream[:len(ciphertext)]))


# ---------------------------------------------------------------------------
# Noir Circuit Interface
# ---------------------------------------------------------------------------

@dataclass
class NoirProof:
    """Represents a ZK proof generated by a Noir circuit."""
    proof_bytes: bytes
    public_inputs: Dict[str, Any]
    circuit_name: str
    generated_at: int
    is_mock: bool = False


class NoirCircuitInterface:
    """
    Bridge between Python and Noir proof system.

    Falls back to mock proofs when Noir is not installed (development mode).
    """

    def __init__(self, circuits_dir: str = "./noir_circuits"):
        self.circuits_dir = circuits_dir
        self._noir_available = self._check_noir()

    def _check_noir(self) -> bool:
        """Check if Noir (nargo) is installed."""
        import subprocess
        try:
            result = subprocess.run(
                ["nargo", "--version"], capture_output=True, timeout=5
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def compile_circuit(self, circuit_name: str) -> bool:
        """Compile a Noir circuit."""
        import subprocess
        circuit_path = f"{self.circuits_dir}/{circuit_name}"
        if not self._noir_available:
            return True  # Mock success

        result = subprocess.run(
            ["nargo", "compile"],
            cwd=circuit_path,
            capture_output=True,
            timeout=60,
        )
        return result.returncode == 0

    def generate_proof(
        self,
        circuit_name: str,
        private_inputs: Dict[str, Any],
        public_inputs: Dict[str, Any],
    ) -> NoirProof:
        """
        Generate a ZK proof using a Noir circuit.

        Falls back to deterministic mock proof in development.
        """
        import time

        if not self._noir_available:
            return self._mock_proof(circuit_name, private_inputs, public_inputs)

        import json
        import subprocess
        import tempfile

        circuit_path = f"{self.circuits_dir}/{circuit_name}"

        with tempfile.TemporaryDirectory() as tmpdir:
            prover_data = {**private_inputs, **public_inputs}
            prover_toml = "\n".join(f'{k} = "{v}"' for k, v in prover_data.items())

            prover_path = f"{circuit_path}/Prover.toml"
            with open(prover_path, "w") as f:
                f.write(prover_toml)

            result = subprocess.run(
                ["nargo", "prove"],
                cwd=circuit_path,
                capture_output=True,
                timeout=120,
            )

            if result.returncode != 0:
                raise CryptoError(f"Noir proof generation failed: {result.stderr.decode()}")

            proof_path = f"{circuit_path}/proofs/{circuit_name}.proof"
            with open(proof_path, "rb") as f:
                proof_bytes = f.read()

        return NoirProof(
            proof_bytes=proof_bytes,
            public_inputs=public_inputs,
            circuit_name=circuit_name,
            generated_at=int(time.time()),
            is_mock=False,
        )

    def verify_proof(self, proof: NoirProof) -> bool:
        """Verify a ZK proof."""
        if proof.is_mock:
            return self._verify_mock_proof(proof)

        import subprocess
        circuit_path = f"{self.circuits_dir}/{proof.circuit_name}"
        result = subprocess.run(
            ["nargo", "verify"],
            cwd=circuit_path,
            capture_output=True,
            timeout=60,
        )
        return result.returncode == 0

    def _mock_proof(
        self,
        circuit_name: str,
        private_inputs: Dict[str, Any],
        public_inputs: Dict[str, Any],
    ) -> NoirProof:
        """Generate a deterministic mock proof for development."""
        import time

        raw = f"{circuit_name}:{json.dumps(private_inputs, sort_keys=True)}:{json.dumps(public_inputs, sort_keys=True)}".encode()
        proof_bytes = hashlib.sha3_256(raw).digest()

        return NoirProof(
            proof_bytes=proof_bytes,
            public_inputs=public_inputs,
            circuit_name=circuit_name,
            generated_at=int(time.time()),
            is_mock=True,
        )

    def _verify_mock_proof(self, proof: NoirProof) -> bool:
        """Verify a mock proof (always valid in dev mode)."""
        return len(proof.proof_bytes) == 32  # Valid if 32-byte SHA3


# Module-level singleton
noir_interface = NoirCircuitInterface()
