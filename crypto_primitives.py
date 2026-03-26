#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
crypto_primitives.py — Cryptographic utilities for the AEGIS Protocol.

Provides:
- Pedersen-style amount commitments (keccak256-based placeholder for ZK circuits)
- MiMC block cipher hash (simplified round-reduced version for off-chain use)
- Merkle tree construction and proof generation

Note: The commitment scheme here is a *placeholder* that mirrors the on-chain
keccak256 logic used in AegisSmartAccount.sol::registerZkProof.  Production
deployments should replace `generate_commitment` with the actual Pedersen /
Poseidon implementation exported by the Noir or Circom verifier.
"""

import hashlib
import hmac
import os
import secrets
import struct
from typing import List, Optional, Tuple


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# MiMC round constant seed (Keccak of ASCII "aegis_mimc")
_MIMC_SEED = b"aegis_mimc"
# Field prime for MiMC (BN254 scalar field)
_FIELD_PRIME = (
    21888242871839275222246405745257275088548364400416034343698204186575808495617
)
_MIMC_ROUNDS = 220

# EURC uses 6 decimal places (same as USDC).
EURC_DECIMALS: int = 6
EURC_UNITS_MULTIPLIER: int = 10**EURC_DECIMALS


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _mimc_round_constants() -> List[int]:
    """Derive MiMC round constants deterministically from the seed."""
    constants: List[int] = []
    h = hashlib.sha3_256(_MIMC_SEED).digest()
    for _ in range(_MIMC_ROUNDS):
        h = hashlib.sha3_256(h).digest()
        constants.append(int.from_bytes(h, "big") % _FIELD_PRIME)
    return constants


_ROUND_CONSTANTS: List[int] = _mimc_round_constants()


def _mimc_encrypt(msg: int, key: int) -> int:
    """MiMC-p/p block cipher (simplified, round-reduced for off-chain use)."""
    x = msg % _FIELD_PRIME
    k = key % _FIELD_PRIME
    for c in _ROUND_CONSTANTS:
        t = (x + k + c) % _FIELD_PRIME
        x = pow(t, 7, _FIELD_PRIME)  # exponent 7 works for BN254 field
    return (x + k) % _FIELD_PRIME


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_commitment(
    amount: float,
    blinding_factor: Optional[str] = None,
) -> dict:
    """Generate a hiding commitment for *amount*.

    The commitment is computed as:
        C = keccak256(amount_wei_bytes32 || blinding_factor_bytes32)

    This mirrors the ``calldataHash`` stored in
    ``AegisSmartAccount.verifiedProofs`` so that off-chain commitments can be
    matched against on-chain registered proofs.

    Args:
        amount:          The EUR amount to commit to (converted to smallest
                         unit × 10^18 internally).
        blinding_factor: Optional hex-encoded 32-byte blinding factor.
                         A cryptographically secure random value is generated
                         when omitted.

    Returns:
        A dict with:
        - ``commitment``      (hex str) — the 32-byte commitment hash.
        - ``blinding_factor`` (hex str) — the 32-byte blinding factor used.
        - ``amount_wei``      (int)     — the integer representation of amount.
    """
    # Represent EUR amount in the smallest unit (6 decimal places for EURC).
    amount_units = int(round(amount * EURC_UNITS_MULTIPLIER))

    if blinding_factor is None:
        raw = secrets.token_bytes(32)
        blinding_factor = raw.hex()

    bf_bytes = bytes.fromhex(blinding_factor.removeprefix("0x"))
    if len(bf_bytes) != 32:
        raise ValueError("blinding_factor must be exactly 32 bytes (64 hex chars)")

    # Pack: amount as uint256 big-endian (32 bytes) || blinding factor (32 bytes)
    amount_bytes = amount_units.to_bytes(32, "big")
    preimage = amount_bytes + bf_bytes

    # Mirror the keccak256 used on-chain in AegisSmartAccount.registerZkProof.
    from eth_hash.auto import keccak  # bundled with web3
    commitment = keccak(preimage)

    return {
        "commitment": "0x" + commitment.hex(),
        "blinding_factor": "0x" + blinding_factor.removeprefix("0x"),
        "amount_units": amount_units,
    }


def mimc_hash(left: int, right: int) -> int:
    """MiMC sponge hash of two field elements (used for Merkle tree nodes).

    Args:
        left:  Left child value as a non-negative integer.
        right: Right child value as a non-negative integer.

    Returns:
        A field element in Z_p representing the hash of the two inputs.
    """
    return _mimc_encrypt(left, right)


def build_merkle_tree(leaves: List[bytes]) -> Tuple[List[List[bytes]], bytes]:
    """Build a binary Merkle tree from a list of leaf hashes.

    Odd layers are padded by duplicating the last leaf.

    Args:
        leaves: List of 32-byte leaf values (e.g. commitment hashes).

    Returns:
        A tuple of (``layers``, ``root``):
        - ``layers``: all tree layers from leaves to root.
        - ``root``:   the 32-byte Merkle root.

    Raises:
        ValueError: If *leaves* is empty.
    """
    if not leaves:
        raise ValueError("Cannot build Merkle tree from empty leaf set")

    from eth_hash.auto import keccak

    def _hash_pair(a: bytes, b: bytes) -> bytes:
        # Sort to produce a consistent hash regardless of order (OpenZeppelin style).
        pair = (a + b) if a <= b else (b + a)
        return keccak(pair)

    current_layer: List[bytes] = [
        keccak(leaf) if len(leaf) != 32 else leaf for leaf in leaves
    ]
    layers: List[List[bytes]] = [current_layer]

    while len(current_layer) > 1:
        if len(current_layer) % 2 == 1:
            current_layer = current_layer + [current_layer[-1]]
        next_layer = [
            _hash_pair(current_layer[i], current_layer[i + 1])
            for i in range(0, len(current_layer), 2)
        ]
        layers.append(next_layer)
        current_layer = next_layer

    return layers, current_layer[0]


def get_merkle_proof(layers: List[List[bytes]], leaf_index: int) -> List[bytes]:
    """Return the Merkle proof (sibling hashes) for a leaf at *leaf_index*.

    Args:
        layers:     The full tree as returned by :func:`build_merkle_tree`.
        leaf_index: Zero-based index of the leaf to prove.

    Returns:
        A list of 32-byte sibling hashes from leaf to root.
    """
    proof: List[bytes] = []
    index = leaf_index
    for layer in layers[:-1]:
        if index % 2 == 0:
            sibling_index = index + 1
        else:
            sibling_index = index - 1
        if sibling_index < len(layer):
            proof.append(layer[sibling_index])
        index //= 2
    return proof


def verify_merkle_proof(
    leaf: bytes,
    proof: List[bytes],
    root: bytes,
) -> bool:
    """Verify a Merkle proof against the expected *root*.

    Args:
        leaf:  The 32-byte leaf hash to verify.
        proof: Sibling hashes as returned by :func:`get_merkle_proof`.
        root:  The expected 32-byte Merkle root.

    Returns:
        ``True`` if the proof is valid, ``False`` otherwise.
    """
    from eth_hash.auto import keccak

    computed = leaf
    for sibling in proof:
        if computed <= sibling:
            computed = keccak(computed + sibling)
        else:
            computed = keccak(sibling + computed)
    return computed == root

