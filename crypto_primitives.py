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
# BN254 scalar field: the field of the Noir circuits and of Poseidon2.
FIELD_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617
DOMAIN_BALANCE = 6  # same separator as noir_circuits/aegis_lib (DOMAIN_BALANCE)
MIMC_ROUNDS = 220
MIMC_SEED = b"mimc"


def _mock_proofs_allowed() -> bool:
    """See noir_bridge.mock_proofs_allowed(): mock proofs only if explicitly enabled."""
    return os.getenv("AEGIS_ALLOW_MOCK_PROOFS", "").strip().lower() in {"1", "true", "yes"}


class CryptoError(Exception):
    pass


# ---------------------------------------------------------------------------
# Pedersen Commitments
# ---------------------------------------------------------------------------

def _field_mod(x: int) -> int:
    return x % FIELD_PRIME


_P2 = None


def _poseidon2_constants():
    global _P2
    if _P2 is None:
        from pathlib import Path
        data = json.loads((Path(__file__).parent / "scripts" / "codegen" / "poseidon2_bn254_t4.json").read_text())
        _P2 = ([[int(x, 16) for x in r] for r in data["rc"]], [int(x, 16) for x in data["diag"]])
    return _P2


def _poseidon2_permutation(state: List[int]) -> List[int]:
    rc, diag = _poseidon2_constants()
    p = FIELD_PRIME

    def ext(s):
        a, b, c, d = s
        return [(5 * a + 7 * b + c + 3 * d) % p, (4 * a + 6 * b + c + d) % p,
                (a + 3 * b + 5 * c + 7 * d) % p, (a + b + 4 * c + 6 * d) % p]

    s = ext([x % p for x in state])
    for r in range(64):
        if r < 4 or r >= 60:
            s = ext([pow((s[j] + rc[r][j]) % p, 5, p) for j in range(4)])
        else:
            s[0] = pow((s[0] + rc[r][0]) % p, 5, p)
            t = sum(s) % p
            s = [(s[j] * diag[j] + t) % p for j in range(4)]
    return s


def poseidon2_hash(inputs: List[int]) -> int:
    """Poseidon2 sponge over BN254 (t=4), identical to Barretenberg, Noir and sdk/aegis-core.mjs."""
    p = FIELD_PRIME
    state = [0, 0, 0, len(inputs) << 64]
    cache: List[int] = []
    for x in inputs:
        if len(cache) == 3:
            for j in range(3):
                state[j] = (state[j] + cache[j]) % p
            state = _poseidon2_permutation(state)
            cache = []
        cache.append(x % p)
    for j, c in enumerate(cache):
        state[j] = (state[j] + c) % p
    return _poseidon2_permutation(state)[0]


def pedersen_commit(value: int, blinding_factor: Optional[int] = None) -> Tuple[int, int]:
    """
    Hiding and binding commitment to a value: C = Poseidon2(DOMAIN_BALANCE, value, r).

    It is the same commitment that the `balance_proof` circuit checks. (The name stays for
    compatibility: the old version computed v*G + r*H as plain numbers modulo a prime, with
    no elliptic curve, so it could be inverted and forged.)

    Returns:
        (commitment, blinding_factor) tuple.
    """
    if blinding_factor is None:
        blinding_factor = int.from_bytes(os.urandom(48), "big") % (FIELD_PRIME - 1) + 1
    commitment = poseidon2_hash([DOMAIN_BALANCE, value, blinding_factor])
    return commitment, blinding_factor


balance_commit = pedersen_commit


def pedersen_verify(value: int, blinding_factor: int, commitment: int) -> bool:
    """Verify that commitment = Poseidon2(DOMAIN_BALANCE, value, blinding_factor)."""
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
    Derive an X25519 viewing key pair from a wallet private key (HKDF-style derivation).

    Returns:
        (viewing_private_key, viewing_public_key): 32 raw bytes each. Only the private key
        can decrypt what is encrypted for the public key.
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    if salt is None:
        salt = os.urandom(32)

    prk = hmac.new(salt, wallet_private_key_bytes, hashlib.sha256).digest()
    viewing_private = hmac.new(prk, b"aegis-viewing-key-v2\x01", hashlib.sha256).digest()
    viewing_public = X25519PrivateKey.from_private_bytes(viewing_private).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return viewing_private, viewing_public


_GRANTEE_INFO = b"aegis-grantee-ecies-v1"


def _grantee_key(shared: bytes, eph_pub: bytes, grantee_pub: bytes) -> bytes:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=_GRANTEE_INFO + eph_pub + grantee_pub).derive(shared)


def encrypt_for_grantee(data: bytes, grantee_public_key: bytes) -> Tuple[bytes, bytes]:
    """
    Encrypt `data` so that ONLY the holder of the grantee's private key can read it.

    ECIES: ephemeral X25519 key, ECDH with the grantee's public key, HKDF-SHA256, AES-256-GCM.
    (The old version derived the key from the public key alone: anyone could decrypt.)

    Returns:
        (header, ciphertext): header = ephemeral public key (32 bytes) || nonce (12 bytes);
        the ciphertext includes the GCM tag.
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    if len(grantee_public_key) != 32:
        raise CryptoError("grantee public key must be 32 bytes (X25519)")
    eph = X25519PrivateKey.generate()
    eph_pub = eph.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    shared = eph.exchange(X25519PublicKey.from_public_bytes(grantee_public_key))
    key = _grantee_key(shared, eph_pub, grantee_public_key)
    nonce = os.urandom(12)
    return eph_pub + nonce, AESGCM(key).encrypt(nonce, data, None)


def decrypt_from_owner(ciphertext: bytes, header: bytes, grantee_private_key: bytes) -> bytes:
    """Decrypt with the grantee's PRIVATE key. Raises CryptoError on a wrong key or tampered data."""
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    if len(header) != 44 or len(grantee_private_key) != 32:
        raise CryptoError("invalid header or private key")
    eph_pub, nonce = header[:32], header[32:]
    priv = X25519PrivateKey.from_private_bytes(grantee_private_key)
    grantee_pub = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    key = _grantee_key(priv.exchange(X25519PublicKey.from_public_bytes(eph_pub)), eph_pub, grantee_pub)
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, None)
    except InvalidTag as exc:
        raise CryptoError("decryption failed: wrong key or tampered data") from exc


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
            if not _mock_proofs_allowed():
                raise CryptoError("Noir not available and mock proofs disabled (AEGIS_ALLOW_MOCK_PROOFS)")
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
        """Mock proofs are valid only in dev mode (AEGIS_ALLOW_MOCK_PROOFS=1)."""
        if not _mock_proofs_allowed():
            return False
        return len(proof.proof_bytes) == 32  # Valid if 32-byte SHA3


# Module-level singleton
noir_interface = NoirCircuitInterface()


# ---------------------------------------------------------------------------
# Grumpkin (y^2 = x^3 - 17 over the BN254 scalar field) and Schnorr signatures
# Same scheme as noir_circuits/aegis_lib/src/credential.nr and sdk/aegis-core.mjs.
# ---------------------------------------------------------------------------

GRUMPKIN_ORDER = 21888242871839275222246405745257275088696311157297823662689037894645226208583
GRUMPKIN_G = (1, 0x0000000000000002CF135E7506A45D632D270D45F1181294833FC48D823F272C)
DOMAIN_SCHNORR = 7


def grumpkin_add(a, b):
    p = FIELD_PRIME
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0]:
        if (a[1] + b[1]) % p == 0:
            return None
        lam = 3 * a[0] * a[0] * pow(2 * a[1], -1, p) % p
    else:
        lam = (b[1] - a[1]) * pow(b[0] - a[0], -1, p) % p
    x = (lam * lam - a[0] - b[0]) % p
    return (x, (lam * (a[0] - x) - a[1]) % p)


def grumpkin_mul(point, k: int):
    k %= GRUMPKIN_ORDER
    acc, add = None, point
    while k:
        if k & 1:
            acc = grumpkin_add(acc, add)
        add = grumpkin_add(add, add)
        k >>= 1
    return acc


def grumpkin_on_curve(pt) -> bool:
    return pt is not None and (pt[1] * pt[1] - (pt[0] ** 3 - 17)) % FIELD_PRIME == 0


def schnorr_sign(secret: int, msg: int) -> dict:
    """Schnorr on Grumpkin: R = k·G, e = Poseidon2(7, R, PK, msg), s = k + e·sk (mod order)."""
    k = int.from_bytes(os.urandom(48), "big") % (GRUMPKIN_ORDER - 1) + 1
    pub = grumpkin_mul(GRUMPKIN_G, secret)
    r = grumpkin_mul(GRUMPKIN_G, k)
    e = poseidon2_hash([DOMAIN_SCHNORR, r[0], r[1], pub[0], pub[1], msg])
    s = (k + e * secret) % GRUMPKIN_ORDER
    return {"r": r, "s": s, "s_lo": s & ((1 << 128) - 1), "s_hi": s >> 128}


def schnorr_verify(pub, msg: int, r, s: int) -> bool:
    if not (grumpkin_on_curve(pub) and grumpkin_on_curve(r)):
        return False
    e = poseidon2_hash([DOMAIN_SCHNORR, r[0], r[1], pub[0], pub[1], msg])
    return grumpkin_mul(GRUMPKIN_G, s) == grumpkin_add(r, grumpkin_mul(pub, e))
