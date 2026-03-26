#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
crypto_primitives.py – The Shield Bridge · Cryptographic Primitives for AEGIS

Implements:
  1. ``prepare_noir_inputs(transaction_data)`` – Format transaction data as
     Noir-compatible JSON (amount, sender, recipient_hash).
  2. ``generate_dummy_proof()`` – Produce a ``bytes32`` proofHash placeholder
     for testing ``AegisSmartAccount.validateZkProof()``.
  3. Viewing Key Management – Asymmetric encryption (RSA-OAEP) to encrypt a
     ``ViewingKey`` with the regulator's public key before on-chain storage
     via ``registerViewingKey()``.

All public functions are **async** where I/O or heavy computation is involved.
Errors are raised as :class:`CryptoError`.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from models import EuroDigitalTransaction

# ──────────────────────────────────────────────────────────────────────────────
# Logging
# ──────────────────────────────────────────────────────────────────────────────
logger = logging.getLogger("aegis.crypto")
logger.setLevel(logging.DEBUG)

if not logger.handlers:
    _handler = logging.StreamHandler()
    _handler.setFormatter(
        logging.Formatter("[%(asctime)s] %(levelname)s %(name)s – %(message)s")
    )
    logger.addHandler(_handler)


# ──────────────────────────────────────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────────────────────────────────────
BYTES32_LENGTH = 32
"""Length of a ``bytes32`` value in bytes."""

RSA_KEY_SIZE = 2048
"""Default RSA key size for viewing key encryption."""


# ──────────────────────────────────────────────────────────────────────────────
# Custom Errors
# ──────────────────────────────────────────────────────────────────────────────
class CryptoErrorType(str, Enum):
    """Categories of cryptographic errors."""

    INVALID_INPUT = "invalid_input"
    PROOF_GENERATION_FAILED = "proof_generation_failed"
    ENCRYPTION_FAILED = "encryption_failed"
    DECRYPTION_FAILED = "decryption_failed"
    KEY_GENERATION_FAILED = "key_generation_failed"
    SERIALIZATION_FAILED = "serialization_failed"


class CryptoError(Exception):
    """Raised on cryptographic operation failures.

    Attributes:
        error_type: Category of the failure.
        details:    Human-readable message.
        metadata:   Extra key/value pairs for debugging.
    """

    def __init__(
        self,
        error_type: CryptoErrorType,
        details: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.error_type = error_type
        self.details = details
        self.metadata = metadata or {}
        super().__init__(f"[{error_type.value}] {details}")


# ══════════════════════════════════════════════════════════════════════════════
# §1 – Noir Input Preparation (The Shield Bridge)
# ══════════════════════════════════════════════════════════════════════════════

def _to_hex_field(value: int) -> str:
    """Convert an integer to a Noir-compatible hex field element (0x-prefixed, 32-byte)."""
    return "0x" + value.to_bytes(BYTES32_LENGTH, byteorder="big").hex()


def _sha3_256(data: bytes) -> str:
    """Compute SHA3-256 and return 0x-prefixed hex string.

    Note: Ethereum uses Keccak-256 (pre-NIST) which differs from SHA3-256.
    For off-chain Noir input preparation, SHA3-256 is used as the hashing
    primitive. On-chain keccak256 hashes are computed by the Solidity contract.
    """
    return "0x" + hashlib.sha3_256(data).hexdigest()


def _hash_address(address: str) -> str:
    """Hash an Ethereum-style address into a field element for Noir.

    Uses SHA3-256 on the lower-cased, 0x-stripped byte representation.
    """
    clean = address.lower().replace("0x", "")
    return _sha3_256(bytes.fromhex(clean)) if len(clean) == 40 else _sha3_256(clean.encode())


async def prepare_noir_inputs(
    transaction_data: EuroDigitalTransaction,
) -> Dict[str, Any]:
    """Format transaction data into Noir-compatible JSON structure.

    The returned dictionary mirrors the expected ``Prover.toml`` / JSON
    witness format consumed by the Noir proving backend::

        {
            "amount":         "0x…",   // uint256 field element
            "sender":         "0x…",   // hashed sender address
            "recipient_hash": "0x…",   // hashed recipient
            "nonce":          "0x…",   // anti-replay nonce
            "timestamp":      "0x…",   // unix timestamp
            "tx_hash":        "0x…"    // transaction identifier
        }

    Args:
        transaction_data: The transaction to encode.

    Returns:
        A dict ready to be serialised to JSON and fed to the Noir prover.

    Raises:
        CryptoError: If input data is invalid or encoding fails.
    """
    try:
        if transaction_data.amount <= 0:
            raise CryptoError(
                CryptoErrorType.INVALID_INPUT,
                "Transaction amount must be positive.",
                {"amount": transaction_data.amount},
            )

        # Convert EUR amount to integer cents for field arithmetic.
        amount_cents = int(transaction_data.amount * 100)

        noir_inputs: Dict[str, Any] = {
            "amount": _to_hex_field(amount_cents),
            "sender": _hash_address(transaction_data.sender),
            "recipient_hash": _hash_address(transaction_data.recipient_hash),
            "nonce": _to_hex_field(transaction_data.nonce),
            "timestamp": _to_hex_field(transaction_data.timestamp),
            "tx_hash": transaction_data.tx_hash
            if transaction_data.tx_hash.startswith("0x")
            else "0x" + transaction_data.tx_hash,
        }

        logger.debug(
            "Noir inputs prepared for tx %s (amount=%d cents)",
            transaction_data.tx_hash,
            amount_cents,
        )
        return noir_inputs

    except CryptoError:
        raise
    except Exception as exc:
        raise CryptoError(
            CryptoErrorType.SERIALIZATION_FAILED,
            f"Failed to prepare Noir inputs: {exc}",
            {"tx_hash": transaction_data.tx_hash},
        ) from exc


async def prepare_noir_inputs_json(
    transaction_data: EuroDigitalTransaction,
) -> str:
    """Convenience wrapper that returns the Noir inputs as a JSON string.

    Args:
        transaction_data: The transaction to encode.

    Returns:
        A JSON string suitable for writing to ``Prover.toml`` / witness file.
    """
    inputs = await prepare_noir_inputs(transaction_data)
    return json.dumps(inputs, indent=2)


# ══════════════════════════════════════════════════════════════════════════════
# §2 – Dummy Proof Generation (Testing Bridge)
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class DummyProofResult:
    """Result of :func:`generate_dummy_proof`.

    Attributes:
        proof_hash:    The ``bytes32`` proof hash (hex-encoded, 0x-prefixed).
        proof_hash_bytes: Raw 32-byte value.
        callee_data:   ABI-style encoded bytes for ``validateZkProof`` calleeData.
        created_at:    ISO-8601 creation timestamp.
    """

    proof_hash: str
    proof_hash_bytes: bytes
    callee_data: bytes
    created_at: str


async def generate_dummy_proof(
    sender: Optional[str] = None,
    amount: Optional[float] = None,
    nonce: Optional[int] = None,
) -> DummyProofResult:
    """Generate a dummy ``bytes32`` proofHash for testing ``validateZkProof``.

    The proof hash is computed as::

        keccak256(sender ‖ amount_cents ‖ nonce ‖ random_entropy)

    This is **not** a real ZK proof – it is a deterministic placeholder that
    allows the backend to exercise the ``AegisSmartAccount.validateZkProof``
    function during integration tests.

    Args:
        sender: Optional sender address (random if ``None``).
        amount: Optional EUR amount (random 1–10 000 if ``None``).
        nonce:  Optional nonce (random if ``None``).

    Returns:
        A :class:`DummyProofResult` with the proof hash and callee data.

    Raises:
        CryptoError: If proof generation fails.
    """
    try:
        _sender = sender or ("0x" + os.urandom(20).hex())
        _amount = amount or (int.from_bytes(os.urandom(2), "big") % 10_000 + 1)
        _nonce = nonce if nonce is not None else int.from_bytes(os.urandom(4), "big")
        _entropy = os.urandom(16)

        amount_cents = int(_amount * 100)

        preimage = (
            bytes.fromhex(_sender.replace("0x", "").ljust(40, "0")[:40])
            + amount_cents.to_bytes(32, "big")
            + _nonce.to_bytes(32, "big")
            + _entropy
        )

        proof_hash_bytes = hashlib.sha3_256(preimage).digest()
        proof_hash_hex = "0x" + proof_hash_bytes.hex()

        # Build calleeData: ABI-encode (sender_hash, amount, nonce) as
        # three consecutive 32-byte words – the format the Solidity
        # placeholder expects for future verifier integration.
        sender_hash = hashlib.sha3_256(
            bytes.fromhex(_sender.replace("0x", "").ljust(40, "0")[:40])
        ).digest()
        callee_data = (
            sender_hash
            + amount_cents.to_bytes(32, "big")
            + _nonce.to_bytes(32, "big")
        )

        result = DummyProofResult(
            proof_hash=proof_hash_hex,
            proof_hash_bytes=proof_hash_bytes,
            callee_data=callee_data,
            created_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        )

        logger.info("Dummy proof generated: %s", proof_hash_hex)
        return result

    except Exception as exc:
        raise CryptoError(
            CryptoErrorType.PROOF_GENERATION_FAILED,
            f"Failed to generate dummy proof: {exc}",
        ) from exc


# ══════════════════════════════════════════════════════════════════════════════
# §3 – Viewing Key Management (Asymmetric Encryption)
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class RegulatorKeyPair:
    """RSA key pair for a regulator (REGULATOR_ROLE).

    Attributes:
        regulator_address: Ethereum address of the regulator.
        private_key:       RSA private key object.
        public_key:        RSA public key object.
        public_key_pem:    PEM-encoded public key bytes.
    """

    regulator_address: str
    private_key: rsa.RSAPrivateKey
    public_key: rsa.RSAPublicKey
    public_key_pem: bytes


@dataclass
class EncryptedViewingKey:
    """An encrypted viewing key ready for on-chain storage.

    Attributes:
        regulator_address: The regulator whose public key was used.
        ciphertext:        RSA-OAEP encrypted viewing key bytes.
        ciphertext_hex:    Hex-encoded ciphertext (for Solidity ``bytes``).
        plaintext_key_hex: The original viewing key (hex) – only kept
                           temporarily for the backend; never stored on-chain.
    """

    regulator_address: str
    ciphertext: bytes
    ciphertext_hex: str
    plaintext_key_hex: str


class ViewingKeyManager:
    """Manages asymmetric encryption of ViewingKeys for REGULATOR_ROLE.

    Workflow:
      1. ``generate_regulator_keypair()`` creates an RSA-2048 key pair.
      2. ``generate_viewing_key()`` creates a random 32-byte viewing key.
      3. ``encrypt_viewing_key()`` encrypts the viewing key with the
         regulator's public key (RSA-OAEP with SHA-256).
      4. The encrypted bytes are then passed to
         ``AegisSmartAccount.registerViewingKey()`` for on-chain storage.
      5. Only the regulator (holding the private key) can later decrypt.
    """

    def __init__(self) -> None:
        # regulator_address → RegulatorKeyPair
        self._keypairs: Dict[str, RegulatorKeyPair] = {}

    # ── Key Generation ───────────────────────────────────────────────────

    async def generate_regulator_keypair(
        self, regulator_address: str
    ) -> RegulatorKeyPair:
        """Generate an RSA-2048 key pair for a regulator.

        Args:
            regulator_address: The Ethereum address of the regulator.

        Returns:
            A :class:`RegulatorKeyPair`.

        Raises:
            CryptoError: On key generation failure.
        """
        try:
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=RSA_KEY_SIZE,
            )
            public_key = private_key.public_key()
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )

            kp = RegulatorKeyPair(
                regulator_address=regulator_address,
                private_key=private_key,
                public_key=public_key,
                public_key_pem=public_pem,
            )
            self._keypairs[regulator_address] = kp

            logger.info(
                "RSA-2048 keypair generated for regulator %s", regulator_address
            )
            return kp

        except Exception as exc:
            raise CryptoError(
                CryptoErrorType.KEY_GENERATION_FAILED,
                f"Failed to generate keypair for {regulator_address}: {exc}",
            ) from exc

    # ── Viewing Key Creation ─────────────────────────────────────────────

    @staticmethod
    async def generate_viewing_key() -> bytes:
        """Generate a cryptographically random 32-byte viewing key.

        Returns:
            32 random bytes.
        """
        return os.urandom(BYTES32_LENGTH)

    # ── Encryption (for on-chain storage) ────────────────────────────────

    async def encrypt_viewing_key(
        self,
        viewing_key: bytes,
        regulator_address: str,
        regulator_public_key: Optional[rsa.RSAPublicKey] = None,
    ) -> EncryptedViewingKey:
        """Encrypt a viewing key using the regulator's RSA public key.

        Uses RSA-OAEP with SHA-256 padding.

        Args:
            viewing_key:          The plaintext 32-byte viewing key.
            regulator_address:    Ethereum address of the regulator.
            regulator_public_key: If supplied, used directly; otherwise the
                                  manager looks up a previously generated pair.

        Returns:
            An :class:`EncryptedViewingKey` ready for ``registerViewingKey()``.

        Raises:
            CryptoError: On encryption failure or missing public key.
        """
        try:
            pub_key = regulator_public_key
            if pub_key is None:
                kp = self._keypairs.get(regulator_address)
                if kp is None:
                    raise CryptoError(
                        CryptoErrorType.ENCRYPTION_FAILED,
                        (
                            f"No public key registered for {regulator_address}. "
                            "Call generate_regulator_keypair() first."
                        ),
                    )
                pub_key = kp.public_key

            ciphertext = pub_key.encrypt(
                viewing_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )

            result = EncryptedViewingKey(
                regulator_address=regulator_address,
                ciphertext=ciphertext,
                ciphertext_hex="0x" + ciphertext.hex(),
                plaintext_key_hex="0x" + viewing_key.hex(),
            )

            logger.info(
                "Viewing key encrypted for regulator %s (%d bytes ciphertext)",
                regulator_address,
                len(ciphertext),
            )
            return result

        except CryptoError:
            raise
        except Exception as exc:
            raise CryptoError(
                CryptoErrorType.ENCRYPTION_FAILED,
                f"Failed to encrypt viewing key: {exc}",
            ) from exc

    # ── Decryption (regulator-side) ──────────────────────────────────────

    async def decrypt_viewing_key(
        self,
        ciphertext: bytes,
        regulator_address: str,
        regulator_private_key: Optional[rsa.RSAPrivateKey] = None,
    ) -> bytes:
        """Decrypt a viewing key using the regulator's RSA private key.

        Args:
            ciphertext:            The encrypted viewing key bytes.
            regulator_address:     Ethereum address of the regulator.
            regulator_private_key: If supplied, used directly; otherwise the
                                   manager looks up the stored pair.

        Returns:
            The original 32-byte viewing key.

        Raises:
            CryptoError: On decryption failure or missing private key.
        """
        try:
            priv_key = regulator_private_key
            if priv_key is None:
                kp = self._keypairs.get(regulator_address)
                if kp is None:
                    raise CryptoError(
                        CryptoErrorType.DECRYPTION_FAILED,
                        f"No private key available for {regulator_address}.",
                    )
                priv_key = kp.private_key

            plaintext = priv_key.decrypt(
                ciphertext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )

            logger.info(
                "Viewing key decrypted for regulator %s", regulator_address
            )
            return plaintext

        except CryptoError:
            raise
        except Exception as exc:
            raise CryptoError(
                CryptoErrorType.DECRYPTION_FAILED,
                f"Failed to decrypt viewing key: {exc}",
            ) from exc

    # ── Utility ──────────────────────────────────────────────────────────

    def get_public_key_pem(self, regulator_address: str) -> Optional[bytes]:
        """Return the PEM-encoded public key for a regulator, or ``None``."""
        kp = self._keypairs.get(regulator_address)
        return kp.public_key_pem if kp else None


# ══════════════════════════════════════════════════════════════════════════════
# §4 – Inline Tests
# ══════════════════════════════════════════════════════════════════════════════

async def _run_tests() -> None:
    """Self-contained test suite – run via ``python crypto_primitives.py``."""
    import traceback

    passed = 0
    failed = 0

    def _ok(name: str) -> None:
        nonlocal passed
        passed += 1
        print(f"  ✓ {name}")

    def _fail(name: str, err: Exception) -> None:
        nonlocal failed
        failed += 1
        print(f"  ✗ {name}: {err}")
        traceback.print_exc()

    print("\n══════ crypto_primitives.py – tests ══════\n")

    # ── 1. prepare_noir_inputs basic ─────────────────────────────────────
    try:
        tx = EuroDigitalTransaction(
            tx_hash="0xabc123",
            sender="0x1234567890abcdef1234567890abcdef12345678",
            recipient_hash="0xfedcba0987654321fedcba0987654321fedcba09",
            amount=1_500.50,
            timestamp=1_700_000_000,
            nonce=42,
        )
        inputs = await prepare_noir_inputs(tx)
        assert "amount" in inputs
        assert "sender" in inputs
        assert "recipient_hash" in inputs
        assert inputs["amount"].startswith("0x")
        assert inputs["sender"].startswith("0x")
        _ok("prepare_noir_inputs: valid structure")
    except Exception as e:
        _fail("prepare_noir_inputs basic", e)

    # ── 2. prepare_noir_inputs amount encoding ───────────────────────────
    try:
        tx = EuroDigitalTransaction(
            tx_hash="0xdef456",
            sender="0x1234567890abcdef1234567890abcdef12345678",
            recipient_hash="0xfedcba0987654321fedcba0987654321fedcba09",
            amount=100.00,
            timestamp=1_700_000_000,
            nonce=0,
        )
        inputs = await prepare_noir_inputs(tx)
        amount_int = int(inputs["amount"], 16)
        assert amount_int == 10_000, f"Expected 10000 cents, got {amount_int}"
        _ok("prepare_noir_inputs: 100.00 EUR → 10000 cents")
    except Exception as e:
        _fail("prepare_noir_inputs amount encoding", e)

    # ── 3. prepare_noir_inputs invalid amount ────────────────────────────
    try:
        tx = EuroDigitalTransaction(
            tx_hash="0xbad",
            sender="0x1234567890abcdef1234567890abcdef12345678",
            recipient_hash="0xfedcba0987654321fedcba0987654321fedcba09",
            amount=1.0,  # will be overridden
            timestamp=1_700_000_000,
            nonce=0,
        )
        tx.amount = -50.0  # bypass pydantic
        try:
            await prepare_noir_inputs(tx)
            _fail("negative amount should fail", AssertionError("no error"))
        except CryptoError as ce:
            assert ce.error_type == CryptoErrorType.INVALID_INPUT
            _ok("prepare_noir_inputs: negative amount → CryptoError")
    except Exception as e:
        _fail("prepare_noir_inputs invalid amount", e)

    # ── 4. prepare_noir_inputs_json ──────────────────────────────────────
    try:
        tx = EuroDigitalTransaction(
            tx_hash="0xjson",
            sender="0x1234567890abcdef1234567890abcdef12345678",
            recipient_hash="0xfedcba0987654321fedcba0987654321fedcba09",
            amount=250.0,
            timestamp=1_700_000_000,
            nonce=1,
        )
        json_str = await prepare_noir_inputs_json(tx)
        parsed = json.loads(json_str)
        assert "amount" in parsed
        _ok("prepare_noir_inputs_json: valid JSON output")
    except Exception as e:
        _fail("prepare_noir_inputs_json", e)

    # ── 5. generate_dummy_proof basic ────────────────────────────────────
    try:
        proof = await generate_dummy_proof()
        assert proof.proof_hash.startswith("0x")
        assert len(proof.proof_hash_bytes) == 32
        assert len(proof.callee_data) == 96  # 3 × 32 bytes
        _ok("generate_dummy_proof: valid bytes32 hash")
    except Exception as e:
        _fail("generate_dummy_proof basic", e)

    # ── 6. generate_dummy_proof with params ──────────────────────────────
    try:
        proof = await generate_dummy_proof(
            sender="0x1234567890abcdef1234567890abcdef12345678",
            amount=500.0,
            nonce=7,
        )
        assert proof.proof_hash.startswith("0x")
        assert proof.created_at  # ISO timestamp
        _ok("generate_dummy_proof: parametric generation")
    except Exception as e:
        _fail("generate_dummy_proof with params", e)

    # ── 7. generate_dummy_proof uniqueness ───────────────────────────────
    try:
        p1 = await generate_dummy_proof()
        p2 = await generate_dummy_proof()
        assert p1.proof_hash != p2.proof_hash, "Proofs should be unique"
        _ok("generate_dummy_proof: unique hashes")
    except Exception as e:
        _fail("generate_dummy_proof uniqueness", e)

    # ── 8. ViewingKeyManager keypair generation ──────────────────────────
    try:
        mgr = ViewingKeyManager()
        kp = await mgr.generate_regulator_keypair("0xRegulator1")
        assert kp.regulator_address == "0xRegulator1"
        assert kp.public_key_pem.startswith(b"-----BEGIN PUBLIC KEY-----")
        _ok("ViewingKeyManager: keypair generation")
    except Exception as e:
        _fail("ViewingKeyManager keypair", e)

    # ── 9. ViewingKeyManager encrypt/decrypt round-trip ──────────────────
    try:
        mgr = ViewingKeyManager()
        await mgr.generate_regulator_keypair("0xReg2")
        vk = await mgr.generate_viewing_key()
        assert len(vk) == 32

        encrypted = await mgr.encrypt_viewing_key(vk, "0xReg2")
        assert encrypted.ciphertext_hex.startswith("0x")
        assert len(encrypted.ciphertext) > 0

        decrypted = await mgr.decrypt_viewing_key(encrypted.ciphertext, "0xReg2")
        assert decrypted == vk, "Round-trip failed"
        _ok("ViewingKeyManager: encrypt → decrypt round-trip")
    except Exception as e:
        _fail("ViewingKeyManager round-trip", e)

    # ── 10. ViewingKeyManager missing key error ──────────────────────────
    try:
        mgr = ViewingKeyManager()
        vk = await mgr.generate_viewing_key()
        try:
            await mgr.encrypt_viewing_key(vk, "0xNonExistent")
            _fail("missing key should fail", AssertionError("no error"))
        except CryptoError as ce:
            assert ce.error_type == CryptoErrorType.ENCRYPTION_FAILED
            _ok("ViewingKeyManager: missing key → CryptoError")
    except Exception as e:
        _fail("ViewingKeyManager missing key", e)

    # ── 11. get_public_key_pem ───────────────────────────────────────────
    try:
        mgr = ViewingKeyManager()
        assert mgr.get_public_key_pem("0xNone") is None
        await mgr.generate_regulator_keypair("0xPem")
        pem = mgr.get_public_key_pem("0xPem")
        assert pem is not None
        assert b"PUBLIC KEY" in pem
        _ok("get_public_key_pem: returns PEM or None")
    except Exception as e:
        _fail("get_public_key_pem", e)

    # ── 12. External public key encryption ───────────────────────────────
    try:
        mgr = ViewingKeyManager()
        ext_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ext_pub = ext_priv.public_key()

        vk = await mgr.generate_viewing_key()
        encrypted = await mgr.encrypt_viewing_key(
            vk, "0xExtReg", regulator_public_key=ext_pub
        )
        assert len(encrypted.ciphertext) > 0

        decrypted = await mgr.decrypt_viewing_key(
            encrypted.ciphertext, "0xExtReg", regulator_private_key=ext_priv
        )
        assert decrypted == vk
        _ok("External public key encryption/decryption")
    except Exception as e:
        _fail("external key encryption", e)

    # ── Summary ──────────────────────────────────────────────────────────
    total = passed + failed
    print(f"\n══════ {passed}/{total} tests passed ══════\n")
    if failed:
        raise SystemExit(1)


if __name__ == "__main__":
    asyncio.run(_run_tests())
