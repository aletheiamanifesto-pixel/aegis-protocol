#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
viewing_keys/escrow.py - Regulatory escrow manager using ECIES (ECDH + HKDF + AES-GCM).
"""

import json
import os
import time
import uuid
from typing import Any, Dict, List, Optional

try:
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    _CRYPTO_AVAILABLE = True
except ImportError:
    _CRYPTO_AVAILABLE = False


class EscrowError(Exception):
    """Raised for escrow validation or crypto errors."""
    pass


def _hkdf_derive(shared_secret: bytes) -> bytes:
    """Derive a 32-byte AES key from an ECDH shared secret."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"aegis-escrow-v2",
    )
    return hkdf.derive(shared_secret)


def _aes_gcm_encrypt(key: bytes, plaintext: bytes):
    """Return (ciphertext, nonce, tag) using AES-256-GCM."""
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ct_with_tag = aesgcm.encrypt(nonce, plaintext, None)
    return ct_with_tag[:-16], nonce, ct_with_tag[-16:]


def _aes_gcm_decrypt(key: bytes, ciphertext: bytes, nonce: bytes, tag: bytes) -> bytes:
    """Decrypt AES-256-GCM and return plaintext."""
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext + tag, None)


class RegulatoryEscrowManager:
    """Manages cryptographic escrow for the regulator.

    Each encrypted transaction also produces an escrow: the data is encrypted
    with the regulator's public key using ECIES (ephemeral ECDH + HKDF + AES-GCM).
    Only the regulator can decrypt by presenting their private key.
    """

    def __init__(self, regulator_public_key_hex: Optional[str] = None):
        """
        Args:
            regulator_public_key_hex: Hex of the regulator's EC public key (secp256r1).
                If None, escrows are not created (dev mode).
        """
        self._regulator_public_key = None
        self._audit_trail: List[Dict[str, Any]] = []

        if regulator_public_key_hex and _CRYPTO_AVAILABLE:
            try:
                pub_bytes = bytes.fromhex(regulator_public_key_hex)
                self._regulator_public_key = serialization.load_der_public_key(pub_bytes)
            except Exception as exc:
                import warnings
                warnings.warn(
                    f"Failed to load regulator public key; escrow disabled: {exc}",
                    RuntimeWarning,
                    stacklevel=2,
                )

    def create_escrow(self, tx_data: Dict, tx_hash: str) -> Optional[Dict[str, Any]]:
        """Encrypt tx_data with ECIES for the regulator.

        ECIES flow:
        1. Generate ephemeral EC key pair (secp256r1)
        2. ECDH: shared_secret = ephemeral_private × regulator_public
        3. HKDF(shared_secret) → AES key
        4. AES-256-GCM encrypt(tx_data)

        Returns:
            {"ephemeral_public_hex", "ciphertext_hex", "nonce_hex", "tag_hex",
             "tx_hash", "escrow_id", "created_at"}
            or None if no regulator key is configured.
        """
        if self._regulator_public_key is None or not _CRYPTO_AVAILABLE:
            return None

        # 1. Ephemeral key pair
        ephemeral_private = ec.generate_private_key(ec.SECP256R1())
        ephemeral_public = ephemeral_private.public_key()

        # 2. ECDH
        shared_secret = ephemeral_private.exchange(ec.ECDH(), self._regulator_public_key)

        # 3. HKDF
        aes_key = _hkdf_derive(shared_secret)

        # 4. Encrypt
        plaintext = json.dumps(tx_data).encode("utf-8")
        ciphertext, nonce, tag = _aes_gcm_encrypt(aes_key, plaintext)

        # Serialize ephemeral public key (DER)
        ephemeral_pub_bytes = ephemeral_public.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        escrow_id = str(uuid.uuid4())
        created_at = time.time()

        result = {
            "escrow_id": escrow_id,
            "tx_hash": tx_hash,
            "ephemeral_public_hex": ephemeral_pub_bytes.hex(),
            "ciphertext_hex": ciphertext.hex(),
            "nonce_hex": nonce.hex(),
            "tag_hex": tag.hex(),
            "created_at": created_at,
        }

        self._audit_trail.append({
            "operation": "create_escrow",
            "escrow_id": escrow_id,
            "tx_hash": tx_hash,
            "timestamp": created_at,
        })

        return result

    def regulator_decrypt_escrow(
        self,
        escrow_data: Dict,
        regulator_private_key_hex: str,
        legal_reference: str,
    ) -> Dict[str, Any]:
        """Decrypt an escrow with the regulator's private key.

        Args:
            escrow_data: Output of create_escrow().
            regulator_private_key_hex: Regulator's EC private key (DER hex).
            legal_reference: Mandatory legal reference (logged in audit trail).

        Returns:
            {"decrypted_data", "legal_reference", "decrypted_at", "tx_hash"}
        """
        if not _CRYPTO_AVAILABLE:
            raise EscrowError("cryptography library not available")

        if not legal_reference or not legal_reference.strip():
            raise EscrowError("legal_reference is required for regulatory decryption")

        try:
            priv_bytes = bytes.fromhex(regulator_private_key_hex)
            regulator_private = serialization.load_der_private_key(priv_bytes, password=None)
        except Exception as exc:
            raise EscrowError(f"Invalid regulator private key: {exc}") from exc

        try:
            ephemeral_pub_bytes = bytes.fromhex(escrow_data["ephemeral_public_hex"])
            ciphertext = bytes.fromhex(escrow_data["ciphertext_hex"])
            nonce = bytes.fromhex(escrow_data["nonce_hex"])
            tag = bytes.fromhex(escrow_data["tag_hex"])
            tx_hash = escrow_data["tx_hash"]
        except (KeyError, ValueError) as exc:
            raise EscrowError(f"Invalid escrow_data format: {exc}") from exc

        try:
            ephemeral_public = serialization.load_der_public_key(ephemeral_pub_bytes)
            shared_secret = regulator_private.exchange(ec.ECDH(), ephemeral_public)
            aes_key = _hkdf_derive(shared_secret)
            plaintext = _aes_gcm_decrypt(aes_key, ciphertext, nonce, tag)
            decrypted_data = json.loads(plaintext.decode("utf-8"))
        except Exception as exc:
            raise EscrowError(f"Decryption failed: {exc}") from exc

        decrypted_at = time.time()

        self._audit_trail.append({
            "operation": "regulator_decrypt",
            "escrow_id": escrow_data.get("escrow_id"),
            "tx_hash": tx_hash,
            "legal_reference": legal_reference,
            "timestamp": decrypted_at,
        })

        return {
            "decrypted_data": decrypted_data,
            "legal_reference": legal_reference,
            "decrypted_at": decrypted_at,
            "tx_hash": tx_hash,
        }

    def get_escrow_audit_trail(self) -> List[Dict[str, Any]]:
        """Return all escrow audit events."""
        return list(self._audit_trail)
