#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
viewing_keys/viewing_keys_v2.py - Hierarchical viewing key management with HKDF and AES-256-GCM.
"""

import json
import os
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from viewing_keys.scope_filter import KeyScope, KeyStatus, filter_by_scope
from viewing_keys.key_lifecycle import check_key_validity, cascade_revoke, find_keys_by_address

try:
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    _CRYPTO_AVAILABLE = True
except ImportError:
    _CRYPTO_AVAILABLE = False


class ViewingKeyError(Exception):
    """Raised for viewing key validation or crypto errors."""
    pass


@dataclass
class ViewingKeyRecord:
    key_id: str
    address: str
    secret: bytes  # 32 bytes
    scope: KeyScope
    status: KeyStatus
    parent_id: Optional[str]        # None for master keys
    created_at: float
    expires_at: Optional[float]
    max_uses: Optional[int]
    children_ids: List[str] = field(default_factory=list)  # derived sub-keys
    use_count: int = 0
    revoked_at: Optional[float] = None


# ---------------------------------------------------------------------------
# Crypto helpers
# ---------------------------------------------------------------------------

def _derive_sub_secret(master_secret: bytes, context: str, scope: KeyScope) -> bytes:
    """Derive a sub-key secret using HKDF-SHA256."""
    if _CRYPTO_AVAILABLE:
        info = f"aegis-vk-v2:{scope.value}:{context}".encode()
        hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info)
        return hkdf.derive(master_secret)
    else:
        import hashlib
        info = f"aegis-vk-v2:{scope.value}:{context}".encode()
        return hashlib.sha256(master_secret + info).digest()


def _encrypt_aes_gcm(key: bytes, plaintext: bytes) -> Tuple[bytes, bytes, bytes]:
    """Encrypt with AES-256-GCM. Returns (ciphertext, nonce, tag)."""
    if _CRYPTO_AVAILABLE:
        nonce = os.urandom(12)
        aesgcm = AESGCM(key)
        ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, None)
        ciphertext = ciphertext_with_tag[:-16]
        tag = ciphertext_with_tag[-16:]
        return ciphertext, nonce, tag
    else:
        import hashlib
        nonce = os.urandom(12)
        # Fallback: XOR stream cipher using HMAC (dev only, not secure)
        stream = hashlib.sha256(key + nonce).digest()
        ciphertext = bytes(a ^ b for a, b in zip(plaintext, (stream * (len(plaintext) // 32 + 1))[:len(plaintext)]))
        tag = hashlib.sha256(key + nonce + ciphertext).digest()[:16]
        return ciphertext, nonce, tag


def _decrypt_aes_gcm(key: bytes, ciphertext: bytes, nonce: bytes, tag: bytes) -> bytes:
    """Decrypt with AES-256-GCM."""
    if _CRYPTO_AVAILABLE:
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext + tag, None)
    else:
        import hashlib
        stream = hashlib.sha256(key + nonce).digest()
        plaintext = bytes(a ^ b for a, b in zip(ciphertext, (stream * (len(ciphertext) // 32 + 1))[:len(ciphertext)]))
        expected_tag = hashlib.sha256(key + nonce + ciphertext).digest()[:16]
        if tag != expected_tag:
            raise ViewingKeyError("Decryption failed: authentication tag mismatch")
        return plaintext


# ---------------------------------------------------------------------------
# Manager
# ---------------------------------------------------------------------------

class ViewingKeyManagerV2:
    """Manages hierarchical viewing keys with HKDF derivation and AES-256-GCM encryption."""

    def __init__(self):
        self._keys: Dict[str, ViewingKeyRecord] = {}   # key_id -> record
        self._master_keys: Dict[str, str] = {}         # address -> master_key_id
        self._audit_trail: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------
    # Key creation / derivation
    # ------------------------------------------------------------------

    def create_master_key(self, address: str) -> Dict[str, Any]:
        """Create a master viewing key for an address.

        If a master already exists for the address, it is revoked first.

        Returns:
            {"key_id", "master_secret" (hex), "address", "created_at"}
        """
        # Revoke existing master (cascade)
        if address in self._master_keys:
            old_master_id = self._master_keys[address]
            cascade_revoke(self._keys, old_master_id)
            self._audit("revoke", address, old_master_id, {"reason": "superseded by new master"})

        key_id = str(uuid.uuid4())
        secret = os.urandom(32)
        created_at = time.time()

        record = ViewingKeyRecord(
            key_id=key_id,
            address=address,
            secret=secret,
            scope=KeyScope.FULL_ACCESS,
            status=KeyStatus.ACTIVE,
            parent_id=None,
            children_ids=[],
            created_at=created_at,
            expires_at=None,
            max_uses=None,
        )
        self._keys[key_id] = record
        self._master_keys[address] = key_id

        self._audit("create_master", address, key_id, {"scope": KeyScope.FULL_ACCESS.value})

        return {
            "key_id": key_id,
            "master_secret": secret.hex(),
            "address": address,
            "created_at": created_at,
        }

    def derive_sub_key(
        self,
        master_key_id: str,
        scope: KeyScope,
        context: str = "",
        expires_in: Optional[int] = None,
        max_uses: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Derive a sub-key from a master key using HKDF-SHA256.

        Args:
            master_key_id: ID of the parent master key.
            scope: Scope for the new sub-key.
            context: HKDF info context string.
            expires_in: Seconds until expiry (None = no expiry).
            max_uses: Maximum number of decrypt uses (None = unlimited).

        Returns:
            {"key_id", "parent_id", "scope", "derived_secret" (hex),
             "expires_at", "max_uses"}
        """
        master = self._keys.get(master_key_id)
        if master is None:
            raise ViewingKeyError(f"Master key {master_key_id} not found")

        valid, reason = check_key_validity(master)
        if not valid:
            raise ViewingKeyError(f"Master key is not usable: {reason}")

        derived_secret = _derive_sub_secret(master.secret, context, scope)
        key_id = str(uuid.uuid4())
        created_at = time.time()
        expires_at = created_at + expires_in if expires_in is not None else None

        record = ViewingKeyRecord(
            key_id=key_id,
            address=master.address,
            secret=derived_secret,
            scope=scope,
            status=KeyStatus.ACTIVE,
            parent_id=master_key_id,
            children_ids=[],
            created_at=created_at,
            expires_at=expires_at,
            max_uses=max_uses,
        )
        self._keys[key_id] = record
        master.children_ids.append(key_id)

        self._audit("derive", master.address, key_id, {
            "parent_id": master_key_id,
            "scope": scope.value,
            "expires_at": expires_at,
            "max_uses": max_uses,
        })

        return {
            "key_id": key_id,
            "parent_id": master_key_id,
            "scope": scope.value,
            "derived_secret": derived_secret.hex(),
            "expires_at": expires_at,
            "max_uses": max_uses,
        }

    # ------------------------------------------------------------------
    # Encrypt / Decrypt
    # ------------------------------------------------------------------

    def encrypt_transaction(self, address: str, tx_data: Dict) -> Dict[str, Any]:
        """Encrypt transaction data with the address master key using AES-256-GCM.

        Returns:
            {"ciphertext" (hex), "nonce" (hex), "tag" (hex), "key_id"}
        """
        master_key_id = self._master_keys.get(address)
        if master_key_id is None:
            raise ViewingKeyError(f"No master key found for address {address}")

        master = self._keys[master_key_id]
        valid, reason = check_key_validity(master)
        if not valid:
            raise ViewingKeyError(f"Master key is not usable: {reason}")

        plaintext = json.dumps(tx_data).encode("utf-8")
        ciphertext, nonce, tag = _encrypt_aes_gcm(master.secret, plaintext)

        self._audit("encrypt", address, master_key_id, {"tx_keys": list(tx_data.keys())})

        return {
            "ciphertext": ciphertext.hex(),
            "nonce": nonce.hex(),
            "tag": tag.hex(),
            "key_id": master_key_id,
        }

    def decrypt_transaction(self, key_id: str, encrypted_data: Dict) -> Dict[str, Any]:
        """Decrypt a transaction. Applies scope filtering after decryption.

        Args:
            key_id: The viewing key to use.
            encrypted_data: Dict with "ciphertext", "nonce", "tag" (hex strings).

        Returns:
            Scope-filtered decrypted data.

        Raises:
            ViewingKeyError: If key is invalid, expired, or revoked.
        """
        record = self._keys.get(key_id)
        if record is None:
            raise ViewingKeyError(f"Key {key_id} not found")

        valid, reason = check_key_validity(record)
        if not valid:
            raise ViewingKeyError(f"Key is not usable: {reason}")

        try:
            ciphertext = bytes.fromhex(encrypted_data["ciphertext"])
            nonce = bytes.fromhex(encrypted_data["nonce"])
            tag = bytes.fromhex(encrypted_data["tag"])
        except (KeyError, ValueError) as exc:
            raise ViewingKeyError(f"Invalid encrypted_data format: {exc}") from exc

        # Determine which key to use for decryption:
        # - Master keys encrypt with their own secret.
        # - Sub-keys are scoped views; decryption uses the root master secret.
        decrypt_record = record
        if record.parent_id is not None:
            decrypt_record = self._find_master(record)
            if decrypt_record is None:
                raise ViewingKeyError("Master key for this sub-key not found")

        try:
            plaintext = _decrypt_aes_gcm(decrypt_record.secret, ciphertext, nonce, tag)
        except Exception as exc:
            raise ViewingKeyError(f"Decryption failed: {exc}") from exc

        data = json.loads(plaintext.decode("utf-8"))

        # Increment use counter before scope filtering
        record.use_count += 1

        filtered = filter_by_scope(data, record.scope)

        self._audit("decrypt", record.address, key_id, {"scope": record.scope.value})

        return filtered

    # ------------------------------------------------------------------
    # Revocation / Regeneration
    # ------------------------------------------------------------------

    def revoke_key(self, key_id: str) -> Dict[str, Any]:
        """Revoke a key. If it is a master, cascade to all sub-keys.

        Returns:
            {"revoked_ids": [...], "key_id": str}
        """
        record = self._keys.get(key_id)
        if record is None:
            raise ViewingKeyError(f"Key {key_id} not found")

        revoked_ids = cascade_revoke(self._keys, key_id)

        # Remove from master_keys registry if this was a master
        if record.parent_id is None and self._master_keys.get(record.address) == key_id:
            del self._master_keys[record.address]

        self._audit("revoke", record.address, key_id, {"revoked_ids": revoked_ids})

        return {"revoked_ids": revoked_ids, "key_id": key_id}

    def revoke_all_keys(self, address: str) -> Dict[str, Any]:
        """Revoke all keys (master + sub) for an address.

        Returns:
            {"revoked_count": int, "address": str}
        """
        key_ids = find_keys_by_address(self._keys, address)
        revoked_count = 0
        for kid in key_ids:
            record = self._keys[kid]
            if record.status != KeyStatus.REVOKED:
                record.status = KeyStatus.REVOKED
                record.revoked_at = time.time()
                revoked_count += 1

        if address in self._master_keys:
            del self._master_keys[address]

        self._audit("revoke_all", address, None, {"revoked_count": revoked_count})

        return {"revoked_count": revoked_count, "address": address}

    def regenerate_master_key(self, address: str) -> Dict[str, Any]:
        """Revoke the old master + all sub-keys, create a new master.

        Returns:
            Info about the new master key.
        """
        # Revoke old master (cascade) if present
        if address in self._master_keys:
            old_id = self._master_keys[address]
            cascade_revoke(self._keys, old_id)
            self._audit("revoke", address, old_id, {"reason": "master regeneration"})
            del self._master_keys[address]

        return self.create_master_key(address)

    # ------------------------------------------------------------------
    # Info / Audit
    # ------------------------------------------------------------------

    def get_key_info(self, key_id: str) -> Optional[Dict[str, Any]]:
        """Return key info (without the secret)."""
        record = self._keys.get(key_id)
        if record is None:
            return None
        return {
            "key_id": record.key_id,
            "address": record.address,
            "scope": record.scope.value,
            "status": record.status.value,
            "parent_id": record.parent_id,
            "children_ids": list(record.children_ids),
            "created_at": record.created_at,
            "expires_at": record.expires_at,
            "max_uses": record.max_uses,
            "use_count": record.use_count,
            "revoked_at": record.revoked_at,
        }

    def get_audit_trail(self, address: str) -> List[Dict[str, Any]]:
        """Return all audit events for the given address."""
        return [e for e in self._audit_trail if e.get("address") == address]

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _audit(self, operation: str, address: str, key_id: Optional[str], extra: Dict) -> None:
        entry = {
            "operation": operation,
            "address": address,
            "key_id": key_id,
            "timestamp": time.time(),
            **extra,
        }
        self._audit_trail.append(entry)

    def has_master_key(self, address: str) -> bool:
        """Return True if the address already has an active master key."""
        return address in self._master_keys

    def get_master_key_id(self, address: str) -> Optional[str]:
        """Return the master key_id for an address, or None if not present."""
        return self._master_keys.get(address)

    def ensure_master_key(self, address: str) -> str:
        """Return the existing master key_id, creating one if none exists.

        Args:
            address: Wallet address.

        Returns:
            The master key_id for the address.
        """
        if address not in self._master_keys:
            result = self.create_master_key(address)
            return result["key_id"]
        return self._master_keys[address]

    def _find_master(self, record: "ViewingKeyRecord") -> Optional["ViewingKeyRecord"]:
        """Walk up the parent chain to find the root master key record."""
        current = record
        visited = set()
        while current.parent_id is not None:
            if current.parent_id in visited:
                return None  # cycle guard
            visited.add(current.parent_id)
            current = self._keys.get(current.parent_id)
            if current is None:
                return None
        return current
