#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
wallet_service.py - User-friendly wallet service for AEGIS Protocol.

Provides simple wallet operations like a consumer banking app.
"""

import base64
import hashlib
import io
import os
from typing import Any, Dict, List, Optional

from cryptography.fernet import Fernet


class WalletError(Exception):
    pass


MIN_PASSWORD_LENGTH = 12
_KDF_PREFIX = "aegis-kdf-v2"
# scrypt: memory-hard, ~64 MiB and ~0.1-0.3 s per attempt; brute-forcing a stolen DB costs dearly.
_SCRYPT_N, _SCRYPT_R, _SCRYPT_P = 2**16, 8, 1


def check_password_strength(password: str) -> None:
    if len(password) < MIN_PASSWORD_LENGTH:
        raise WalletError(f"Password too short: at least {MIN_PASSWORD_LENGTH} characters")
    if len(set(password)) < 6:
        raise WalletError("Password too repetitive")


def _derive_key(password: str, salt: bytes) -> bytes:
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

    kdf = Scrypt(salt=salt, length=32, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P)
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


def encrypt_private_key(private_key_hex: str, password: str) -> str:
    """Encrypt a private key with scrypt(password, random salt) + Fernet.

    Format: aegis-kdf-v2$<salt base64>$<Fernet token>. It is for CLIENT-SIDE storage
    (app, CLI): the AEGIS API never receives private keys.
    """
    check_password_strength(password)
    salt = os.urandom(16)
    token = Fernet(_derive_key(password, salt)).encrypt(private_key_hex.encode()).decode()
    return f"{_KDF_PREFIX}${base64.urlsafe_b64encode(salt).decode()}${token}"


def create_wallet(password: str) -> Dict[str, str]:
    """Generate a new wallet (12-word mnemonic) with the key encrypted under scrypt.

    To be used ON THE CLIENT (app/CLI). The API does not expose this function: the server
    never handles mnemonics or private keys.
    """
    from eth_account import Account
    from mnemonic import Mnemonic

    check_password_strength(password)
    Account.enable_unaudited_hdwallet_features()
    mnemonic_phrase = Mnemonic("english").generate(strength=128)
    account = Account.from_mnemonic(mnemonic_phrase)
    return {
        "address": account.address,
        "mnemonic": mnemonic_phrase,
        "encrypted_key": encrypt_private_key(account.key.hex(), password),
    }


def import_wallet(mnemonic_or_private_key: str, password: str) -> Dict[str, str]:
    """Import from a 12/24-word mnemonic or a private key (client side)."""
    from eth_account import Account

    check_password_strength(password)
    Account.enable_unaudited_hdwallet_features()
    secret = mnemonic_or_private_key.strip()
    if len(secret.split()) in (12, 24):
        account = Account.from_mnemonic(secret)
    else:
        account = Account.from_key(secret)
    return {"address": account.address, "encrypted_key": encrypt_private_key(account.key.hex(), password)}


def decrypt_wallet_key(encrypted_key: str, password: str) -> str:
    """Decrypt a key encrypted with encrypt_private_key."""
    try:
        prefix, salt_b64, token = encrypted_key.split("$", 2)
        if prefix != _KDF_PREFIX:
            raise ValueError("unknown format")
        key = _derive_key(password, base64.urlsafe_b64decode(salt_b64))
        return Fernet(key).decrypt(token.encode()).decode()
    except Exception as e:  # noqa: BLE001 - every failure is "wrong password or corrupted file"
        raise WalletError("Failed to decrypt wallet key: wrong password or corrupted data") from e


def get_balance(address: str) -> float:
    """
    Get AEGIS EUR balance for an address.

    Returns balance in EUR (float). Falls back to 0.0 if blockchain not available.
    """
    try:
        from transaction_processor import TransactionProcessor
        tp = TransactionProcessor()
        return tp.get_balance(address)
    except Exception:
        return 0.0


def send_payment(
    from_address: str,
    to_address: str,
    amount_eur: float,
    encrypted_key: str,
    password: str,
    proof_hash: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Send a payment from one address to another.

    Args:
        from_address: Sender address (for validation).
        to_address: Recipient address.
        amount_eur: Amount in EUR.
        encrypted_key: Encrypted private key of the sender.
        password: Password to decrypt the key.
        proof_hash: Optional ZK proof hash for amounts >= 1000 EUR.

    Returns:
        Dict with tx_hash, status, amount, fee_estimate.
    """
    if amount_eur <= 0:
        raise WalletError("Amount must be positive")

    private_key = decrypt_wallet_key(encrypted_key, password)

    try:
        from transaction_processor import TransactionProcessor
        tp = TransactionProcessor()
        result = tp.send_eurc(private_key, to_address, amount_eur, proof_hash)
        return result
    except Exception as e:
        raise WalletError(f"Payment failed: {e}") from e


def generate_receive_qr(address: str) -> bytes:
    """
    Generate a QR code PNG for receiving payments to an address.

    Args:
        address: Wallet address.

    Returns:
        PNG image bytes.
    """
    try:
        import qrcode

        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr_data = f"ethereum:{address}"
        qr.add_data(qr_data)
        qr.make(fit=True)

        img = qr.make_image(fill_color="black", back_color="white")
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        return buf.getvalue()
    except ImportError:
        return base64.b64decode(
            "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="
        )


def get_transaction_history(address: str, limit: int = 50) -> List[Dict[str, Any]]:
    """Get transaction history for an address (MVP: returns empty list)."""
    return []


def estimate_fee(from_address: str, to_address: str, amount_eur: float) -> Dict[str, float]:
    """
    Estimate transaction fee.

    Returns:
        Dict with estimated_fee_eur, gas_price_gwei, estimated_gas.
    """
    try:
        from transaction_processor import TransactionProcessor
        tp = TransactionProcessor()
        w3 = tp._web3()
        gas_price_wei = w3.eth.gas_price
        gas_price_gwei = gas_price_wei / 1e9
        estimated_gas = 65000  # ERC-20 transfer
        fee_eth = (gas_price_wei * estimated_gas) / 1e18
        fee_eur = fee_eth * 3000  # Approximate ETH/EUR rate; replace with a price oracle in production

        return {
            "estimated_fee_eur": round(fee_eur, 4),
            "gas_price_gwei": round(gas_price_gwei, 2),
            "estimated_gas": estimated_gas,
        }
    except Exception:
        return {
            "estimated_fee_eur": 0.01,
            "gas_price_gwei": 30.0,
            "estimated_gas": 65000,
        }
