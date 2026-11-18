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


def _get_fernet(password: str) -> Fernet:
    """Derive a Fernet key from a password."""
    key = base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())
    return Fernet(key)


def create_wallet(password: str) -> Dict[str, str]:
    """
    Generate a new wallet with mnemonic phrase.

    Args:
        password: Password used to encrypt the private key at rest.

    Returns:
        Dict with address, mnemonic, encrypted_key.
    """
    try:
        from eth_account import Account
        from mnemonic import Mnemonic
        Account.enable_unaudited_hdwallet_features()

        mnemo = Mnemonic("english")
        mnemonic_phrase = mnemo.generate(strength=128)  # 12 words

        account = Account.from_mnemonic(mnemonic_phrase)
        private_key_hex = account.key.hex()

        fernet = _get_fernet(password)
        encrypted_key = fernet.encrypt(private_key_hex.encode()).decode()

        return {
            "address": account.address,
            "mnemonic": mnemonic_phrase,
            "encrypted_key": encrypted_key,
        }

    except ImportError:
        # Without eth_account there is no valid address: simulation only in development.
        from aegis_env import require_mocks

        require_mocks("wallet creation (eth_account missing)")
        import secrets
        private_key_hex = secrets.token_hex(32)
        mnemonic_phrase = "mock mnemonic phrase for development testing only do not use"
        account_address = "0x" + hashlib.sha256(private_key_hex.encode()).hexdigest()[:40]

        fernet = _get_fernet(password)
        encrypted_key = fernet.encrypt(private_key_hex.encode()).decode()

        return {
            "address": account_address,
            "mnemonic": mnemonic_phrase,
            "encrypted_key": encrypted_key,
            "warning": "Development mode: use real keys in production",
        }


def import_wallet(mnemonic_or_private_key: str, password: str) -> Dict[str, str]:
    """
    Import an existing wallet from mnemonic or private key.

    Args:
        mnemonic_or_private_key: 12/24-word mnemonic OR 0x-prefixed private key.
        password: Password to encrypt the key at rest.

    Returns:
        Dict with address and encrypted_key.
    """
    try:
        from eth_account import Account
        Account.enable_unaudited_hdwallet_features()

        words = mnemonic_or_private_key.strip().split()
        if len(words) in (12, 24):
            account = Account.from_mnemonic(mnemonic_or_private_key.strip())
        else:
            account = Account.from_key(mnemonic_or_private_key.strip())

        private_key_hex = account.key.hex()
        fernet = _get_fernet(password)
        encrypted_key = fernet.encrypt(private_key_hex.encode()).decode()

        return {"address": account.address, "encrypted_key": encrypted_key}

    except ImportError:
        from aegis_env import require_mocks

        require_mocks("wallet import (eth_account missing)")
        private_key_hex = mnemonic_or_private_key.strip().lstrip("0x")
        account_address = "0x" + hashlib.sha256(private_key_hex.encode()).hexdigest()[:40]

        fernet = _get_fernet(password)
        encrypted_key = fernet.encrypt(private_key_hex.encode()).decode()

        return {"address": account_address, "encrypted_key": encrypted_key}


def decrypt_wallet_key(encrypted_key: str, password: str) -> str:
    """Decrypt an encrypted private key."""
    try:
        fernet = _get_fernet(password)
        return fernet.decrypt(encrypted_key.encode()).decode()
    except Exception as e:
        raise WalletError("Failed to decrypt wallet key: wrong password?") from e


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
