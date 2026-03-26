#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
transaction_processor.py - Web3 transaction processor for AEGIS Protocol
"""

import hashlib
import os
import time
from typing import Any, Dict, Optional

from dotenv import load_dotenv

load_dotenv()

RPC_URL = os.getenv("RPC_URL", "https://rpc-amoy.polygon.technology")
PRIVATE_KEY = os.getenv("PRIVATE_KEY", "")
AEGIS_CONTRACT_ADDRESS = os.getenv("AEGIS_CONTRACT_ADDRESS", "")
EURC_TOKEN_ADDRESS = os.getenv("EURC_TOKEN_ADDRESS", "")
CHAIN_ID = int(os.getenv("CHAIN_ID", "80002"))
EURC_DECIMALS = 6

# Minimal ERC-20 ABI for transfer and balanceOf
_ERC20_ABI = [
    {
        "name": "balanceOf",
        "type": "function",
        "inputs": [{"name": "account", "type": "address"}],
        "outputs": [{"name": "", "type": "uint256"}],
        "stateMutability": "view",
    },
    {
        "name": "transfer",
        "type": "function",
        "inputs": [
            {"name": "to", "type": "address"},
            {"name": "amount", "type": "uint256"},
        ],
        "outputs": [{"name": "", "type": "bool"}],
        "stateMutability": "nonpayable",
    },
    {
        "name": "decimals",
        "type": "function",
        "inputs": [],
        "outputs": [{"name": "", "type": "uint8"}],
        "stateMutability": "view",
    },
]


def _mock_tx_hash(sender: str, recipient: str, amount: float) -> str:
    raw = f"{sender}:{recipient}:{amount}:{time.time()}".encode()
    return "0x" + hashlib.sha256(raw).hexdigest()


class TransactionProcessor:
    """Handles all on-chain EURC operations with graceful dev-mode fallback."""

    def _web3(self):
        from web3 import Web3
        w3 = Web3(Web3.HTTPProvider(RPC_URL))
        return w3

    def _eurc_contract(self, w3):
        from web3 import Web3
        if not EURC_TOKEN_ADDRESS:
            raise RuntimeError("EURC_TOKEN_ADDRESS not set")
        return w3.eth.contract(
            address=Web3.to_checksum_address(EURC_TOKEN_ADDRESS),
            abi=_ERC20_ABI,
        )

    def get_balance(self, address: str) -> float:
        """Return EURC balance for an address in EUR (float)."""
        try:
            from web3 import Web3
            w3 = self._web3()
            if not w3.is_connected():
                return 0.0
            contract = self._eurc_contract(w3)
            raw = contract.functions.balanceOf(Web3.to_checksum_address(address)).call()
            return raw / (10 ** EURC_DECIMALS)
        except Exception:
            return 0.0

    def send_eurc(
        self,
        sender_private_key: str,
        recipient: str,
        amount_eur: float,
        proof_hash: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Send EURC from sender to recipient.

        Returns:
            dict with tx_hash, status, amount, recipient.
        """
        try:
            from web3 import Web3
            w3 = self._web3()
            if not w3.is_connected():
                raise RuntimeError("Node not reachable")

            account = w3.eth.account.from_key(sender_private_key)
            contract = self._eurc_contract(w3)

            amount_raw = int(amount_eur * (10 ** EURC_DECIMALS))
            recipient_cs = Web3.to_checksum_address(recipient)

            tx = contract.functions.transfer(recipient_cs, amount_raw).build_transaction(
                {
                    "from": account.address,
                    "nonce": w3.eth.get_transaction_count(account.address),
                    "chainId": CHAIN_ID,
                    "gas": 100000,
                    "maxFeePerGas": w3.eth.gas_price * 2,
                    "maxPriorityFeePerGas": w3.to_wei(1, "gwei"),
                }
            )

            signed = w3.eth.account.sign_transaction(tx, sender_private_key)
            tx_hash = w3.eth.send_raw_transaction(signed.rawTransaction)

            return {
                "tx_hash": tx_hash.hex(),
                "status": "pending",
                "amount": amount_eur,
                "recipient": recipient,
                "proof_hash": proof_hash,
            }

        except Exception as exc:
            # Dev-mode mock
            # Use hashed address, never include private key material in logs/hashes
            sender_id = hashlib.sha256(sender_private_key.encode()).hexdigest()[:16] if sender_private_key else "unknown"
            mock_hash = _mock_tx_hash(
                sender_id,
                recipient,
                amount_eur,
            )
            return {
                "tx_hash": mock_hash,
                "status": "mock_pending",
                "amount": amount_eur,
                "recipient": recipient,
                "proof_hash": proof_hash,
                "dev_mode": True,
                "error": str(exc),
            }

    def get_transaction_status(self, tx_hash: str) -> Dict[str, Any]:
        """Return transaction status from the blockchain."""
        try:
            from web3 import Web3
            w3 = self._web3()
            if not w3.is_connected():
                raise RuntimeError("Node not reachable")

            receipt = w3.eth.get_transaction_receipt(tx_hash)
            if receipt is None:
                return {"tx_hash": tx_hash, "status": "pending", "block_number": None}

            return {
                "tx_hash": tx_hash,
                "status": "confirmed" if receipt.status == 1 else "failed",
                "block_number": receipt.blockNumber,
                "gas_used": receipt.gasUsed,
            }
        except Exception as exc:
            return {"tx_hash": tx_hash, "status": "unknown", "error": str(exc)}

    def create_wallet(self) -> Dict[str, str]:
        """Generate a new Ethereum wallet."""
        try:
            from eth_account import Account
            acct = Account.create()
            return {
                "address": acct.address,
                "private_key": acct.key.hex(),
            }
        except Exception:
            import secrets
            pk = secrets.token_hex(32)
            address = "0x" + hashlib.sha256(pk.encode()).hexdigest()[:40]
            return {"address": address, "private_key": pk, "dev_mode": True}

    def import_wallet(self, private_key: str) -> Dict[str, str]:
        """Derive address from a private key."""
        try:
            from eth_account import Account
            acct = Account.from_key(private_key)
            return {"address": acct.address}
        except Exception:
            address = "0x" + hashlib.sha256(private_key.encode()).hexdigest()[:40]
            return {"address": address, "dev_mode": True}
