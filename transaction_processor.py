#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
transaction_processor.py - Web3 Transaction Processor for AEGIS Protocol

Handles:
  - Creating and signing Ethereum transactions
  - Sending signed transactions via JSON-RPC
  - Polling for transaction receipts
  - EURC ERC-20 transfer encoding
"""

import os
import hashlib
import logging
from typing import Optional, Dict, Any

from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Minimal ABI fragments needed by the processor
# ---------------------------------------------------------------------------

EURC_TRANSFER_ABI = [
    {
        "name": "transfer",
        "type": "function",
        "inputs": [
            {"name": "recipient", "type": "address"},
            {"name": "amount", "type": "uint256"},
        ],
        "outputs": [{"name": "", "type": "bool"}],
        "stateMutability": "nonpayable",
    },
    {
        "name": "balanceOf",
        "type": "function",
        "inputs": [{"name": "account", "type": "address"}],
        "outputs": [{"name": "", "type": "uint256"}],
        "stateMutability": "view",
    },
]

AEGIS_EXECUTE_ABI = [
    {
        "name": "executeCompliant",
        "type": "function",
        "inputs": [
            {"name": "recipient", "type": "address"},
            {"name": "amount", "type": "uint256"},
            {"name": "proofHash", "type": "bytes32"},
        ],
        "outputs": [],
        "stateMutability": "nonpayable",
    },
]

EURC_DECIMALS = 6  # EURC uses 6 decimal places


# ---------------------------------------------------------------------------
# TransactionProcessor
# ---------------------------------------------------------------------------


class TransactionProcessor:
    """
    Handles on-chain interactions via Web3.py.

    Configuration via environment variables:
      RPC_URL                  – JSON-RPC endpoint (default: http://localhost:8545)
      PRIVATE_KEY              – Backend signing key (hex, with 0x prefix)
      AEGIS_CONTRACT_ADDRESS   – Deployed AegisSmartAccount address
      EURC_TOKEN_ADDRESS       – EURC ERC-20 contract address
      CHAIN_ID                 – Network chain ID (default: 80002 for Polygon Amoy)
    """

    def __init__(self) -> None:
        self._rpc_url = os.getenv("RPC_URL", "http://localhost:8545")
        self._private_key = os.getenv("PRIVATE_KEY", "")
        self._aegis_address = os.getenv("AEGIS_CONTRACT_ADDRESS", "")
        self._eurc_address = os.getenv("EURC_TOKEN_ADDRESS", "")
        self._chain_id = int(os.getenv("CHAIN_ID", "80002"))
        self._w3 = None  # lazy-initialised

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _web3(self):
        """Return a connected Web3 instance (lazy init)."""
        if self._w3 is not None:
            return self._w3
        try:
            from web3 import Web3

            self._w3 = Web3(Web3.HTTPProvider(self._rpc_url))
            if not self._w3.is_connected():
                logger.warning("Web3 not connected to %s", self._rpc_url)
        except ImportError:
            raise RuntimeError("web3 package not installed")
        return self._w3

    def _account(self):
        from eth_account import Account

        if not self._private_key:
            raise ValueError("PRIVATE_KEY not configured")
        return Account.from_key(self._private_key)

    @staticmethod
    def _to_eurc_units(amount_eur: float) -> int:
        """Convert a EUR float to EURC integer units (6 decimals)."""
        return int(round(amount_eur * 10 ** EURC_DECIMALS))

    @staticmethod
    def _deterministic_proof_hash(tx_hash: str) -> bytes:
        """
        Produce a bytes32 proof hash from a tx hash.
        Used for low-value transactions that do not require a real ZK proof.
        """
        return hashlib.sha256(tx_hash.encode()).digest()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_balance(self, address: str) -> float:
        """Return EURC balance for *address* as a EUR float."""
        w3 = self._web3()
        from web3 import Web3

        checksum = Web3.to_checksum_address(address)
        if not self._eurc_address:
            # Fall back to native ETH balance (for dev/testing)
            balance_wei = w3.eth.get_balance(checksum)
            return float(w3.from_wei(balance_wei, "ether"))

        contract = w3.eth.contract(
            address=Web3.to_checksum_address(self._eurc_address),
            abi=EURC_TRANSFER_ABI,
        )
        raw = contract.functions.balanceOf(checksum).call()
        return raw / 10 ** EURC_DECIMALS

    def send_eurc(
        self,
        sender_private_key: str,
        recipient: str,
        amount_eur: float,
        proof_hash: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Sign and broadcast a EURC transfer transaction.

        Returns a dict with keys: tx_hash, status, block_number.
        """
        w3 = self._web3()
        from eth_account import Account
        from web3 import Web3

        sender_account = Account.from_key(sender_private_key)
        sender_address = sender_account.address
        nonce = w3.eth.get_transaction_count(sender_address)
        gas_price = w3.eth.gas_price
        amount_units = self._to_eurc_units(amount_eur)
        recipient_checksum = Web3.to_checksum_address(recipient)

        if self._eurc_address:
            contract = w3.eth.contract(
                address=Web3.to_checksum_address(self._eurc_address),
                abi=EURC_TRANSFER_ABI,
            )
            tx = contract.functions.transfer(recipient_checksum, amount_units).build_transaction(
                {
                    "chainId": self._chain_id,
                    "from": sender_address,
                    "nonce": nonce,
                    "gasPrice": gas_price,
                }
            )
        else:
            # Dev fallback: plain ETH transfer
            tx = {
                "chainId": self._chain_id,
                "to": recipient_checksum,
                "value": w3.to_wei(amount_eur, "ether"),
                "gas": 21000,
                "gasPrice": gas_price,
                "nonce": nonce,
            }

        signed = sender_account.sign_transaction(tx)
        raw_tx = signed.rawTransaction
        tx_hash = w3.eth.send_raw_transaction(raw_tx).hex()
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)

        return {
            "tx_hash": tx_hash,
            "status": "confirmed" if receipt.status == 1 else "failed",
            "block_number": receipt.blockNumber,
            "gas_used": receipt.gasUsed,
        }

    def get_transaction_status(self, tx_hash: str) -> Dict[str, Any]:
        """Return the current on-chain status of a transaction."""
        w3 = self._web3()
        try:
            receipt = w3.eth.get_transaction_receipt(tx_hash)
            if receipt is None:
                return {"tx_hash": tx_hash, "status": "pending"}
            return {
                "tx_hash": tx_hash,
                "status": "confirmed" if receipt.status == 1 else "failed",
                "block_number": receipt.blockNumber,
                "gas_used": receipt.gasUsed,
            }
        except Exception as exc:  # noqa: BLE001
            logger.error("Error fetching tx status for %s: %s", tx_hash, exc)
            return {"tx_hash": tx_hash, "status": "unknown", "error": str(exc)}

    def create_wallet(self) -> Dict[str, str]:
        """
        Generate a fresh Ethereum key-pair.
        Returns address and private_key (caller must encrypt before storing).
        """
        from eth_account import Account

        account = Account.create()
        return {
            "address": account.address,
            "private_key": account.key.hex(),
        }

    def import_wallet(self, private_key: str) -> Dict[str, str]:
        """Derive wallet address from a private key."""
        from eth_account import Account

        account = Account.from_key(private_key)
        return {"address": account.address}

