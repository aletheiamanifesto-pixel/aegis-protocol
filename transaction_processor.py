#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
transaction_processor.py - Web3 transaction processor for AEGIS Protocol
"""

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any, Dict, Optional

from dotenv import load_dotenv

load_dotenv()

RPC_URL = os.getenv("RPC_URL", "https://rpc-amoy.polygon.technology")
PRIVATE_KEY = os.getenv("PRIVATE_KEY", "")
AEGIS_CONTRACT_ADDRESS = os.getenv("AEGIS_CONTRACT_ADDRESS", "")
EURC_TOKEN_ADDRESS = os.getenv("EURC_TOKEN_ADDRESS", "")
CHAIN_ID = int(os.getenv("CHAIN_ID", "80002"))
EURC_DECIMALS = 6

# MiCA threshold above which a ZK proof is required (in EUR)
MICA_ZK_THRESHOLD = 1000.0

# Minimal ERC-20 ABI fallback (balanceOf, transfer, decimals)
_ERC20_ABI_MINIMAL = [
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


def _load_abi(filename: str):
    """Try to load a full ABI from contracts/abi/<filename>; fall back to minimal ERC-20 ABI."""
    abi_path = Path(__file__).parent / "contracts" / "abi" / filename
    try:
        with open(abi_path) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return _ERC20_ABI_MINIMAL


# Load full AegisEUR ABI (falls back to minimal if file is absent)
_ERC20_ABI = _load_abi("AegisEUR.json")


def _mock_tx_hash(sender: str, recipient: str, amount: float) -> str:
    raw = f"{sender}:{recipient}:{amount}:{time.time()}".encode()
    return "0x" + hashlib.sha256(raw).hexdigest()


class TransactionError(Exception):
    pass


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
                raise RuntimeError("Node not reachable")
            contract = self._eurc_contract(w3)
            raw = contract.functions.balanceOf(Web3.to_checksum_address(address)).call()
            return raw / (10 ** EURC_DECIMALS)
        except Exception as exc:  # noqa: BLE001
            # "0 €" when the node is down would be a false balance: only in development.
            from aegis_env import require_mocks

            require_mocks(f"balance read ({type(exc).__name__})")
            return 0.0

    # ------------------------------------------------------------------
    # Client-side signed transfers: the private key NEVER reaches the server
    # ------------------------------------------------------------------

    def decode_signed_transfer(self, signed_tx: str) -> Dict[str, Any]:
        """Decode an EIP-1559 tx signed on the device and verify that it is an EURC transfer().

        Return sender (recovered from the signature), recipient, amount in token units and nonce.
        """
        from eth_account import Account
        try:  # eth-account >= 0.13
            from eth_account.typed_transactions import TypedTransaction
        except ImportError:  # older eth-account
            from eth_account._utils.typed_transactions import TypedTransaction

        from hexbytes import HexBytes

        try:
            raw = HexBytes(bytes.fromhex(signed_tx.removeprefix("0x")))
            sender = Account.recover_transaction(raw)
            fields = TypedTransaction.from_bytes(raw).as_dict()
        except Exception as exc:  # noqa: BLE001 - malformed or non EIP-1559 input
            raise TransactionError(f"invalid signed transaction: {exc}") from exc
        if int(fields.get("chainId", -1)) != CHAIN_ID:
            raise TransactionError("wrong chainId")
        to = fields.get("to") or b""
        to = ("0x" + bytes(to).hex()) if isinstance(to, (bytes, bytearray)) else str(to)
        to = "0x" + to.lower().removeprefix("0x").removeprefix("0x")
        if not EURC_TOKEN_ADDRESS or to.lower() != EURC_TOKEN_ADDRESS.lower():
            raise TransactionError("the transaction is not addressed to the EURC token")
        if int(fields.get("value", 0)) != 0:
            raise TransactionError("the transaction must not move native coin")
        data = fields.get("data") or b""
        if isinstance(data, str):
            data = bytes.fromhex(data.removeprefix("0x"))
        if len(data) != 4 + 32 + 32 or data[:4] != bytes.fromhex("a9059cbb"):
            raise TransactionError("only transfer(address,uint256) is accepted")
        data = bytes(data)
        recipient = "0x" + data[4 + 12:4 + 32].hex()
        amount_raw = int.from_bytes(data[36:68], "big")
        if amount_raw == 0:
            raise TransactionError("zero amount")
        return {"sender": sender, "recipient": recipient, "amount_raw": amount_raw,
                "amount": amount_raw / (10 ** EURC_DECIMALS), "nonce": int(fields["nonce"]), "raw": raw}

    def broadcast_signed(self, raw: bytes) -> Dict[str, Any]:
        """Broadcast an already signed tx. Without a node: simulation only in development."""
        try:
            w3 = self._web3()
            if not w3.is_connected():
                raise RuntimeError("Node not reachable")
            return {"tx_hash": w3.eth.send_raw_transaction(raw).hex(), "status": "pending"}
        except Exception as exc:  # noqa: BLE001
            from aegis_env import require_mocks

            require_mocks(f"broadcast ({type(exc).__name__})")
            return {"tx_hash": "0x" + hashlib.sha256(raw).hexdigest(), "status": "mock_pending", "dev_mode": True}

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
