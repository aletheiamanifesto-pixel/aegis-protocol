#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
transaction_processor.py – Web3.py integration for AEGIS Protocol

Connects to an EVM-compatible testnet (Polygon Amoy / Sepolia) and submits
MiCA-compliant transactions through the AegisSmartAccount smart contract.
"""

import json
import logging
import os
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv
from web3 import Web3
from web3.exceptions import ContractLogicError, TransactionNotFound

load_dotenv()

logger = logging.getLogger(__name__)

# ── Paths ────────────────────────────────────────────────────────────────
_ABI_PATH = Path(__file__).resolve().parent / "abi" / "AegisSmartAccount.json"

# ── Configuration ────────────────────────────────────────────────────────
RPC_URL: str = os.getenv("RPC_URL", "")
PRIVATE_KEY: str = os.getenv("PRIVATE_KEY", "")
CONTRACT_ADDRESS: str = os.getenv("AEGIS_CONTRACT_ADDRESS", "")
CHAIN_ID: int = int(os.getenv("CHAIN_ID", "80002"))  # default Polygon Amoy


def _load_abi() -> list:
    """Load the ABI from the local JSON file."""
    with open(_ABI_PATH, "r") as f:
        return json.load(f)


def _get_web3() -> Web3:
    """Return a connected Web3 instance."""
    if not RPC_URL:
        raise RuntimeError(
            "RPC_URL is not set. Add it to your .env file "
            "(see .env.example for instructions)."
        )
    w3 = Web3(Web3.HTTPProvider(RPC_URL))
    if not w3.is_connected():
        raise ConnectionError(f"Cannot connect to RPC at {RPC_URL}")
    return w3


def _get_contract(w3: Web3):
    """Return a Web3 Contract instance for AegisSmartAccount."""
    if not CONTRACT_ADDRESS:
        raise RuntimeError(
            "AEGIS_CONTRACT_ADDRESS is not set. Deploy the contract first "
            "and add the address to your .env file."
        )
    abi = _load_abi()
    return w3.eth.contract(
        address=Web3.to_checksum_address(CONTRACT_ADDRESS),
        abi=abi,
    )


def _get_account(w3: Web3):
    """Return the admin account derived from PRIVATE_KEY."""
    if not PRIVATE_KEY:
        raise RuntimeError(
            "PRIVATE_KEY is not set. Add it to your .env file "
            "(see .env.example for instructions)."
        )
    return w3.eth.account.from_key(PRIVATE_KEY)


def _sign_and_send(w3: Web3, tx: dict, account) -> str:
    """Sign a transaction dict and broadcast it. Return the tx hash hex."""
    signed = account.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    hex_hash = w3.to_hex(tx_hash)
    logger.info("Transaction sent: %s", hex_hash)
    return hex_hash


# ── Public API ───────────────────────────────────────────────────────────

def submit_compliant_transaction(
    proof_hash: str,
    calldata_hash: str,
) -> str:
    """
    Register a ZK proof on the AegisSmartAccount contract.

    Parameters
    ----------
    proof_hash : str
        Hex-encoded bytes32 proof hash (e.g. "0xabcd…").
    calldata_hash : str
        Hex-encoded bytes32 calldata hash.

    Returns
    -------
    str
        The blockchain transaction hash (hex).
    """
    w3 = _get_web3()
    contract = _get_contract(w3)
    account = _get_account(w3)

    # Ensure inputs are proper bytes32.
    proof_bytes = bytes.fromhex(proof_hash.removeprefix("0x").zfill(64))
    calldata_bytes = bytes.fromhex(calldata_hash.removeprefix("0x").zfill(64))

    nonce = w3.eth.get_transaction_count(account.address)

    base_fee = w3.eth.get_block("latest").get("baseFeePerGas", w3.eth.gas_price)
    max_priority = w3.to_wei(2, "gwei")

    tx = contract.functions.registerZkProof(
        proof_bytes,
        calldata_bytes,
    ).build_transaction(
        {
            "from": account.address,
            "nonce": nonce,
            "chainId": CHAIN_ID,
            "gas": 200_000,
            "maxFeePerGas": base_fee * 2 + max_priority,
            "maxPriorityFeePerGas": max_priority,
        }
    )

    return _sign_and_send(w3, tx, account)


def execute_transaction(
    to: str,
    value: int,
    data: bytes = b"",
) -> str:
    """
    Execute an arbitrary call through the AegisSmartAccount.

    Parameters
    ----------
    to : str
        Target address.
    value : int
        Wei value to send.
    data : bytes
        Calldata bytes.

    Returns
    -------
    str
        The blockchain transaction hash (hex).
    """
    w3 = _get_web3()
    contract = _get_contract(w3)
    account = _get_account(w3)

    nonce = w3.eth.get_transaction_count(account.address)

    base_fee = w3.eth.get_block("latest").get("baseFeePerGas", w3.eth.gas_price)
    max_priority = w3.to_wei(2, "gwei")

    tx = contract.functions.execute(
        Web3.to_checksum_address(to),
        value,
        data,
    ).build_transaction(
        {
            "from": account.address,
            "nonce": nonce,
            "chainId": CHAIN_ID,
            "gas": 300_000,
            "maxFeePerGas": base_fee * 2 + max_priority,
            "maxPriorityFeePerGas": max_priority,
        }
    )

    return _sign_and_send(w3, tx, account)


def is_proof_registered(proof_hash: str) -> bool:
    """
    Check whether a proof has been registered on-chain.

    Parameters
    ----------
    proof_hash : str
        Hex-encoded bytes32 proof hash.

    Returns
    -------
    bool
    """
    w3 = _get_web3()
    contract = _get_contract(w3)
    proof_bytes = bytes.fromhex(proof_hash.removeprefix("0x").zfill(64))
    return contract.functions.isProofRegistered(proof_bytes).call()


def wait_for_receipt(tx_hash: str, timeout: int = 120) -> Optional[dict]:
    """
    Wait for a transaction receipt.

    Returns the receipt dict or None on timeout.
    """
    w3 = _get_web3()
    try:
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=timeout)
        return dict(receipt)
    except Exception as exc:
        logger.warning("Receipt not available for %s: %s", tx_hash, exc)
        return None
