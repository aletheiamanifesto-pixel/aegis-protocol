#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
transaction_processor.py — ERC-4337 UserOperation builder and relay engine.

Responsibilities:
1. Build a ``PackedUserOperation`` from a transaction request and the
   AegisSmartAccount ABI (``build_user_operation``).
2. Relay the signed UserOperation to the on-chain EntryPoint via web3.py
   (``relay_transaction``).
3. Apply a privacy hook before relay: call
   ``crypto_primitives.generate_commitment`` to hide the EUR amount in the
   AEGIS off-chain commitment database before the calldata hits the chain.

Environment variables (via .env or the shell):
    RPC_URL           — JSON-RPC endpoint (e.g. http://localhost:8545)
    ENTRY_POINT_ADDR  — Canonical ERC-4337 EntryPoint address
    SMART_ACCOUNT_ADDR— AegisSmartAccount proxy/factory address
    BUNDLER_PRIVATE_KEY — Private key used to submit txs to the EntryPoint
    ABI_PATH          — Path to aegis_smart_account_abi.json (optional override)
"""

import json
import logging
import os
from pathlib import Path
from typing import Any, Optional

from dotenv import load_dotenv
from eth_account import Account
from eth_account.messages import encode_defunct
from web3 import Web3
from web3.types import TxReceipt

from crypto_primitives import generate_commitment

load_dotenv()

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

RPC_URL: str = os.getenv("RPC_URL", "http://localhost:8545")
ENTRY_POINT_ADDR: str = os.getenv(
    "ENTRY_POINT_ADDR", "0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789"
)
SMART_ACCOUNT_ADDR: str = os.getenv("SMART_ACCOUNT_ADDR", "")
BUNDLER_PRIVATE_KEY: str = os.getenv("BUNDLER_PRIVATE_KEY", "")

_ABI_PATH: Path = Path(
    os.getenv("ABI_PATH", Path(__file__).parent / "aegis_smart_account_abi.json")
)

# Minimal EntryPoint ABI — only the functions we call from the backend.
_ENTRY_POINT_ABI: list = [
    {
        "type": "function",
        "name": "handleOps",
        "stateMutability": "nonpayable",
        "inputs": [
            {
                "name": "ops",
                "type": "tuple[]",
                "components": [
                    {"name": "sender",             "type": "address"},
                    {"name": "nonce",              "type": "uint256"},
                    {"name": "initCode",           "type": "bytes"},
                    {"name": "callData",           "type": "bytes"},
                    {"name": "accountGasLimits",   "type": "bytes32"},
                    {"name": "preVerificationGas", "type": "uint256"},
                    {"name": "gasFees",            "type": "bytes32"},
                    {"name": "paymasterAndData",   "type": "bytes"},
                    {"name": "signature",          "type": "bytes"},
                ],
            },
            {"name": "beneficiary", "type": "address"},
        ],
        "outputs": [],
    },
    {
        "type": "function",
        "name": "getNonce",
        "stateMutability": "view",
        "inputs": [
            {"name": "sender", "type": "address"},
            {"name": "key",    "type": "uint192"},
        ],
        "outputs": [{"name": "nonce", "type": "uint256"}],
    },
    {
        "type": "function",
        "name": "getUserOpHash",
        "stateMutability": "view",
        "inputs": [
            {
                "name": "userOp",
                "type": "tuple",
                "components": [
                    {"name": "sender",             "type": "address"},
                    {"name": "nonce",              "type": "uint256"},
                    {"name": "initCode",           "type": "bytes"},
                    {"name": "callData",           "type": "bytes"},
                    {"name": "accountGasLimits",   "type": "bytes32"},
                    {"name": "preVerificationGas", "type": "uint256"},
                    {"name": "gasFees",            "type": "bytes32"},
                    {"name": "paymasterAndData",   "type": "bytes"},
                    {"name": "signature",          "type": "bytes"},
                ],
            }
        ],
        "outputs": [{"name": "", "type": "bytes32"}],
    },
]

# ---------------------------------------------------------------------------
# Web3 / contract helpers
# ---------------------------------------------------------------------------

def _get_web3() -> Web3:
    """Return a connected Web3 instance."""
    w3 = Web3(Web3.HTTPProvider(RPC_URL))
    if not w3.is_connected():
        raise ConnectionError(f"Cannot connect to RPC endpoint: {RPC_URL}")
    return w3


def _load_abi() -> list:
    """Load the AegisSmartAccount ABI from disk."""
    if not _ABI_PATH.exists():
        raise FileNotFoundError(f"ABI file not found: {_ABI_PATH}")
    with _ABI_PATH.open() as f:
        return json.load(f)


def _get_smart_account_contract(w3: Web3):
    """Return a web3 contract instance for AegisSmartAccount."""
    abi = _load_abi()
    return w3.eth.contract(
        address=Web3.to_checksum_address(SMART_ACCOUNT_ADDR),
        abi=abi,
    )


def _get_entry_point_contract(w3: Web3):
    """Return a web3 contract instance for the EntryPoint."""
    return w3.eth.contract(
        address=Web3.to_checksum_address(ENTRY_POINT_ADDR),
        abi=_ENTRY_POINT_ABI,
    )


# ---------------------------------------------------------------------------
# Gas packing helpers (ERC-4337 v0.7 packed encoding)
# ---------------------------------------------------------------------------

def _pack_gas(high: int, low: int) -> bytes:
    """Pack two 128-bit gas values into a single bytes32 field.

    ERC-4337 v0.7 stores (verificationGasLimit | callGasLimit) and
    (maxPriorityFeePerGas | maxFeePerGas) each as a single bytes32.
    """
    if high > (2**128 - 1) or low > (2**128 - 1):
        raise ValueError("Gas value exceeds 128 bits")
    value = (high << 128) | low
    return value.to_bytes(32, "big")


# ---------------------------------------------------------------------------
# UserOperation construction
# ---------------------------------------------------------------------------

def build_user_operation(
    sender: str,
    call_data: bytes,
    signature: bytes = b"",
    verification_gas_limit: int = 150_000,
    call_gas_limit: int = 300_000,
    pre_verification_gas: int = 50_000,
    max_priority_fee_per_gas: int = 1_500_000_000,   # 1.5 gwei
    max_fee_per_gas: int = 3_000_000_000,             # 3 gwei
    init_code: bytes = b"",
    paymaster_and_data: bytes = b"",
) -> dict:
    """Construct a ``PackedUserOperation`` dict.

    Args:
        sender:                  The smart account address.
        call_data:               ABI-encoded call to ``execute`` / ``executeBatch``.
        signature:               Owner ECDSA signature (empty before signing).
        verification_gas_limit:  Gas limit for the ``validateUserOp`` step.
        call_gas_limit:          Gas limit for the inner call execution.
        pre_verification_gas:    Overhead gas for bundler processing.
        max_priority_fee_per_gas: EIP-1559 tip (wei).
        max_fee_per_gas:         EIP-1559 max fee (wei).
        init_code:               Non-empty only on first deployment.
        paymaster_and_data:      Paymaster address + data; empty means self-pay.

    Returns:
        A dict matching the ``PackedUserOperation`` Solidity struct.
    """
    w3 = _get_web3()
    entry_point = _get_entry_point_contract(w3)

    # Fetch the on-chain nonce for this sender (key=0).
    nonce: int = entry_point.functions.getNonce(
        Web3.to_checksum_address(sender), 0
    ).call()

    account_gas_limits = _pack_gas(verification_gas_limit, call_gas_limit)
    gas_fees = _pack_gas(max_priority_fee_per_gas, max_fee_per_gas)

    return {
        "sender":             Web3.to_checksum_address(sender),
        "nonce":              nonce,
        "initCode":           init_code,
        "callData":           call_data,
        "accountGasLimits":   account_gas_limits,
        "preVerificationGas": pre_verification_gas,
        "gasFees":            gas_fees,
        "paymasterAndData":   paymaster_and_data,
        "signature":          signature,
    }


def encode_execute_call(
    target: str,
    value: int,
    data: bytes,
) -> bytes:
    """ABI-encode a call to ``AegisSmartAccount.execute``.

    Args:
        target: Destination contract address.
        value:  ETH to forward (in wei).
        data:   Inner calldata for the target.

    Returns:
        ABI-encoded bytes suitable as the ``callData`` of a UserOperation.
    """
    w3 = _get_web3()
    contract = _get_smart_account_contract(w3)
    return contract.encode_abi(
        "execute",
        args=[Web3.to_checksum_address(target), value, data],
    )


def encode_execute_batch_call(
    targets: list[str],
    values: list[int],
    data_arr: list[bytes],
) -> bytes:
    """ABI-encode a call to ``AegisSmartAccount.executeBatch``.

    Args:
        targets:  List of destination addresses.
        values:   List of ETH values (wei) per call.
        data_arr: List of calldata bytes per call.

    Returns:
        ABI-encoded bytes suitable as the ``callData`` of a UserOperation.
    """
    if not (len(targets) == len(values) == len(data_arr)):
        raise ValueError("targets, values, and data_arr must have equal length")
    w3 = _get_web3()
    contract = _get_smart_account_contract(w3)
    checksum_targets = [Web3.to_checksum_address(t) for t in targets]
    return contract.encode_abi(
        "executeBatch",
        args=[checksum_targets, values, data_arr],
    )


def compute_user_op_hash(user_op: dict) -> bytes:
    """Compute the ERC-4337 UserOperation hash via the EntryPoint.

    Args:
        user_op: A dict as returned by :func:`build_user_operation`.

    Returns:
        32-byte hash to be signed by the account owner.
    """
    w3 = _get_web3()
    entry_point = _get_entry_point_contract(w3)
    # Convert bytes fields to bytes if they came in as hex strings.
    op_tuple = _user_op_to_tuple(user_op)
    return entry_point.functions.getUserOpHash(op_tuple).call()


def _user_op_to_tuple(user_op: dict) -> tuple:
    """Convert a UserOperation dict to the ordered tuple expected by web3."""
    return (
        user_op["sender"],
        user_op["nonce"],
        user_op["initCode"],
        user_op["callData"],
        user_op["accountGasLimits"],
        user_op["preVerificationGas"],
        user_op["gasFees"],
        user_op["paymasterAndData"],
        user_op["signature"],
    )


# ---------------------------------------------------------------------------
# Privacy hook
# ---------------------------------------------------------------------------

def _apply_privacy_hook(amount_eur: float, sender: str) -> dict:
    """Generate and store an off-chain amount commitment before relay.

    This hides the raw EUR amount in the AEGIS off-chain commitment database
    (in production: encrypted KV store / encrypted IPFS node) so that on-chain
    observers only see the commitment hash, not the plain amount.

    Args:
        amount_eur: Plain EUR amount from the transaction request.
        sender:     Sender Ethereum address (used for logging / indexing).

    Returns:
        The commitment dict from :func:`~crypto_primitives.generate_commitment`.
    """
    commitment = generate_commitment(amount=amount_eur)
    # In production: persist commitment to encrypted off-chain DB here.
    logger.info(
        "Privacy hook: amount commitment generated for sender=%s commitment=%s",
        sender,
        commitment["commitment"],
    )
    return commitment


# ---------------------------------------------------------------------------
# Transaction relay
# ---------------------------------------------------------------------------

def relay_transaction(
    user_op: dict,
    amount_eur: float,
    beneficiary: Optional[str] = None,
) -> dict:
    """Sign and relay a UserOperation to the EntryPoint via ``handleOps``.

    Workflow:
    1. Apply the privacy hook — generate an off-chain commitment for *amount_eur*.
    2. Compute the ``userOpHash`` from the EntryPoint.
    3. Sign the hash with the bundler key (EIP-191).
    4. Submit the signed op via ``EntryPoint.handleOps``.

    Args:
        user_op:     UserOperation dict (with an owner-signed ``signature``
                     already set if using account-level signing flow).
        amount_eur:  Plain EUR amount — consumed by the privacy hook.
        beneficiary: Address that receives the bundler fee refund.
                     Defaults to the bundler's own address.

    Returns:
        A dict with ``tx_hash``, ``commitment``, and ``status``.

    Raises:
        EnvironmentError: If ``BUNDLER_PRIVATE_KEY`` is not configured.
        ConnectionError:  If the RPC endpoint is unreachable.
    """
    if not BUNDLER_PRIVATE_KEY:
        raise EnvironmentError(
            "BUNDLER_PRIVATE_KEY is not set. Configure it in your .env file."
        )

    # 1. Privacy hook — hide amount before hitting the chain.
    commitment = _apply_privacy_hook(amount_eur=amount_eur, sender=user_op["sender"])

    # 2. Compute the userOpHash and sign it with the bundler key.
    w3 = _get_web3()
    bundler_account = Account.from_key(BUNDLER_PRIVATE_KEY)

    if beneficiary is None:
        beneficiary = bundler_account.address

    user_op_hash: bytes = compute_user_op_hash(user_op)
    signed = bundler_account.sign_message(encode_defunct(user_op_hash))
    user_op["signature"] = signed.signature

    # 3. Submit to EntryPoint.
    entry_point = _get_entry_point_contract(w3)
    op_tuple = _user_op_to_tuple(user_op)

    tx = entry_point.functions.handleOps(
        [op_tuple], Web3.to_checksum_address(beneficiary)
    ).build_transaction(
        {
            "from": bundler_account.address,
            "nonce": w3.eth.get_transaction_count(bundler_account.address),
            "gas": 500_000,
        }
    )
    signed_tx = w3.eth.account.sign_transaction(tx, BUNDLER_PRIVATE_KEY)
    tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)

    logger.info("UserOperation relayed: tx_hash=%s", tx_hash.hex())

    return {
        "tx_hash": tx_hash.hex() if tx_hash.hex().startswith("0x") else "0x" + tx_hash.hex(),
        "commitment": commitment["commitment"],
        "status": "relayed",
    }

