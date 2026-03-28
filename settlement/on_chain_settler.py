#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
settlement/on_chain_settler.py - Submits Merkle bundle roots to AegisBundleVerifier on-chain.
"""

import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Optional

from settlement.config import SettlementConfig

logger = logging.getLogger(__name__)

# Minimal ABI for AegisBundleVerifier — only the submitRoot function is needed.
_BUNDLE_VERIFIER_ABI = [
    {
        "name": "submitRoot",
        "type": "function",
        "inputs": [
            {"name": "bundleId", "type": "bytes32"},
            {"name": "merkleRoot", "type": "bytes32"},
        ],
        "outputs": [],
        "stateMutability": "nonpayable",
    }
]


@dataclass
class SettlementResult:
    """Result of an on-chain settlement attempt.

    Attributes:
        bundle_id: The bundle identifier (hex string).
        tx_hash: On-chain transaction hash, or empty string in dev mode.
        block_number: Block number where the tx was confirmed, or 0 in dev mode.
        gas_used: Gas consumed by the transaction, or 0 in dev mode.
        status: One of "pending", "confirmed", or "failed".
        error: Error message if status is "failed", otherwise empty string.
    """

    bundle_id: str
    tx_hash: str
    block_number: int
    gas_used: int
    status: str
    error: str = ""


class OnChainSettler:
    """Submits TransactionBundle Merkle roots to AegisBundleVerifier on Polygon Amoy.

    In dev mode (no PRIVATE_KEY configured), bundles are logged instead of
    submitted on-chain so the system remains fully functional without a wallet.

    Args:
        config: SettlementConfig instance.  Defaults to a config sourced from
                environment variables.

    Example:
        settler = OnChainSettler()
        result = settler.settle(bundle)
    """

    def __init__(self, config: Optional[SettlementConfig] = None) -> None:
        self._config = config or SettlementConfig()
        self._dev_mode = not bool(self._config.private_key)
        if self._dev_mode:
            logger.info(
                "OnChainSettler running in dev mode — "
                "bundles will be logged, not submitted on-chain."
            )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def settle(self, bundle) -> SettlementResult:
        """Settle a TransactionBundle on-chain (or log it in dev mode).

        Args:
            bundle: A TransactionBundle instance from the bundler package.

        Returns:
            SettlementResult with status "confirmed" (or "dev_logged" in dev mode).
        """
        if self._dev_mode:
            return self._dev_log(bundle)

        last_error: str = ""
        for attempt in range(1, self._config.max_retries + 1):
            try:
                return self._submit(bundle)
            except Exception as exc:  # noqa: BLE001
                last_error = str(exc)
                logger.warning(
                    "Settlement attempt %d/%d failed for bundle %s: %s",
                    attempt,
                    self._config.max_retries,
                    bundle.bundle_id,
                    exc,
                )
                if attempt < self._config.max_retries:
                    time.sleep(2 ** attempt)  # exponential backoff

        logger.error(
            "All %d settlement attempts failed for bundle %s",
            self._config.max_retries,
            bundle.bundle_id,
        )
        return SettlementResult(
            bundle_id=bundle.bundle_id,
            tx_hash="",
            block_number=0,
            gas_used=0,
            status="failed",
            error=last_error,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _submit(self, bundle) -> SettlementResult:
        """Build and broadcast the submitRoot transaction."""
        try:
            from web3 import Web3
        except ImportError as exc:
            raise RuntimeError("web3 package is required for on-chain settlement") from exc

        if not self._config.bundle_verifier_address:
            raise RuntimeError("BUNDLE_VERIFIER_ADDRESS is not configured")

        w3 = Web3(Web3.HTTPProvider(self._config.rpc_url))
        if not w3.is_connected():
            raise RuntimeError(f"Cannot connect to RPC endpoint: {self._config.rpc_url}")

        account = w3.eth.account.from_key(self._config.private_key)
        contract = w3.eth.contract(
            address=Web3.to_checksum_address(self._config.bundle_verifier_address),
            abi=_BUNDLE_VERIFIER_ABI,
        )

        # Encode bundle_id as bytes32 and merkle_root as bytes32
        bundle_id_bytes = bytes.fromhex(bundle.bundle_id.ljust(64, "0")[:64])
        merkle_root_hex = bundle.merkle_root
        if merkle_root_hex.startswith("0x"):
            merkle_root_hex = merkle_root_hex[2:]
        merkle_root_bytes = bytes.fromhex(merkle_root_hex.ljust(64, "0")[:64])

        nonce = w3.eth.get_transaction_count(account.address, "pending")
        gas_estimate = contract.functions.submitRoot(
            bundle_id_bytes, merkle_root_bytes
        ).estimate_gas({"from": account.address})
        gas_limit = int(gas_estimate * self._config.gas_multiplier)

        tx = contract.functions.submitRoot(bundle_id_bytes, merkle_root_bytes).build_transaction(
            {
                "from": account.address,
                "nonce": nonce,
                "gas": gas_limit,
                "chainId": self._config.chain_id,
            }
        )

        signed = account.sign_transaction(tx)
        tx_hash_bytes = w3.eth.send_raw_transaction(signed.rawTransaction)
        tx_hash = tx_hash_bytes.hex()
        if not tx_hash.startswith("0x"):
            tx_hash = "0x" + tx_hash

        # Wait for confirmation
        receipt = w3.eth.wait_for_transaction_receipt(
            tx_hash_bytes,
            timeout=120,
            poll_latency=2,
        )

        status = "confirmed" if receipt.status == 1 else "failed"
        return SettlementResult(
            bundle_id=bundle.bundle_id,
            tx_hash=tx_hash,
            block_number=receipt.blockNumber,
            gas_used=receipt.gasUsed,
            status=status,
            error="" if status == "confirmed" else "Transaction reverted on-chain",
        )

    def _dev_log(self, bundle) -> SettlementResult:
        """Log the bundle details instead of submitting on-chain (dev mode)."""
        logger.info(
            "[DEV MODE] Bundle ready for settlement — "
            "bundle_id=%s merkle_root=%s tx_count=%d",
            bundle.bundle_id,
            bundle.merkle_root,
            len(bundle.transactions),
        )
        return SettlementResult(
            bundle_id=bundle.bundle_id,
            tx_hash="",
            block_number=0,
            gas_used=0,
            status="dev_logged",
        )
