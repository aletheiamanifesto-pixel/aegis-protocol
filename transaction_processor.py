"""
transaction_processor.py - Blockchain Transaction Processor for AEGIS Protocol

Connects to Ethereum via Web3.py and records approved transactions
on-chain through the AegisSmartAccount contract.
"""

import json
import logging
import os
from typing import Optional

from web3 import Web3
from web3.exceptions import Web3Exception

from compliance_engine import ComplianceEngine, ComplianceResult
from models import EuroDigitalTransaction

logger = logging.getLogger(__name__)


class TransactionProcessor:
    """
    Processes Euro Digital transactions and records approvals on Ethereum.

    Uses an RPC endpoint (e.g. Alchemy) to communicate with the blockchain
    and the ComplianceEngine to enforce MiCA rules before submission.
    """

    def __init__(
        self,
        rpc_url: Optional[str] = None,
        private_key: Optional[str] = None,
        contract_address: Optional[str] = None,
        contract_abi: Optional[list] = None,
        chain_id: Optional[int] = None,
    ):
        """
        Initialise the processor.

        All sensitive parameters are read from environment variables when not
        explicitly supplied:
            RPC_URL             – JSON-RPC endpoint (e.g. Alchemy Sepolia)
            PRIVATE_KEY         – Signing key (hex, without 0x prefix is fine)
            AEGIS_CONTRACT_ADDRESS – Deployed AegisSmartAccount address
            CHAIN_ID            – Target chain ID (default: 11155111 for Sepolia)
        """
        self.rpc_url = rpc_url or os.environ.get("RPC_URL", "")
        self.private_key = private_key or os.environ.get("PRIVATE_KEY", "")
        self.contract_address = contract_address or os.environ.get(
            "AEGIS_CONTRACT_ADDRESS", ""
        )
        self.chain_id = chain_id or int(os.environ.get("CHAIN_ID", "11155111"))

        if not self.rpc_url:
            raise ValueError(
                "RPC_URL must be set via argument or environment variable"
            )

        self.w3 = Web3(Web3.HTTPProvider(self.rpc_url))
        if not self.w3.is_connected():
            raise ConnectionError(
                f"Unable to connect to Ethereum node at {self.rpc_url}"
            )

        self.compliance_engine = ComplianceEngine()

        # Derive the account from the private key if available
        self.account = None
        if self.private_key:
            self.account = self.w3.eth.account.from_key(self.private_key)

        # Set up the contract instance if ABI + address are available
        self.contract = None
        if self.contract_address and contract_abi:
            self.contract = self.w3.eth.contract(
                address=Web3.to_checksum_address(self.contract_address),
                abi=contract_abi,
            )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def process_transaction(
        self,
        transaction: EuroDigitalTransaction,
        proof_hash: Optional[str] = None,
    ) -> ComplianceResult:
        """
        Run MiCA compliance checks and, if approved, notify the blockchain.

        Args:
            transaction: The Euro Digital transaction to process.
            proof_hash: Optional ZK proof hash for high-value transactions.

        Returns:
            ComplianceResult from the compliance engine.
        """
        result = self.compliance_engine.check_transaction_with_proof(
            transaction, proof_hash
        )

        if result.approved:
            try:
                tx_hash = self._send_approval_to_chain(transaction)
                logger.info(
                    "Transaction %s approved and recorded on-chain: %s",
                    transaction.tx_hash,
                    tx_hash,
                )
            except Exception:
                logger.exception(
                    "Failed to record approval on-chain for %s",
                    transaction.tx_hash,
                )
        else:
            logger.warning(
                "Transaction %s rejected: %s",
                transaction.tx_hash,
                result.message,
            )

        return result

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _send_approval_to_chain(self, transaction: EuroDigitalTransaction) -> str:
        """
        Send an on-chain record that *transaction* has been approved.

        If a contract instance is configured the processor calls
        ``executeCompliant`` on the AegisSmartAccount.  Otherwise it
        falls back to a simple value-transfer as a lightweight log.

        Returns:
            The transaction hash as a hex string.
        """
        if not self.account:
            raise RuntimeError("No private key configured — cannot sign transactions")

        nonce = self.w3.eth.get_transaction_count(self.account.address)

        if self.contract is not None:
            # Encode the executeCompliant call
            amount_wei = self.w3.to_wei(transaction.amount, "ether")
            proof_bytes = (
                bytes.fromhex(transaction.proof_hash.replace("0x", ""))
                if transaction.proof_hash
                else b"\x00" * 32
            )
            tx_data = self.contract.functions.executeCompliant(
                Web3.to_checksum_address(transaction.recipient_hash),
                amount_wei,
                proof_bytes,
            ).build_transaction(
                {
                    "chainId": self.chain_id,
                    "from": self.account.address,
                    "nonce": nonce,
                    "gas": 200_000,
                }
            )
        else:
            # Lightweight fallback: embed the approval in tx input data
            approval_data = (
                f"AEGIS_APPROVED:{transaction.tx_hash}:{transaction.amount}"
            ).encode()
            tx_data = {
                "chainId": self.chain_id,
                "to": self.account.address,
                "value": 0,
                "nonce": nonce,
                "gas": 21_000 + len(approval_data) * 16,
                "data": approval_data,
            }

        signed = self.account.sign_transaction(tx_data)
        tx_hash = self.w3.eth.send_raw_transaction(signed.raw_transaction)
        return self.w3.to_hex(tx_hash)
