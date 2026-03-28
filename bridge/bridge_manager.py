#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
bridge/bridge_manager.py - Cross-chain bridge abstraction for AEGIS Protocol.

Supports Polygon Amoy, Ethereum Sepolia, and Base Sepolia.
In dev mode, all operations are simulated with deterministic mock data
so the system is fully functional without real blockchain connections.
"""

import hashlib
import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Dict, Optional

from bridge.config import BridgeConfig, SUPPORTED_CHAINS

logger = logging.getLogger(__name__)

# MiCA single-tx limit for bridge transfers (EUR)
_MICA_BRIDGE_LIMIT_EUR: float = 5_000.0


@dataclass
class BridgeRequest:
    """A cross-chain token transfer request.

    Attributes:
        source_chain: Name of the source chain (e.g. "polygon_amoy").
        dest_chain: Name of the destination chain (e.g. "ethereum_sepolia").
        token_address: ERC-20 token address on the source chain.
        amount: Amount in EUR / token units (float).
        recipient: Destination address on dest_chain.
        sender: Source address on source_chain.
    """

    source_chain: str
    dest_chain: str
    token_address: str
    amount: float
    recipient: str
    sender: str


@dataclass
class BridgeResult:
    """Result of a bridge operation.

    Attributes:
        request_id: Unique identifier for this bridge request.
        status: One of "pending", "locked", "completed", "failed".
        source_tx_hash: Transaction hash on the source chain (empty if pending/failed).
        dest_tx_hash: Transaction hash on the destination chain (empty until completed).
        estimated_time: Estimated seconds until the bridge completes.
        error: Error message if status is "failed".
    """

    request_id: str
    status: str
    source_tx_hash: str = ""
    dest_tx_hash: str = ""
    estimated_time: int = 300
    error: str = ""


class BridgeError(Exception):
    """Raised for bridge validation or execution errors."""


class BridgeManager:
    """Manages cross-chain token bridge transfers for AEGIS Protocol.

    Validates requests against MiCA limits using the compliance engine,
    then either executes on-chain lock-and-mint operations or simulates
    them in dev mode.

    Args:
        config: BridgeConfig instance.  Defaults to a config sourced from
                environment variables.
        compliance_engine: Optional ComplianceEngine for amount validation.

    Example:
        manager = BridgeManager()
        result = manager.initiate_bridge(request)
    """

    def __init__(
        self,
        config: Optional[BridgeConfig] = None,
        compliance_engine=None,
    ) -> None:
        self._config = config or BridgeConfig()
        self._compliance_engine = compliance_engine
        self._requests: Dict[str, BridgeResult] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def initiate_bridge(self, request: BridgeRequest) -> BridgeResult:
        """Validate and initiate a cross-chain bridge transfer.

        Args:
            request: BridgeRequest describing the transfer.

        Returns:
            BridgeResult with a request_id and initial status.

        Raises:
            BridgeError: When validation fails (unsupported chain, limit exceeded, etc.).
        """
        self._validate_request(request)
        self._check_compliance(request)

        request_id = str(uuid.uuid4())

        if self._config.dev_mode:
            result = self._simulate_bridge(request_id, request)
        else:
            result = self._execute_bridge(request_id, request)

        self._requests[request_id] = result
        return result

    def check_bridge_status(self, request_id: str) -> BridgeResult:
        """Poll the current status of a bridge request.

        Args:
            request_id: The UUID returned by initiate_bridge.

        Returns:
            Current BridgeResult for the request.

        Raises:
            BridgeError: When request_id is not found.
        """
        if request_id not in self._requests:
            raise BridgeError(f"Bridge request not found: {request_id}")
        return self._requests[request_id]

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _validate_request(self, request: BridgeRequest) -> None:
        """Check chain support and basic field validity."""
        if request.source_chain not in SUPPORTED_CHAINS:
            raise BridgeError(
                f"Unsupported source chain: {request.source_chain}. "
                f"Supported: {list(SUPPORTED_CHAINS.keys())}"
            )
        if request.dest_chain not in SUPPORTED_CHAINS:
            raise BridgeError(
                f"Unsupported destination chain: {request.dest_chain}. "
                f"Supported: {list(SUPPORTED_CHAINS.keys())}"
            )
        if request.source_chain == request.dest_chain:
            raise BridgeError("Source and destination chains must be different")
        if request.amount <= 0:
            raise BridgeError("Bridge amount must be positive")
        if not request.recipient:
            raise BridgeError("Recipient address is required")
        if not request.sender:
            raise BridgeError("Sender address is required")

    def _check_compliance(self, request: BridgeRequest) -> None:
        """Run MiCA compliance checks on the bridge amount."""
        if request.amount > _MICA_BRIDGE_LIMIT_EUR:
            raise BridgeError(
                f"Bridge amount {request.amount} EUR exceeds MiCA single-tx limit "
                f"{_MICA_BRIDGE_LIMIT_EUR} EUR"
            )

        if self._compliance_engine is not None:
            try:
                result = self._compliance_engine.check_transaction(
                    sender=request.sender,
                    amount=request.amount,
                    op_type="bridge_transfer",
                )
                if not result.approved:
                    raise BridgeError(f"Compliance check failed: {result.message}")
            except BridgeError:
                raise
            except Exception as exc:  # noqa: BLE001
                logger.warning("BridgeManager: compliance check error (ignored): %s", exc)

    def _simulate_bridge(self, request_id: str, request: BridgeRequest) -> BridgeResult:
        """Return a deterministic simulated bridge result (dev mode)."""
        raw = f"{request_id}:{request.source_chain}:{request.dest_chain}:{request.amount}"
        fake_src_hash = "0x" + hashlib.sha256(f"src:{raw}".encode()).hexdigest()
        fake_dst_hash = "0x" + hashlib.sha256(f"dst:{raw}".encode()).hexdigest()
        logger.info(
            "[DEV MODE] Simulating bridge %s → %s amount=%.2f EUR (request_id=%s)",
            request.source_chain,
            request.dest_chain,
            request.amount,
            request_id,
        )
        return BridgeResult(
            request_id=request_id,
            status="completed",
            source_tx_hash=fake_src_hash,
            dest_tx_hash=fake_dst_hash,
            estimated_time=0,
        )

    def _execute_bridge(self, request_id: str, request: BridgeRequest) -> BridgeResult:
        """Initiate a real on-chain lock transaction (production mode stub)."""
        # NOTE: Full on-chain bridge execution requires deploying the bridge
        # contracts.  This stub returns a "pending" result; a relayer service
        # would update the status once the lock tx is confirmed and the mint
        # tx is broadcast on the destination chain.
        logger.warning(
            "BridgeManager: on-chain execution not fully implemented — "
            "returning pending result for request %s",
            request_id,
        )
        return BridgeResult(
            request_id=request_id,
            status="pending",
            estimated_time=self._config.lock_timeout_seconds,
        )
