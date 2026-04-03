#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
viewing_keys/regulatory_flow.py - Regulatory access request workflow for AEGIS Protocol.

Implements the full lifecycle:

    Agency requests access     → Status: PENDING_USER_APPROVAL
    → User approves            → Status: APPROVED  (sub-key derived)
    → User denies              → Status: DENIED
    → Key expires automatically→ Status: EXPIRED   (auto-checked)
    → User revokes manually    → Status: REVOKED
"""

import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional

from viewing_keys.scope_filter import KeyScope
from viewing_keys.viewing_keys_v2 import ViewingKeyManagerV2, ViewingKeyError


# ---------------------------------------------------------------------------
# Enums and constants
# ---------------------------------------------------------------------------

class RequestStatus(str, Enum):
    PENDING_USER_APPROVAL = "pending_user_approval"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"
    REVOKED = "revoked"


VALID_REQUESTER_TYPES = {
    "uif",
    "guardia_finanza",
    "esma",
    "tax_authority",
    "aml_authority",
}

# Requests that remain PENDING longer than this many days are auto-expired.
REQUEST_AUTO_EXPIRE_DAYS = 7

# Scope ordering for restriction checks (higher index = more restrictive).
_SCOPE_ORDER = [
    KeyScope.FULL_ACCESS,
    KeyScope.TX_ONLY,
    KeyScope.BALANCE_ONLY,
    KeyScope.SINGLE_TX,
    KeyScope.AMOUNT_RANGE,
    KeyScope.LIMITED,
]


def _scope_index(scope: KeyScope) -> int:
    """Return restriction index; higher means more restrictive."""
    try:
        return _SCOPE_ORDER.index(scope)
    except ValueError:
        return 0


def _scope_is_at_least_as_restrictive(granted: KeyScope, requested: KeyScope) -> bool:
    """Return True if *granted* is equal to or more restrictive than *requested*."""
    return _scope_index(granted) >= _scope_index(requested)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class RegulatoryAccessRequest:
    request_id: str
    requester_id: str           # identity of requesting agency
    requester_type: str         # e.g. "uif", "guardia_finanza"
    owner_address: str          # wallet owner whose tx data is requested
    tx_hash: str
    scope_requested: KeyScope
    duration_days_requested: int
    legal_reference: str        # mandatory legal basis
    reason: str
    status: RequestStatus
    created_at: float
    responded_at: Optional[float] = None
    viewing_key_id: Optional[str] = None    # set when APPROVED
    denied_reason: Optional[str] = None     # set when DENIED
    scope_granted: Optional[KeyScope] = None
    duration_days_granted: Optional[int] = None
    _audit: List[Dict[str, Any]] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Manager
# ---------------------------------------------------------------------------

class RegulatoryAccessManager:
    """Manages regulatory access requests and their lifecycle.

    Args:
        vk_manager: An instance of :class:`ViewingKeyManagerV2` used to derive
                    sub-keys when a request is approved.
    """

    def __init__(self, vk_manager: ViewingKeyManagerV2) -> None:
        self._vk_manager = vk_manager
        self._requests: Dict[str, RegulatoryAccessRequest] = {}
        self._audit_trail: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------
    # Create request
    # ------------------------------------------------------------------

    def create_request(
        self,
        requester_id: str,
        requester_type: str,
        owner_address: str,
        tx_hash: str,
        scope_requested: KeyScope,
        duration_days: int,
        legal_reference: str,
        reason: str,
    ) -> Dict[str, Any]:
        """Create a new regulatory access request.

        Args:
            requester_id: Unique identifier of the requesting agency.
            requester_type: Type of agency (must be one of VALID_REQUESTER_TYPES).
            owner_address: Address of the wallet owner whose data is requested.
            tx_hash: The transaction hash the agency wants to inspect.
            scope_requested: The scope of access requested.
            duration_days: Number of days the agency requests access for.
            legal_reference: Mandatory legal basis (e.g. "Decreto 231/2007 Art. 35").
            reason: Human-readable explanation of why access is needed.

        Returns:
            Dict with request details.

        Raises:
            ValueError: If any mandatory field is missing or invalid.
        """
        if not legal_reference or not legal_reference.strip():
            raise ValueError("legal_reference is required and must not be empty")
        if not requester_id or not requester_id.strip():
            raise ValueError("requester_id is required")
        if requester_type not in VALID_REQUESTER_TYPES:
            raise ValueError(
                f"Invalid requester_type '{requester_type}'. "
                f"Must be one of: {sorted(VALID_REQUESTER_TYPES)}"
            )
        if not owner_address or not owner_address.strip():
            raise ValueError("owner_address is required")
        if not tx_hash or not tx_hash.strip():
            raise ValueError("tx_hash is required")
        if duration_days <= 0:
            raise ValueError("duration_days must be a positive integer")

        request_id = str(uuid.uuid4())
        now = time.time()

        req = RegulatoryAccessRequest(
            request_id=request_id,
            requester_id=requester_id.strip(),
            requester_type=requester_type,
            owner_address=owner_address.strip(),
            tx_hash=tx_hash.strip(),
            scope_requested=scope_requested,
            duration_days_requested=duration_days,
            legal_reference=legal_reference.strip(),
            reason=reason,
            status=RequestStatus.PENDING_USER_APPROVAL,
            created_at=now,
        )
        self._requests[request_id] = req

        self._audit("create_request", request_id, owner_address, {
            "requester_id": requester_id,
            "requester_type": requester_type,
            "tx_hash": tx_hash,
            "scope_requested": scope_requested.value,
            "duration_days": duration_days,
            "legal_reference": legal_reference,
        })

        return self._request_to_dict(req)

    # ------------------------------------------------------------------
    # List pending requests
    # ------------------------------------------------------------------

    def list_pending_requests(self, owner_address: str) -> List[Dict[str, Any]]:
        """Return all PENDING_USER_APPROVAL requests for *owner_address*.

        Args:
            owner_address: Wallet address of the owner.

        Returns:
            List of request dicts.
        """
        return [
            self._request_to_dict(r)
            for r in self._requests.values()
            if r.owner_address == owner_address
            and r.status == RequestStatus.PENDING_USER_APPROVAL
        ]

    # ------------------------------------------------------------------
    # Approve request
    # ------------------------------------------------------------------

    def approve_request(
        self,
        request_id: str,
        owner_address: str,
        approved_scope: KeyScope,
        approved_duration_days: int,
    ) -> Dict[str, Any]:
        """Approve a pending regulatory access request.

        The owner may grant a scope that is equal to or more restrictive than
        what was requested, and a duration equal to or shorter.

        Args:
            request_id: ID of the request to approve.
            owner_address: Must match the request's owner_address.
            approved_scope: The scope actually granted (≥ restriction of requested scope).
            approved_duration_days: Duration granted (≤ requested duration).

        Returns:
            Dict with request + key info.

        Raises:
            ValueError: If validation fails.
            ViewingKeyError: If sub-key derivation fails.
        """
        req = self._get_and_validate_request(
            request_id, owner_address, RequestStatus.PENDING_USER_APPROVAL
        )

        if not _scope_is_at_least_as_restrictive(approved_scope, req.scope_requested):
            raise ValueError(
                f"Approved scope '{approved_scope.value}' is less restrictive than "
                f"requested scope '{req.scope_requested.value}'"
            )
        if approved_duration_days <= 0:
            raise ValueError("approved_duration_days must be a positive integer")
        if approved_duration_days > req.duration_days_requested:
            raise ValueError(
                f"Approved duration ({approved_duration_days} days) exceeds requested "
                f"duration ({req.duration_days_requested} days)"
            )

        # Ensure the owner has a master key; create one if absent.
        master_key_id = self._vk_manager.ensure_master_key(owner_address)
        expires_in_seconds = approved_duration_days * 86400

        sub_key = self._vk_manager.derive_sub_key(
            master_key_id=master_key_id,
            scope=approved_scope,
            context=f"regulatory:{req.tx_hash}:{req.requester_id}",
            expires_in=expires_in_seconds,
        )

        now = time.time()
        req.status = RequestStatus.APPROVED
        req.responded_at = now
        req.viewing_key_id = sub_key["key_id"]
        req.scope_granted = approved_scope
        req.duration_days_granted = approved_duration_days

        self._audit("approve_request", request_id, owner_address, {
            "approved_scope": approved_scope.value,
            "approved_duration_days": approved_duration_days,
            "viewing_key_id": sub_key["key_id"],
        })

        result = self._request_to_dict(req)
        result["key_info"] = self._vk_manager.get_key_info(sub_key["key_id"])
        return result

    # ------------------------------------------------------------------
    # Deny request
    # ------------------------------------------------------------------

    def deny_request(
        self,
        request_id: str,
        owner_address: str,
        reason: str = "",
    ) -> Dict[str, Any]:
        """Deny a pending regulatory access request.

        Args:
            request_id: ID of the request to deny.
            owner_address: Must match the request's owner_address.
            reason: Optional human-readable reason for denial.

        Returns:
            Dict with updated request details.
        """
        req = self._get_and_validate_request(
            request_id, owner_address, RequestStatus.PENDING_USER_APPROVAL
        )

        now = time.time()
        req.status = RequestStatus.DENIED
        req.responded_at = now
        req.denied_reason = reason

        self._audit("deny_request", request_id, owner_address, {"reason": reason})

        return self._request_to_dict(req)

    # ------------------------------------------------------------------
    # Revoke approved key
    # ------------------------------------------------------------------

    def revoke_approved_key(
        self,
        request_id: str,
        owner_address: str,
    ) -> Dict[str, Any]:
        """Manually revoke the viewing key granted for an approved request.

        Args:
            request_id: ID of the approved request.
            owner_address: Must match the request's owner_address.

        Returns:
            Dict with updated request details.
        """
        req = self._get_and_validate_request(
            request_id, owner_address, RequestStatus.APPROVED
        )

        if req.viewing_key_id is None:
            raise ValueError("No viewing key associated with this request")

        self._vk_manager.revoke_key(req.viewing_key_id)

        now = time.time()
        req.status = RequestStatus.REVOKED
        req.responded_at = now

        self._audit("revoke_key", request_id, owner_address, {
            "viewing_key_id": req.viewing_key_id,
        })

        return self._request_to_dict(req)

    # ------------------------------------------------------------------
    # Get request
    # ------------------------------------------------------------------

    def get_request(self, request_id: str) -> Optional[Dict[str, Any]]:
        """Return details of a single request, or None if not found.

        Args:
            request_id: The request UUID.
        """
        req = self._requests.get(request_id)
        if req is None:
            return None
        return self._request_to_dict(req)

    # ------------------------------------------------------------------
    # Auto-expire stale pending requests
    # ------------------------------------------------------------------

    def check_expired_requests(self) -> List[str]:
        """Mark as EXPIRED any PENDING requests older than REQUEST_AUTO_EXPIRE_DAYS.

        Returns:
            List of request_ids that were just expired.
        """
        expired_ids: List[str] = []
        cutoff = time.time() - REQUEST_AUTO_EXPIRE_DAYS * 86400
        for req in self._requests.values():
            if (
                req.status == RequestStatus.PENDING_USER_APPROVAL
                and req.created_at < cutoff
            ):
                req.status = RequestStatus.EXPIRED
                req.responded_at = time.time()
                expired_ids.append(req.request_id)
                self._audit("auto_expire", req.request_id, req.owner_address, {})

        return expired_ids

    # ------------------------------------------------------------------
    # Audit trail
    # ------------------------------------------------------------------

    def get_audit_trail(self) -> List[Dict[str, Any]]:
        """Return the full regulatory audit trail."""
        return list(self._audit_trail)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _get_and_validate_request(
        self,
        request_id: str,
        owner_address: str,
        expected_status: RequestStatus,
    ) -> RegulatoryAccessRequest:
        req = self._requests.get(request_id)
        if req is None:
            raise ValueError(f"Request '{request_id}' not found")
        if req.owner_address != owner_address:
            raise ValueError("owner_address does not match the request")
        if req.status != expected_status:
            raise ValueError(
                f"Request is in status '{req.status.value}', "
                f"expected '{expected_status.value}'"
            )
        return req

    def _audit(
        self,
        operation: str,
        request_id: str,
        owner_address: str,
        extra: Dict[str, Any],
    ) -> None:
        self._audit_trail.append({
            "operation": operation,
            "request_id": request_id,
            "owner_address": owner_address,
            "timestamp": time.time(),
            **extra,
        })

    @staticmethod
    def _request_to_dict(req: RegulatoryAccessRequest) -> Dict[str, Any]:
        return {
            "request_id": req.request_id,
            "requester_id": req.requester_id,
            "requester_type": req.requester_type,
            "owner_address": req.owner_address,
            "tx_hash": req.tx_hash,
            "scope_requested": req.scope_requested.value,
            "duration_days_requested": req.duration_days_requested,
            "legal_reference": req.legal_reference,
            "reason": req.reason,
            "status": req.status.value,
            "created_at": req.created_at,
            "responded_at": req.responded_at,
            "viewing_key_id": req.viewing_key_id,
            "denied_reason": req.denied_reason,
            "scope_granted": req.scope_granted.value if req.scope_granted else None,
            "duration_days_granted": req.duration_days_granted,
        }
