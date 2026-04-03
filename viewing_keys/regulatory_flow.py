#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
viewing_keys/regulatory_flow.py - Regulatory access request workflow.

Implements the complete flow:
  Agency requests access → Status: PENDING_USER_APPROVAL
  → User approves (with scope + duration) → Status: APPROVED → sub-key derived
  → Or user denies → Status: DENIED
  → Key expires automatically → Status: EXPIRED
  → User revokes manually → Status: REVOKED
"""

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from viewing_keys.viewing_keys_v2 import ViewingKeyManagerV2, ViewingKeyError
from viewing_keys.scope_filter import KeyScope


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PENDING_REQUEST_TTL_DAYS = 7  # pending requests expire after 7 days without response

VALID_REQUESTER_TYPES = {
    "uif",
    "guardia_finanza",
    "esma",
    "tax_authority",
    "aml_authority",
}

# Scope hierarchy: lower index = more restrictive
_SCOPE_ORDER = [
    KeyScope.LIMITED,
    KeyScope.AMOUNT_RANGE,
    KeyScope.BALANCE_ONLY,
    KeyScope.SINGLE_TX,
    KeyScope.TX_ONLY,
    KeyScope.FULL_ACCESS,
]


def _scope_level(scope: KeyScope) -> int:
    """Return an integer representing the scope privilege level (higher = more access)."""
    try:
        return _SCOPE_ORDER.index(scope)
    except ValueError:
        return -1


# ---------------------------------------------------------------------------
# Enums / Dataclasses
# ---------------------------------------------------------------------------

class RequestStatus(str, Enum):
    PENDING_USER_APPROVAL = "pending_user_approval"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"
    REVOKED = "revoked"


@dataclass
class RegulatoryAccessRequest:
    """Represents a regulatory agency's request to access a transaction."""

    request_id: str
    requester_id: str           # identifier of the requesting agency
    requester_type: str         # e.g. "uif", "guardia_finanza", "esma"
    owner_address: str          # wallet owner whose tx is targeted
    tx_hash: str                # target transaction hash
    scope_requested: KeyScope   # the scope the agency is asking for
    duration_days_requested: int
    legal_reference: str        # mandatory legal basis (e.g. "Decreto 231/2007 Art. 35")
    reason: str
    status: RequestStatus
    created_at: float           # Unix timestamp
    responded_at: Optional[float] = None
    viewing_key_id: Optional[str] = None   # set when approved
    denied_reason: Optional[str] = None    # set when denied
    scope_granted: Optional[KeyScope] = None
    duration_days_granted: Optional[int] = None
    audit_events: List[Dict[str, Any]] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Manager
# ---------------------------------------------------------------------------

class RegulatoryFlowError(Exception):
    """Raised for invalid operations in the regulatory flow."""
    pass


class RegulatoryAccessManager:
    """Orchestrates the regulatory access request lifecycle."""

    def __init__(self, vk_manager: ViewingKeyManagerV2) -> None:
        self._vk_manager = vk_manager
        self._requests: Dict[str, RegulatoryAccessRequest] = {}  # request_id -> request

    # ------------------------------------------------------------------
    # Agency-side: create a request
    # ------------------------------------------------------------------

    def create_request(
        self,
        requester_id: str,
        requester_type: str,
        owner_address: str,
        tx_hash: str,
        scope_requested: str,
        duration_days: int,
        legal_reference: str,
        reason: str,
    ) -> Dict[str, Any]:
        """Create a new regulatory access request.

        Args:
            requester_id: Identifier of the requesting agency.
            requester_type: Type of agency (e.g. "uif", "esma").
            owner_address: Wallet address of the data owner.
            tx_hash: Transaction hash the agency wants to inspect.
            scope_requested: Scope string requested.
            duration_days: Number of days of access requested.
            legal_reference: Mandatory legal reference (e.g. "Decreto 231/2007 Art. 35").
            reason: Human-readable reason for the request.

        Returns:
            Dict with request details.

        Raises:
            RegulatoryFlowError: If validation fails.
        """
        if not legal_reference or not legal_reference.strip():
            raise RegulatoryFlowError("legal_reference is mandatory and cannot be empty")

        if not requester_id or not requester_id.strip():
            raise RegulatoryFlowError("requester_id cannot be empty")

        if requester_type not in VALID_REQUESTER_TYPES:
            raise RegulatoryFlowError(
                f"Invalid requester_type '{requester_type}'. "
                f"Must be one of: {', '.join(sorted(VALID_REQUESTER_TYPES))}"
            )

        if not tx_hash or not tx_hash.strip():
            raise RegulatoryFlowError("tx_hash cannot be empty")

        if not owner_address or not owner_address.strip():
            raise RegulatoryFlowError("owner_address cannot be empty")

        if duration_days <= 0:
            raise RegulatoryFlowError("duration_days must be a positive integer")

        try:
            scope_enum = KeyScope(scope_requested)
        except ValueError:
            raise RegulatoryFlowError(
                f"Invalid scope '{scope_requested}'. "
                f"Valid scopes: {[s.value for s in KeyScope]}"
            )

        request_id = str(uuid.uuid4())
        now = time.time()

        req = RegulatoryAccessRequest(
            request_id=request_id,
            requester_id=requester_id,
            requester_type=requester_type,
            owner_address=owner_address,
            tx_hash=tx_hash,
            scope_requested=scope_enum,
            duration_days_requested=duration_days,
            legal_reference=legal_reference.strip(),
            reason=reason,
            status=RequestStatus.PENDING_USER_APPROVAL,
            created_at=now,
        )

        self._append_audit(req, "request_created", {
            "requester_id": requester_id,
            "requester_type": requester_type,
            "scope_requested": scope_requested,
            "duration_days": duration_days,
            "legal_reference": legal_reference.strip(),
        })

        self._requests[request_id] = req
        return self._request_to_dict(req)

    # ------------------------------------------------------------------
    # Owner-side: list pending requests
    # ------------------------------------------------------------------

    def list_pending_requests(self, owner_address: str) -> List[Dict[str, Any]]:
        """Return all pending requests for the given owner address.

        Also auto-expires stale pending requests before returning.

        Args:
            owner_address: The wallet address to filter by.

        Returns:
            List of request dicts with status PENDING_USER_APPROVAL.
        """
        self.check_expired_requests()
        return [
            self._request_to_dict(r)
            for r in self._requests.values()
            if r.owner_address == owner_address
            and r.status == RequestStatus.PENDING_USER_APPROVAL
        ]

    # ------------------------------------------------------------------
    # Owner-side: approve a request
    # ------------------------------------------------------------------

    def approve_request(
        self,
        request_id: str,
        owner_address: str,
        approved_scope: str,
        approved_duration_days: int,
    ) -> Dict[str, Any]:
        """Approve a regulatory access request.

        The owner may grant a scope equal to or more restrictive than the
        requested scope, and a duration equal to or shorter than requested.

        Args:
            request_id: ID of the request to approve.
            owner_address: Must match the request's owner_address.
            approved_scope: Scope string to grant (≤ scope_requested in privilege).
            approved_duration_days: Duration in days (≤ duration_days_requested).

        Returns:
            Dict with approved request info and the derived viewing key info.

        Raises:
            RegulatoryFlowError: If the request is not found, owner mismatch,
                wrong status, or invalid scope/duration.
        """
        req = self._get_request_or_raise(request_id)

        if req.owner_address != owner_address:
            raise RegulatoryFlowError("owner_address does not match the request")

        if req.status != RequestStatus.PENDING_USER_APPROVAL:
            raise RegulatoryFlowError(
                f"Request is not pending approval (current status: {req.status.value})"
            )

        try:
            granted_scope_enum = KeyScope(approved_scope)
        except ValueError:
            raise RegulatoryFlowError(f"Invalid scope '{approved_scope}'")

        # Scope restriction check: approved scope must not exceed requested scope
        if _scope_level(granted_scope_enum) > _scope_level(req.scope_requested):
            raise RegulatoryFlowError(
                f"Cannot grant scope '{approved_scope}' which is broader than "
                f"the requested scope '{req.scope_requested.value}'"
            )

        # Duration restriction check
        if approved_duration_days <= 0:
            raise RegulatoryFlowError("approved_duration_days must be a positive integer")
        if approved_duration_days > req.duration_days_requested:
            raise RegulatoryFlowError(
                f"Cannot grant {approved_duration_days} days which exceeds "
                f"the requested {req.duration_days_requested} days"
            )

        # Ensure a master key exists for the owner; create one if not
        if owner_address not in self._vk_manager._master_keys:
            self._vk_manager.create_master_key(owner_address)

        master_key_id = self._vk_manager._master_keys[owner_address]
        expires_in_seconds = approved_duration_days * 86400

        sub_key = self._vk_manager.derive_sub_key(
            master_key_id=master_key_id,
            scope=granted_scope_enum,
            context=req.tx_hash,
            expires_in=expires_in_seconds,
            max_uses=None,
        )

        now = time.time()
        req.status = RequestStatus.APPROVED
        req.responded_at = now
        req.viewing_key_id = sub_key["key_id"]
        req.scope_granted = granted_scope_enum
        req.duration_days_granted = approved_duration_days

        self._append_audit(req, "request_approved", {
            "approved_by": owner_address,
            "scope_granted": approved_scope,
            "duration_days_granted": approved_duration_days,
            "viewing_key_id": sub_key["key_id"],
            "expires_at": sub_key["expires_at"],
        })

        return {
            **self._request_to_dict(req),
            "viewing_key": sub_key,
        }

    # ------------------------------------------------------------------
    # Owner-side: deny a request
    # ------------------------------------------------------------------

    def deny_request(
        self,
        request_id: str,
        owner_address: str,
        reason: str,
    ) -> Dict[str, Any]:
        """Deny a regulatory access request.

        Args:
            request_id: ID of the request.
            owner_address: Must match the request's owner_address.
            reason: Human-readable reason for the denial.

        Returns:
            Dict with updated request info.

        Raises:
            RegulatoryFlowError: If the request is not found, owner mismatch,
                or the request is not in PENDING_USER_APPROVAL status.
        """
        req = self._get_request_or_raise(request_id)

        if req.owner_address != owner_address:
            raise RegulatoryFlowError("owner_address does not match the request")

        if req.status != RequestStatus.PENDING_USER_APPROVAL:
            raise RegulatoryFlowError(
                f"Request is not pending approval (current status: {req.status.value})"
            )

        now = time.time()
        req.status = RequestStatus.DENIED
        req.responded_at = now
        req.denied_reason = reason

        self._append_audit(req, "request_denied", {
            "denied_by": owner_address,
            "reason": reason,
        })

        return self._request_to_dict(req)

    # ------------------------------------------------------------------
    # Owner-side: revoke an approved key
    # ------------------------------------------------------------------

    def revoke_approved_key(
        self,
        request_id: str,
        owner_address: str,
    ) -> Dict[str, Any]:
        """Manually revoke the viewing key for an approved request.

        Args:
            request_id: ID of the request whose key should be revoked.
            owner_address: Must match the request's owner_address.

        Returns:
            Dict with updated request info.

        Raises:
            RegulatoryFlowError: If request not found, owner mismatch,
                or request is not in APPROVED status.
        """
        req = self._get_request_or_raise(request_id)

        if req.owner_address != owner_address:
            raise RegulatoryFlowError("owner_address does not match the request")

        if req.status != RequestStatus.APPROVED:
            raise RegulatoryFlowError(
                f"Request is not in APPROVED status (current: {req.status.value})"
            )

        if req.viewing_key_id:
            try:
                self._vk_manager.revoke_key(req.viewing_key_id)
            except ViewingKeyError:
                pass  # key may already be gone

        now = time.time()
        req.status = RequestStatus.REVOKED
        req.responded_at = now

        self._append_audit(req, "key_revoked", {
            "revoked_by": owner_address,
            "viewing_key_id": req.viewing_key_id,
        })

        return self._request_to_dict(req)

    # ------------------------------------------------------------------
    # Shared: get request details
    # ------------------------------------------------------------------

    def get_request(self, request_id: str) -> Optional[Dict[str, Any]]:
        """Return details of a request, or None if not found.

        Args:
            request_id: ID of the request.

        Returns:
            Dict with request details or None.
        """
        req = self._requests.get(request_id)
        if req is None:
            return None
        return self._request_to_dict(req)

    # ------------------------------------------------------------------
    # Auto-expiry of stale pending requests
    # ------------------------------------------------------------------

    def check_expired_requests(self) -> List[str]:
        """Auto-expire pending requests older than PENDING_REQUEST_TTL_DAYS.

        Returns:
            List of request_ids that were expired.
        """
        now = time.time()
        ttl_seconds = PENDING_REQUEST_TTL_DAYS * 86400
        expired_ids: List[str] = []

        for req in self._requests.values():
            if req.status == RequestStatus.PENDING_USER_APPROVAL:
                if now - req.created_at > ttl_seconds:
                    req.status = RequestStatus.EXPIRED
                    req.responded_at = now
                    self._append_audit(req, "request_auto_expired", {
                        "ttl_days": PENDING_REQUEST_TTL_DAYS,
                    })
                    expired_ids.append(req.request_id)

        return expired_ids

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _get_request_or_raise(self, request_id: str) -> RegulatoryAccessRequest:
        req = self._requests.get(request_id)
        if req is None:
            raise RegulatoryFlowError(f"Request {request_id} not found")
        return req

    @staticmethod
    def _append_audit(
        req: RegulatoryAccessRequest,
        event: str,
        details: Dict[str, Any],
    ) -> None:
        req.audit_events.append({
            "event": event,
            "timestamp": time.time(),
            **details,
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
            "audit_events": list(req.audit_events),
        }
