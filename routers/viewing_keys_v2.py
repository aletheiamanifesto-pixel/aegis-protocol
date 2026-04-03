#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
routers/viewing_keys_v2.py - Viewing Keys V2 + Regulatory Access Flow endpoints.

Endpoints:

Viewing Keys V2 (user-facing):
  POST   /viewing-keys/v2/create           Create a master key for an address
  POST   /viewing-keys/v2/derive           Derive a sub-key from a master
  POST   /viewing-keys/v2/decrypt          Decrypt a transaction with a key
  DELETE /viewing-keys/v2/{key_id}/revoke  Revoke a key (cascade if master)
  GET    /viewing-keys/v2/{key_id}/info    Key metadata (no secret)
  GET    /viewing-keys/v2/{address}/audit  Audit trail for an address

Regulatory Access Flow:
  POST   /regulatory/request-access               Agency requests access
  GET    /regulatory/requests/{owner_address}      List pending requests for owner
  POST   /regulatory/requests/{request_id}/approve Owner approves a request
  POST   /regulatory/requests/{request_id}/deny    Owner denies a request
  POST   /regulatory/requests/{request_id}/revoke  Owner revokes an approved key
  GET    /regulatory/requests/detail/{request_id}  Details of a specific request
"""

from typing import Dict

from fastapi import APIRouter, Depends, HTTPException, Request

from routers.auth import _get_current_user
from schemas import (
    ViewingKeyV2CreateRequest,
    ViewingKeyV2DeriveRequest,
    ViewingKeyV2DecryptRequest,
    RegulatoryRequestCreate,
    RegulatoryRequestApprove,
    RegulatoryRequestDeny,
    RegulatoryRequestRevoke,
)

try:
    from viewing_keys import ViewingKeyManagerV2, ViewingKeyError, KeyScope
    from viewing_keys.regulatory_flow import RegulatoryAccessManager, RegulatoryFlowError
    _vk_v2_available = True
except ImportError:
    _vk_v2_available = False

# Module-level singletons (stateful in-process store; swap for DB-backed impl in prod)
_vk_manager: "ViewingKeyManagerV2 | None" = None
_regulatory_manager: "RegulatoryAccessManager | None" = None


def _get_vk_manager() -> "ViewingKeyManagerV2":
    global _vk_manager
    if _vk_manager is None:
        if not _vk_v2_available:
            raise HTTPException(status_code=503, detail="Viewing Keys V2 service not available")
        _vk_manager = ViewingKeyManagerV2()
    return _vk_manager


def _get_regulatory_manager() -> "RegulatoryAccessManager":
    global _regulatory_manager
    if _regulatory_manager is None:
        if not _vk_v2_available:
            raise HTTPException(status_code=503, detail="Regulatory flow service not available")
        _regulatory_manager = RegulatoryAccessManager(_get_vk_manager())
    return _regulatory_manager


router = APIRouter(tags=["viewing-keys-v2"])


# ---------------------------------------------------------------------------
# Viewing Keys V2 — user-facing
# ---------------------------------------------------------------------------

@router.post("/viewing-keys/v2/create")
def vk_v2_create(
    req: ViewingKeyV2CreateRequest,
    current_user: Dict = Depends(_get_current_user),
):
    """Create a master viewing key for a wallet address."""
    mgr = _get_vk_manager()
    try:
        result = mgr.create_master_key(req.address)
    except ViewingKeyError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return result


@router.post("/viewing-keys/v2/derive")
def vk_v2_derive(
    req: ViewingKeyV2DeriveRequest,
    current_user: Dict = Depends(_get_current_user),
):
    """Derive a sub-key from a master key with the given scope and optional expiry."""
    mgr = _get_vk_manager()
    try:
        scope_enum = KeyScope(req.scope)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid scope: {req.scope}")
    try:
        result = mgr.derive_sub_key(
            master_key_id=req.master_key_id,
            scope=scope_enum,
            context=req.context,
            expires_in=req.expires_in,
            max_uses=req.max_uses,
        )
    except ViewingKeyError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return result


@router.post("/viewing-keys/v2/decrypt")
def vk_v2_decrypt(
    req: ViewingKeyV2DecryptRequest,
    current_user: Dict = Depends(_get_current_user),
):
    """Decrypt an encrypted transaction using the specified key.

    The response is scope-filtered: only fields allowed by the key's scope are returned.
    """
    mgr = _get_vk_manager()
    encrypted_data = {
        "ciphertext": req.ciphertext,
        "nonce": req.nonce,
        "tag": req.tag,
    }
    try:
        result = mgr.decrypt_transaction(req.key_id, encrypted_data)
    except ViewingKeyError as exc:
        raise HTTPException(status_code=403, detail=str(exc))
    return result


@router.delete("/viewing-keys/v2/{key_id}/revoke")
def vk_v2_revoke(
    key_id: str,
    current_user: Dict = Depends(_get_current_user),
):
    """Revoke a viewing key. If it is a master key, all derived sub-keys are also revoked."""
    mgr = _get_vk_manager()
    try:
        result = mgr.revoke_key(key_id)
    except ViewingKeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return result


@router.get("/viewing-keys/v2/{key_id}/info")
def vk_v2_info(
    key_id: str,
    current_user: Dict = Depends(_get_current_user),
):
    """Return metadata for a key (the secret is never exposed)."""
    mgr = _get_vk_manager()
    info = mgr.get_key_info(key_id)
    if info is None:
        raise HTTPException(status_code=404, detail=f"Key {key_id} not found")
    return info


@router.get("/viewing-keys/v2/{address}/audit")
def vk_v2_audit(
    address: str,
    current_user: Dict = Depends(_get_current_user),
):
    """Return the audit trail for all viewing key operations on an address."""
    mgr = _get_vk_manager()
    trail = mgr.get_audit_trail(address)
    return {"address": address, "audit_trail": trail}


# ---------------------------------------------------------------------------
# Regulatory Access Flow
# ---------------------------------------------------------------------------

@router.post("/regulatory/request-access")
def regulatory_request_access(
    req: RegulatoryRequestCreate,
    current_user: Dict = Depends(_get_current_user),
):
    """Agency submits a regulatory access request for a specific transaction.

    The request is created with status PENDING_USER_APPROVAL.
    The wallet owner must approve or deny the request separately.
    """
    rm = _get_regulatory_manager()
    try:
        result = rm.create_request(
            requester_id=req.requester_id,
            requester_type=req.requester_type,
            owner_address=req.owner_address,
            tx_hash=req.tx_hash,
            scope_requested=req.scope,
            duration_days=req.duration_days,
            legal_reference=req.legal_reference,
            reason=req.reason,
        )
    except RegulatoryFlowError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return result


@router.get("/regulatory/requests/{owner_address}")
def regulatory_list_requests(
    owner_address: str,
    current_user: Dict = Depends(_get_current_user),
):
    """List all pending regulatory access requests for a wallet owner."""
    rm = _get_regulatory_manager()
    requests = rm.list_pending_requests(owner_address)
    return {"owner_address": owner_address, "pending_requests": requests}


@router.post("/regulatory/requests/{request_id}/approve")
def regulatory_approve_request(
    request_id: str,
    req: RegulatoryRequestApprove,
    current_user: Dict = Depends(_get_current_user),
):
    """Owner approves a regulatory access request.

    The owner may grant a scope equal to or more restrictive than requested,
    and a duration equal to or shorter than requested.
    """
    rm = _get_regulatory_manager()
    try:
        result = rm.approve_request(
            request_id=request_id,
            owner_address=req.owner_address,
            approved_scope=req.scope,
            approved_duration_days=req.duration_days,
        )
    except RegulatoryFlowError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return result


@router.post("/regulatory/requests/{request_id}/deny")
def regulatory_deny_request(
    request_id: str,
    req: RegulatoryRequestDeny,
    current_user: Dict = Depends(_get_current_user),
):
    """Owner denies a regulatory access request."""
    rm = _get_regulatory_manager()
    try:
        result = rm.deny_request(
            request_id=request_id,
            owner_address=req.owner_address,
            reason=req.reason,
        )
    except RegulatoryFlowError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return result


@router.post("/regulatory/requests/{request_id}/revoke")
def regulatory_revoke_key(
    request_id: str,
    req: RegulatoryRequestRevoke,
    current_user: Dict = Depends(_get_current_user),
):
    """Owner revokes the viewing key for an already-approved request."""
    rm = _get_regulatory_manager()
    try:
        result = rm.revoke_approved_key(
            request_id=request_id,
            owner_address=req.owner_address,
        )
    except RegulatoryFlowError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return result


@router.get("/regulatory/requests/detail/{request_id}")
def regulatory_get_request(
    request_id: str,
    current_user: Dict = Depends(_get_current_user),
):
    """Return details of a specific regulatory access request."""
    rm = _get_regulatory_manager()
    result = rm.get_request(request_id)
    if result is None:
        raise HTTPException(status_code=404, detail=f"Request {request_id} not found")
    return result
