#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
routers/viewing_keys_v2.py - Viewing Keys V2 and Regulatory Access Flow endpoints.

Exposes:
  - Viewing Keys V2 (user): create master, derive sub-key, decrypt, revoke, info, audit
  - Regulatory Access Flow: request-access, list, approve, deny, details
"""

from typing import Dict

from fastapi import APIRouter, Depends, HTTPException

from routers.auth import _get_current_user
from schemas import (
    ViewingKeyV2CreateRequest,
    ViewingKeyV2DeriveRequest,
    ViewingKeyV2DecryptRequest,
    RegulatoryRequestCreate,
    RegulatoryRequestApprove,
    RegulatoryRequestDeny,
)

try:
    from viewing_keys.viewing_keys_v2 import ViewingKeyManagerV2, ViewingKeyError
    from viewing_keys.scope_filter import KeyScope
    from viewing_keys.regulatory_flow import RegulatoryAccessManager

    _vk_v2_manager = ViewingKeyManagerV2()
    _regulatory_manager = RegulatoryAccessManager(_vk_v2_manager)
    _vk_v2_available = True
except ImportError:
    _vk_v2_available = False

router = APIRouter(tags=["viewing-keys-v2"])


def _require_service() -> None:
    if not _vk_v2_available:
        raise HTTPException(status_code=503, detail="Viewing keys V2 service not available")


# ---------------------------------------------------------------------------
# Viewing Keys V2 — user-facing endpoints
# ---------------------------------------------------------------------------

@router.post("/viewing-keys/v2/create")
def vk_v2_create(
    req: ViewingKeyV2CreateRequest,
    current_user: Dict = Depends(_get_current_user),
):
    """Create a master viewing key for a wallet address."""
    _require_service()
    try:
        result = _vk_v2_manager.create_master_key(req.address)
        # Omit the raw secret from the response
        result.pop("master_secret", None)
        return result
    except ViewingKeyError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/viewing-keys/v2/derive")
def vk_v2_derive(
    req: ViewingKeyV2DeriveRequest,
    current_user: Dict = Depends(_get_current_user),
):
    """Derive a scoped sub-key from a master key."""
    _require_service()
    try:
        scope = KeyScope(req.scope)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid scope: {req.scope}")
    try:
        result = _vk_v2_manager.derive_sub_key(
            master_key_id=req.master_key_id,
            scope=scope,
            context=req.context,
            expires_in=req.expires_in,
            max_uses=req.max_uses,
        )
        # Omit the raw secret from the response
        result.pop("derived_secret", None)
        return result
    except ViewingKeyError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/viewing-keys/v2/{key_id}/decrypt")
def vk_v2_decrypt(
    key_id: str,
    req: ViewingKeyV2DecryptRequest,
    current_user: Dict = Depends(_get_current_user),
):
    """Decrypt a transaction using a viewing key (scope-filtered)."""
    _require_service()
    try:
        encrypted_data = {
            "ciphertext": req.ciphertext,
            "nonce": req.nonce,
            "tag": req.tag,
        }
        return _vk_v2_manager.decrypt_transaction(key_id, encrypted_data)
    except ViewingKeyError as exc:
        raise HTTPException(status_code=403, detail=str(exc))


@router.delete("/viewing-keys/v2/{key_id}/revoke")
def vk_v2_revoke(
    key_id: str,
    current_user: Dict = Depends(_get_current_user),
):
    """Revoke a viewing key (cascades to sub-keys if it is a master)."""
    _require_service()
    try:
        result = _vk_v2_manager.revoke_key(key_id)
        return {"message": "Key revoked", **result}
    except ViewingKeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.get("/viewing-keys/v2/{key_id}/info")
def vk_v2_info(
    key_id: str,
    current_user: Dict = Depends(_get_current_user),
):
    """Return metadata for a viewing key (no secret material)."""
    _require_service()
    info = _vk_v2_manager.get_key_info(key_id)
    if info is None:
        raise HTTPException(status_code=404, detail=f"Key {key_id} not found")
    return info


@router.get("/viewing-keys/v2/{address}/audit")
def vk_v2_audit(
    address: str,
    current_user: Dict = Depends(_get_current_user),
):
    """Return the audit trail for all operations on a wallet address."""
    _require_service()
    return {"address": address, "audit_trail": _vk_v2_manager.get_audit_trail(address)}


# ---------------------------------------------------------------------------
# Regulatory Access Flow
# ---------------------------------------------------------------------------

@router.post("/regulatory/request-access")
def regulatory_request_access(
    req: RegulatoryRequestCreate,
    current_user: Dict = Depends(_get_current_user),
):
    """Agency requests viewing-key access to a transaction (creates PENDING request)."""
    _require_service()
    try:
        scope = KeyScope(req.scope)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid scope: {req.scope}")
    try:
        result = _regulatory_manager.create_request(
            requester_id=req.requester_id,
            requester_type=req.requester_type,
            owner_address=req.owner_address,
            tx_hash=req.tx_hash,
            scope_requested=scope,
            duration_days=req.duration_days,
            legal_reference=req.legal_reference,
            reason=req.reason,
        )
        return result
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/regulatory/requests/{owner_address}")
def regulatory_list_pending(
    owner_address: str,
    current_user: Dict = Depends(_get_current_user),
):
    """List all PENDING regulatory access requests for a wallet address."""
    _require_service()
    return {
        "owner_address": owner_address,
        "pending_requests": _regulatory_manager.list_pending_requests(owner_address),
    }


@router.post("/regulatory/requests/{request_id}/approve")
def regulatory_approve(
    request_id: str,
    req: RegulatoryRequestApprove,
    current_user: Dict = Depends(_get_current_user),
):
    """Owner approves a regulatory access request (creates scoped sub-key)."""
    _require_service()
    try:
        scope = KeyScope(req.scope)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid scope: {req.scope}")
    try:
        result = _regulatory_manager.approve_request(
            request_id=request_id,
            owner_address=req.owner_address,
            approved_scope=scope,
            approved_duration_days=req.duration_days,
        )
        return result
    except (ValueError, ViewingKeyError) as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/regulatory/requests/{request_id}/deny")
def regulatory_deny(
    request_id: str,
    req: RegulatoryRequestDeny,
    current_user: Dict = Depends(_get_current_user),
):
    """Owner denies a regulatory access request."""
    _require_service()
    try:
        result = _regulatory_manager.deny_request(
            request_id=request_id,
            owner_address=req.owner_address,
            reason=req.reason,
        )
        return result
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/regulatory/requests/detail/{request_id}")
def regulatory_get_request(
    request_id: str,
    current_user: Dict = Depends(_get_current_user),
):
    """Return details of a specific regulatory access request."""
    _require_service()
    result = _regulatory_manager.get_request(request_id)
    if result is None:
        raise HTTPException(status_code=404, detail=f"Request {request_id} not found")
    return result
