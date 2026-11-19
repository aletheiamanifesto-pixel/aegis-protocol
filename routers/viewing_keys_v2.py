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

from fastapi import APIRouter, Depends, HTTPException

from routers.auth import _get_current_user
from security import get_db, has_role, owns_address, require_owner, require_roles
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

# Managers are created PER REQUEST on the database session: state survives restarts and
# is shared across instances. Without a database, in-memory only in development.
_dev_vk_manager: "ViewingKeyManagerV2 | None" = None
_dev_regulatory_manager: "RegulatoryAccessManager | None" = None


def get_vk_manager(db=Depends(get_db)) -> "ViewingKeyManagerV2":
    global _dev_vk_manager
    if not _vk_v2_available:
        raise HTTPException(status_code=503, detail="Viewing Keys V2 service not available")
    if db is not None:
        from viewing_keys.persistence import persistent_vk_manager

        return persistent_vk_manager(db)
    from aegis_env import mocks_allowed

    if not mocks_allowed():
        raise HTTPException(status_code=503, detail="Database unavailable")
    if _dev_vk_manager is None:
        _dev_vk_manager = ViewingKeyManagerV2()
    return _dev_vk_manager


def get_regulatory_manager(db=Depends(get_db), vk=Depends(get_vk_manager)) -> "RegulatoryAccessManager":
    global _dev_regulatory_manager
    if db is not None:
        from viewing_keys.persistence import persistent_regulatory_manager

        return persistent_regulatory_manager(db, vk)
    if _dev_regulatory_manager is None:
        _dev_regulatory_manager = RegulatoryAccessManager(vk)
    return _dev_regulatory_manager


router = APIRouter(tags=["viewing-keys-v2"])


# ---------------------------------------------------------------------------
# Authorization helpers
# ---------------------------------------------------------------------------

def _key_address(mgr, key_id: str) -> str:
    info = mgr.get_key_info(key_id)
    if info is None:
        raise HTTPException(status_code=404, detail=f"Key {key_id} not found")
    return info["address"]


def _authority_holds_key(rm, user: Dict, key_id: str) -> bool:
    """An authority may use a key only if it was issued for ITS request, once approved."""
    if not has_role(user, "authority"):
        return False
    for req in rm._requests.values():  # noqa: SLF001
        if req.viewing_key_id == key_id and req.requester_id == user["user_id"] and req.status.value == "approved":
            return True
    return False


def _request_or_404(rm, request_id: str) -> Dict:
    detail = rm.get_request(request_id)
    if detail is None:
        raise HTTPException(status_code=404, detail="Request not found")
    return detail


# ---------------------------------------------------------------------------
# Viewing Keys V2 — user-facing
# ---------------------------------------------------------------------------

@router.post("/viewing-keys/v2/create")
def vk_v2_create(
    req: ViewingKeyV2CreateRequest,
    current_user: Dict = Depends(_get_current_user),
    db=Depends(get_db),
    mgr=Depends(get_vk_manager),
    rm=Depends(get_regulatory_manager),
):
    """Create a master viewing key for a wallet address."""
    require_owner(db, current_user, req.address)
    try:
        result = mgr.create_master_key(req.address)
    except ViewingKeyError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return result


@router.post("/viewing-keys/v2/derive")
def vk_v2_derive(
    req: ViewingKeyV2DeriveRequest,
    current_user: Dict = Depends(_get_current_user),
    db=Depends(get_db),
    mgr=Depends(get_vk_manager),
    rm=Depends(get_regulatory_manager),
):
    """Derive a sub-key from a master key with the given scope and optional expiry."""
    require_owner(db, current_user, _key_address(mgr, req.master_key_id))
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
    db=Depends(get_db),
    mgr=Depends(get_vk_manager),
    rm=Depends(get_regulatory_manager),
):
    """Decrypt an encrypted transaction using the specified key.

    The response is scope-filtered: only fields allowed by the key's scope are returned.
    """
    if not (owns_address(db, current_user, _key_address(mgr, req.key_id)) or _authority_holds_key(rm, current_user, req.key_id)):
        raise HTTPException(status_code=403, detail="Key not usable by this user")
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
    db=Depends(get_db),
    mgr=Depends(get_vk_manager),
    rm=Depends(get_regulatory_manager),
):
    """Revoke a viewing key. If it is a master key, all derived sub-keys are also revoked."""
    require_owner(db, current_user, _key_address(mgr, key_id))
    try:
        result = mgr.revoke_key(key_id)
    except ViewingKeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return result


@router.get("/viewing-keys/v2/{key_id}/info")
def vk_v2_info(
    key_id: str,
    current_user: Dict = Depends(_get_current_user),
    db=Depends(get_db),
    mgr=Depends(get_vk_manager),
    rm=Depends(get_regulatory_manager),
):
    """Return metadata for a key (the secret is never exposed)."""
    info = mgr.get_key_info(key_id)
    if info is None:
        raise HTTPException(status_code=404, detail=f"Key {key_id} not found")
    if not (owns_address(db, current_user, info["address"]) or _authority_holds_key(rm, current_user, key_id)
            or has_role(current_user, "compliance", "admin")):
        raise HTTPException(status_code=403, detail="Key not visible to this user")
    return info


@router.get("/viewing-keys/v2/{address}/audit")
def vk_v2_audit(
    address: str,
    current_user: Dict = Depends(_get_current_user),
    db=Depends(get_db),
    mgr=Depends(get_vk_manager),
    rm=Depends(get_regulatory_manager),
):
    """Return the audit trail for all viewing key operations on an address."""
    require_owner(db, current_user, address, also_roles=("compliance", "admin"))
    trail = mgr.get_audit_trail(address)
    return {"address": address, "audit_trail": trail}


# ---------------------------------------------------------------------------
# Regulatory Access Flow
# ---------------------------------------------------------------------------

@router.post("/regulatory/request-access")
def regulatory_request_access(
    req: RegulatoryRequestCreate,
    current_user: Dict = Depends(require_roles("authority")),
    rm=Depends(get_regulatory_manager),
):
    """Agency submits a regulatory access request for a specific transaction.

    The request is created with status PENDING_USER_APPROVAL.
    The wallet owner must approve or deny the request separately.
    """
    try:
        result = rm.create_request(
            # Who is requesting comes from the account, NEVER from the body: you cannot claim to be the UIF.
            requester_id=current_user["user_id"],
            requester_type=current_user["authority_type"],
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
    db=Depends(get_db),
    mgr=Depends(get_vk_manager),
    rm=Depends(get_regulatory_manager),
):
    """List all pending regulatory access requests for a wallet owner."""
    require_owner(db, current_user, owner_address, also_roles=("compliance", "admin"))
    requests = rm.list_pending_requests(owner_address)
    return {"owner_address": owner_address, "pending_requests": requests}


@router.post("/regulatory/requests/{request_id}/approve")
def regulatory_approve_request(
    request_id: str,
    req: RegulatoryRequestApprove,
    current_user: Dict = Depends(_get_current_user),
    db=Depends(get_db),
    mgr=Depends(get_vk_manager),
    rm=Depends(get_regulatory_manager),
):
    """Owner approves a regulatory access request.

    The owner may grant a scope equal to or more restrictive than requested,
    and a duration equal to or shorter than requested.
    """
    # Only the real owner of the address in the request decides (not whoever writes it in the body).
    detail = _request_or_404(rm, request_id)
    if req.owner_address.lower() != detail["owner_address"].lower():
        raise HTTPException(status_code=403, detail="owner_address does not match the request")
    require_owner(db, current_user, detail["owner_address"])
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
    db=Depends(get_db),
    mgr=Depends(get_vk_manager),
    rm=Depends(get_regulatory_manager),
):
    """Owner denies a regulatory access request."""
    # Only the real owner of the address in the request decides (not whoever writes it in the body).
    detail = _request_or_404(rm, request_id)
    if req.owner_address.lower() != detail["owner_address"].lower():
        raise HTTPException(status_code=403, detail="owner_address does not match the request")
    require_owner(db, current_user, detail["owner_address"])
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
    db=Depends(get_db),
    mgr=Depends(get_vk_manager),
    rm=Depends(get_regulatory_manager),
):
    """Owner revokes the viewing key for an already-approved request."""
    # Only the real owner of the address in the request decides (not whoever writes it in the body).
    detail = _request_or_404(rm, request_id)
    if req.owner_address.lower() != detail["owner_address"].lower():
        raise HTTPException(status_code=403, detail="owner_address does not match the request")
    require_owner(db, current_user, detail["owner_address"])
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
    db=Depends(get_db),
    mgr=Depends(get_vk_manager),
    rm=Depends(get_regulatory_manager),
):
    """Return details of a specific regulatory access request (owner, requesting authority, compliance)."""
    result = _request_or_404(rm, request_id)
    allowed = (
        owns_address(db, current_user, result["owner_address"])
        or (has_role(current_user, "authority") and result["requester_id"] == current_user["user_id"])
        or has_role(current_user, "compliance", "admin")
    )
    if not allowed:
        raise HTTPException(status_code=403, detail="Request not visible to this user")
    return result
