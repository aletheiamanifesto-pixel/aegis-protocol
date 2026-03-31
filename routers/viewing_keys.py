#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
routers/viewing_keys.py - Viewing key endpoints for AEGIS Protocol.
"""

from typing import Dict

from fastapi import APIRouter, Depends, HTTPException, Request

from routers.auth import _get_current_user
from schemas import ViewingKeyCreateRequest, ViewingKeyGrantRequest, ViewingKeyRedeemRequest

try:
    from viewing_keys_service import (
        create_viewing_key,
        grant_access,
        redeem_viewing_key,
        revoke_viewing_key,
        get_active_keys,
        ViewingKeyError,
    )
    _vk_available = True
except ImportError:
    _vk_available = False

router = APIRouter(tags=["viewing-keys"])


@router.post("/viewing-keys/create")
def viewing_keys_create(
    req: ViewingKeyCreateRequest,
    current_user: Dict = Depends(_get_current_user),
):
    if not _vk_available:
        raise HTTPException(status_code=503, detail="Viewing keys service not available")
    from models import ScopeType
    try:
        scope = ScopeType(req.scope)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid scope: {req.scope}")
    perm = create_viewing_key(req.owner_address, scope, req.duration_days)
    return perm.dict()


@router.post("/viewing-keys/grant")
def viewing_keys_grant(
    req: ViewingKeyGrantRequest,
    current_user: Dict = Depends(_get_current_user),
):
    if not _vk_available:
        raise HTTPException(status_code=503, detail="Viewing keys service not available")
    from models import ScopeType
    try:
        scope = ScopeType(req.scope)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid scope: {req.scope}")
    perm = grant_access(req.owner_address, req.grantee, scope, req.duration_days)
    return perm.dict()


@router.post("/viewing-keys/{key_id}/redeem")
def viewing_keys_redeem(
    key_id: str,
    req: ViewingKeyRedeemRequest,
    request: Request,
    current_user: Dict = Depends(_get_current_user),
):
    if not _vk_available:
        raise HTTPException(status_code=503, detail="Viewing keys service not available")
    try:
        ip = request.client.host if request.client else None
        result = redeem_viewing_key(key_id, req.grantee, ip)
        return result
    except ViewingKeyError as e:
        raise HTTPException(status_code=403, detail=str(e))


@router.delete("/viewing-keys/{key_id}/revoke")
def viewing_keys_revoke(key_id: str, current_user: Dict = Depends(_get_current_user)):
    if not _vk_available:
        raise HTTPException(status_code=503, detail="Viewing keys service not available")
    try:
        revoke_viewing_key(key_id, revoker=current_user["user_id"])
        return {"message": "Viewing key revoked", "key_id": key_id}
    except ViewingKeyError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.get("/viewing-keys/{owner}/active")
def viewing_keys_active(owner: str, current_user: Dict = Depends(_get_current_user)):
    if not _vk_available:
        raise HTTPException(status_code=503, detail="Viewing keys service not available")
    keys = get_active_keys(owner)
    return {"owner": owner, "active_keys": [k.dict() for k in keys]}
