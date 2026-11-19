#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
security.py - Authentication and authorization for the AEGIS API.

Rules:
  * the identity comes ONLY from the token, and is reloaded from the database on every
    request (deactivated user or revoked token → 401);
  * roles: "user" (default), "compliance", "authority", "admin". Assigned only by an admin;
  * an address can be used only by its owner (Wallet.user_id), never because
    it was written in the request body.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Callable, Dict, Iterable, Optional

from fastapi import Depends, HTTPException, Request
from jose import JWTError, jwt

from aegis_env import get_secret_key, mocks_allowed

SECRET_KEY = get_secret_key()
ALGORITHM = "HS256"

ROLES = {"user", "compliance", "authority", "admin"}
AUTHORITY_TYPES = {"uif", "guardia_finanza", "tax_authority", "judicial_authority", "esma", "aml_authority"}

LOGIN_MAX_FAILURES = 5
LOGIN_WINDOW = timedelta(minutes=15)

try:
    from db import get_db
    import db_models

    _db_available = True
except ImportError:  # pragma: no cover
    _db_available = False

    def get_db():
        yield None


def create_access_token(user, expires_minutes: int) -> str:
    payload = {
        "sub": str(user.id),
        "username": user.username,
        "tv": int(user.token_version or 0),
        "exp": datetime.utcnow() + timedelta(minutes=expires_minutes),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def _user_dict(user) -> Dict:
    return {
        "user_id": str(user.id),
        "username": user.username,
        "role": user.role or "user",
        "authority_type": user.authority_type,
    }


def get_current_user(request: Request, db=Depends(get_db)) -> Dict:
    token = request.headers.get("Authorization", "").removeprefix("Bearer ").strip()
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    sub = payload.get("sub")
    if not sub:
        raise HTTPException(status_code=401, detail="Invalid token")

    if not _db_available or db is None:
        if not mocks_allowed():
            raise HTTPException(status_code=503, detail="User database unavailable")
        return {"user_id": str(sub), "username": payload.get("username", ""), "role": "user", "authority_type": None}

    try:
        user = db.get(db_models.User, int(sub))
    except (TypeError, ValueError):
        user = None
    if user is None or not user.is_active:
        raise HTTPException(status_code=401, detail="Invalid token")
    if int(payload.get("tv", -1)) != int(user.token_version or 0):
        raise HTTPException(status_code=401, detail="Token revoked")
    return _user_dict(user)


def require_roles(*roles: str) -> Callable:
    allowed = set(roles)

    def dep(current_user: Dict = Depends(get_current_user)) -> Dict:
        if current_user.get("role") not in allowed:
            raise HTTPException(status_code=403, detail="Operation not allowed for this role")
        return current_user

    return dep


def has_role(user: Dict, *roles: str) -> bool:
    return user.get("role") in roles


def owned_addresses(db, user: Dict) -> set:
    if not _db_available or db is None:
        return set()
    rows = db.query(db_models.Wallet.address).filter(db_models.Wallet.user_id == int(user["user_id"])).all()
    return {r[0].lower() for r in rows}


def owns_address(db, user: Dict, address: Optional[str]) -> bool:
    return bool(address) and address.lower() in owned_addresses(db, user)


def require_owner(db, user: Dict, address: Optional[str], *, also_roles: Iterable[str] = ()) -> None:
    """403 unless `user` owns `address` (or has one of `also_roles`, e.g. compliance for reading)."""
    if owns_address(db, user, address):
        return
    if also_roles and has_role(user, *also_roles):
        return
    raise HTTPException(status_code=403, detail="Address not owned by the authenticated user")


# ---------------------------------------------------------------------------
# Brute-force protection
# ---------------------------------------------------------------------------

def check_login_allowed(db, username: str, ip: Optional[str]) -> None:
    if not _db_available or db is None:
        return
    since = datetime.utcnow() - LOGIN_WINDOW
    q = db.query(db_models.LoginAttempt).filter(
        db_models.LoginAttempt.success.is_(False), db_models.LoginAttempt.created_at >= since
    )
    by_user = q.filter(db_models.LoginAttempt.username == username).count()
    by_ip = q.filter(db_models.LoginAttempt.ip_address == ip).count() if ip else 0
    if by_user >= LOGIN_MAX_FAILURES or by_ip >= LOGIN_MAX_FAILURES * 4:
        raise HTTPException(status_code=429, detail="Too many failed attempts: try again in 15 minutes")


def record_login(db, username: str, ip: Optional[str], success: bool) -> None:
    if not _db_available or db is None:
        return
    db.add(db_models.LoginAttempt(username=username, ip_address=ip, success=success))
    if success:
        # a successful login clears the failures counted for this user
        db.query(db_models.LoginAttempt).filter(
            db_models.LoginAttempt.username == username, db_models.LoginAttempt.success.is_(False)
        ).delete(synchronize_session=False)
    db.commit()
