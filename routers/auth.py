#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
routers/auth.py - Authentication endpoints and helpers for AEGIS Protocol.
"""

import os
from typing import Dict, Optional

from dotenv import load_dotenv
from fastapi import APIRouter, Depends, HTTPException, Request
from passlib.context import CryptContext
from pydantic import BaseModel
from sqlalchemy.orm import Session

from schemas import LoginRequest, RegisterRequest

load_dotenv()

from aegis_env import mocks_allowed
from security import (
    AUTHORITY_TYPES,
    ROLES,
    SECRET_KEY,  # noqa: F401 - re-exported for backwards compatibility
    check_login_allowed,
    create_access_token,
    get_current_user,
    record_login,
    require_roles,
)

ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))

try:
    from db import get_db
    import db_models
    _db_available = True
except ImportError:
    _db_available = False

    def get_db():
        yield None

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

router = APIRouter(tags=["auth"])


# ---------------------------------------------------------------------------
# Auth helpers (importable by other routers)
# ---------------------------------------------------------------------------

def _hash_password(password: str) -> str:
    return pwd_context.hash(password)


def _verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


# Historical name used by every router: identity always comes from the token + database.
_get_current_user = get_current_user


# ---------------------------------------------------------------------------
# Auth endpoints
# ---------------------------------------------------------------------------

@router.post("/auth/register", status_code=201)
def register(req: RegisterRequest, db: Session = Depends(get_db)):
    if not _db_available or db is None:
        if not mocks_allowed():
            raise HTTPException(status_code=503, detail="User database unavailable")
        return {"message": "User registered (dev mode)", "username": req.username}

    existing = db.query(db_models.User).filter(
        (db_models.User.username == req.username) | (db_models.User.email == req.email)
    ).first()
    if existing:
        raise HTTPException(status_code=400, detail="Username or email already registered")

    user = db_models.User(
        username=req.username,
        email=req.email,
        hashed_password=_hash_password(req.password),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return {"message": "User registered successfully", "user_id": user.id, "username": user.username}


@router.post("/auth/login")
def login(req: LoginRequest, request: Request, db: Session = Depends(get_db)):
    if not _db_available or db is None:
        # Without a database there is no way to check the password: never issue a token.
        raise HTTPException(status_code=503, detail="User database unavailable")

    ip = request.client.host if request.client else None
    check_login_allowed(db, req.username, ip)
    user = db.query(db_models.User).filter(db_models.User.username == req.username).first()
    if not user or not user.is_active or not _verify_password(req.password, user.hashed_password):
        record_login(db, req.username, ip, success=False)
        raise HTTPException(status_code=401, detail="Invalid credentials")

    record_login(db, req.username, ip, success=True)
    token = create_access_token(user, ACCESS_TOKEN_EXPIRE_MINUTES)
    return {"access_token": token, "token_type": "bearer"}


@router.post("/auth/logout")
def logout(current_user: Dict = Depends(get_current_user), db: Session = Depends(get_db)):
    """Invalidate ALL of the user's tokens (bumps token_version)."""
    user = db.get(db_models.User, int(current_user["user_id"]))
    user.token_version = int(user.token_version or 0) + 1
    db.commit()
    return {"message": "Logged out: all tokens revoked"}


@router.get("/auth/me")
def me(current_user: Dict = Depends(get_current_user)):
    return current_user


class RoleUpdate(BaseModel):
    role: str
    authority_type: Optional[str] = None


@router.post("/admin/users/{user_id}/role")
def set_role(
    user_id: int,
    req: RoleUpdate,
    admin: Dict = Depends(require_roles("admin")),
    db: Session = Depends(get_db),
):
    """Only an admin assigns roles. Changing the role revokes the user's tokens."""
    if req.role not in ROLES:
        raise HTTPException(status_code=400, detail=f"Invalid role: {req.role}")
    if req.role == "authority" and req.authority_type not in AUTHORITY_TYPES:
        raise HTTPException(status_code=400, detail="An authority needs a valid authority_type")
    user = db.get(db_models.User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    user.role = req.role
    user.authority_type = req.authority_type if req.role == "authority" else None
    user.token_version = int(user.token_version or 0) + 1
    db.add(db_models.AuditLog(user_id=int(admin["user_id"]), action="set_role",
                              details={"target_user": user_id, "role": req.role, "authority_type": user.authority_type}))
    db.commit()
    return {"user_id": user_id, "role": user.role, "authority_type": user.authority_type}
