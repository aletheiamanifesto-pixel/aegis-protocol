#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
routers/auth.py - Authentication endpoints and helpers for AEGIS Protocol.
"""

import os
from datetime import datetime, timedelta
from typing import Dict, Optional

from dotenv import load_dotenv
from fastapi import APIRouter, Depends, HTTPException, Request
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from schemas import LoginRequest, RegisterRequest

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY", "change-me-in-production")
ALGORITHM = "HS256"
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


def _create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode["exp"] = expire
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def _get_current_user(request: Request, db: Session = Depends(get_db)) -> Dict:
    token = request.headers.get("Authorization", "").removeprefix("Bearer ").strip()
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid token")
        return {"user_id": user_id, "username": payload.get("username", "")}
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


# ---------------------------------------------------------------------------
# Auth endpoints
# ---------------------------------------------------------------------------

@router.post("/auth/register", status_code=201)
def register(req: RegisterRequest, db: Session = Depends(get_db)):
    if not _db_available or db is None:
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
def login(req: LoginRequest, db: Session = Depends(get_db)):
    if not _db_available or db is None:
        token = _create_access_token({"sub": req.username, "username": req.username})
        return {"access_token": token, "token_type": "bearer"}

    user = db.query(db_models.User).filter(db_models.User.username == req.username).first()
    if not user or not _verify_password(req.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = _create_access_token({"sub": str(user.id), "username": user.username})
    return {"access_token": token, "token_type": "bearer"}
