#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
main_app.py - FastAPI application for AEGIS Protocol.

This module wires together all sub-routers.  Business logic and Pydantic
models live in the respective routers/ modules and schemas.py.
"""

import os

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

load_dotenv()

CORS_ORIGINS = os.getenv("CORS_ORIGINS", "http://localhost:3000").split(",")

try:
    from db import get_db, init_db
    _db_available = True
except ImportError:
    _db_available = False

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

app = FastAPI(
    title="AEGIS Protocol API",
    description="Math-based decentralized bank with EUR token, wallet and payment system",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


from fastapi.responses import JSONResponse  # noqa: E402

from aegis_env import InsecureConfigError  # noqa: E402


@app.exception_handler(InsecureConfigError)
def _unavailable(_request, exc: InsecureConfigError):
    """A required service (chain, oracle, keys) is unavailable and simulation is off: 503, not fake data."""
    return JSONResponse(status_code=503, content={"detail": f"Service unavailable: {exc}"})


@app.on_event("startup")
def startup():
    # The schema is managed by migrations (alembic upgrade head). Only in local
    # development (AEGIS_ALLOW_MOCKS=1) are tables created automatically.
    from aegis_env import mocks_allowed

    if _db_available and mocks_allowed():
        # A broken database must stop startup, not leave the app running "half-way".
        init_db()


# ---------------------------------------------------------------------------
# Routers
# ---------------------------------------------------------------------------

from routers.auth import router as auth_router
from routers.banking import router as banking_router
from routers.bridge import router as bridge_router
from routers.pool import router as pool_router
from routers.compliance import router as compliance_router
from routers.oracle import router as oracle_router
from routers.reporting import router as reporting_router
from routers.settlement import router as settlement_router
from routers.transactions import router as transactions_router
from routers.viewing_keys_v2 import router as viewing_keys_v2_router
from routers.wallet import router as wallet_router
from proofmint.router import router as proofmint_router

app.include_router(auth_router)
app.include_router(wallet_router)
app.include_router(transactions_router)
app.include_router(compliance_router)
app.include_router(viewing_keys_v2_router)
app.include_router(banking_router)
app.include_router(settlement_router)
app.include_router(oracle_router)
app.include_router(reporting_router)
app.include_router(bridge_router)
app.include_router(pool_router)
app.include_router(proofmint_router)


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

@app.get("/health")
def health():
    _bo_available = True  # banking_operations is a hard dependency (DB-backed)
    from routers.bridge import _bridge_available
    from routers.compliance import _ce_available
    from routers.oracle import _oracle_available
    from routers.reporting import _reporting_available
    from routers.settlement import _settlement_available
    from routers.transactions import _tp_available
    from routers.viewing_keys_v2 import _vk_v2_available
    from routers.wallet import _ws_available

    return {
        "status": "ok",
        "version": "0.1.0",
        "services": {
            "database": _db_available,
            "compliance_engine": _ce_available,
            "transaction_processor": _tp_available,
            "wallet_service": _ws_available,
            "banking_operations": _bo_available,
            "viewing_keys_v2": _vk_v2_available,
            "settlement": _settlement_available,
            "oracle": _oracle_available,
            "reporting": _reporting_available,
            "bridge": _bridge_available,
        },
    }
