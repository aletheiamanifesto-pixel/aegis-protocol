#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
aegis_env.py - Runtime settings that must never fall back silently to insecure values.

  AEGIS_ALLOW_MOCKS=1         simulated chain, transactions, bridge and wallet allowed
                              (local development and tests ONLY). Without it, a missing
                              chain/library is an error, never a fake "successful" result.
  AEGIS_ALLOW_MOCK_PROOFS=1   fake ZK proofs allowed (see noir_bridge.py).
  SECRET_KEY                  required outside development; known placeholders are refused.
"""

from __future__ import annotations

import logging
import os
import secrets

logger = logging.getLogger(__name__)

_TRUE = {"1", "true", "yes"}
_INSECURE_SECRETS = {
    "",
    "change-me",
    "change-me-in-production",
    "aegis-dev-secret-key-32bytes!!!",
}
_dev_secret: str | None = None


class InsecureConfigError(RuntimeError):
    pass


def mocks_allowed() -> bool:
    return os.getenv("AEGIS_ALLOW_MOCKS", "").strip().lower() in _TRUE


def require_mocks(what: str) -> None:
    """Call before returning a simulated result: fails unless mocks are explicitly allowed."""
    if not mocks_allowed():
        raise InsecureConfigError(f"{what} unavailable and simulation disabled (set AEGIS_ALLOW_MOCKS=1 only in development)")
    logger.warning("[DEV MOCK] %s simulated", what)


def get_secret_key() -> str:
    """SECRET_KEY from the environment. In development (AEGIS_ALLOW_MOCKS=1) without a key,
    a random per-process key is generated (tokens die on restart); otherwise it is an error."""
    global _dev_secret
    key = os.getenv("SECRET_KEY", "").strip()
    if key not in _INSECURE_SECRETS and len(key) >= 32:
        return key
    if mocks_allowed():
        if _dev_secret is None:
            _dev_secret = secrets.token_urlsafe(48)
            logger.warning("SECRET_KEY missing or weak: using a random development key")
        return _dev_secret
    raise InsecureConfigError("SECRET_KEY missing, too short (<32 characters) or a known placeholder")
