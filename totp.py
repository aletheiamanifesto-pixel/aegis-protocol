#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""totp.py - Two-factor codes (RFC 6238: HMAC-SHA1, 30 s, 6 digits), compatible with
Google Authenticator, Authy, 1Password, etc. Each code can be used only once."""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import struct
import time
from typing import Optional
from urllib.parse import quote

STEP = 30
DIGITS = 6


def new_secret() -> str:
    return base64.b32encode(os.urandom(20)).decode().rstrip("=")


def _code(secret_b32: str, counter: int) -> str:
    key = base64.b32decode(secret_b32 + "=" * (-len(secret_b32) % 8), casefold=True)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(value % 10 ** DIGITS).zfill(DIGITS)


def code_at(secret_b32: str, t: float) -> str:
    return _code(secret_b32, int(t // STEP))


def verify(secret_b32: str, code: str, *, last_step: Optional[int] = None, now: Optional[float] = None,
           window: int = 1) -> Optional[int]:
    """Return the step used if the code is valid (and newer than last_step), otherwise None."""
    if not code or not code.isdigit() or len(code) != DIGITS:
        return None
    current = int((now if now is not None else time.time()) // STEP)
    for step in range(current - window, current + window + 1):
        if last_step is not None and step <= last_step:
            continue  # the same code (or an older one) cannot be reused
        if hmac.compare_digest(_code(secret_b32, step), code):
            return step
    return None


def provisioning_uri(secret_b32: str, account: str, issuer: str = "AEGIS") -> str:
    return f"otpauth://totp/{quote(issuer)}:{quote(account)}?secret={secret_b32}&issuer={quote(issuer)}&digits={DIGITS}&period={STEP}"
