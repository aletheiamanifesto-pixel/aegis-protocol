#!/usr/bin/env python3
"""End-to-end smoke test against a running stack (docker compose or uvicorn).

    python scripts/e2e_smoke.py http://localhost:8000 [http://localhost:3000]

Checks the real user flow: health → register → login → link a wallet signed on the
"device" → deposit instruction (awaiting_funds) → statement → reserve → frontend reachable.
Exit code 0 only if everything passes.
"""
import secrets
import sys

import httpx
from eth_account import Account
from eth_account.messages import encode_defunct

API = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://localhost:8000"
WEB = sys.argv[2].rstrip("/") if len(sys.argv) > 2 else None


def check(cond, msg):
    if not cond:
        print(f"FAIL: {msg}")
        sys.exit(1)
    print(f"ok   {msg}")


def main():
    c = httpx.Client(base_url=API, timeout=30)
    r = c.get("/health")
    check(r.status_code == 200, f"health {r.status_code}")

    user = "smoke_" + secrets.token_hex(4)
    pw = "Sm0ke-" + secrets.token_urlsafe(12)
    r = c.post("/auth/register", json={"username": user, "email": f"{user}@example.com", "password": pw})
    check(r.status_code == 201, f"register {r.status_code} {r.text[:120]}")
    r = c.post("/auth/register", json={"username": user + "x", "email": f"{user}x@example.com", "password": "short"})
    check(r.status_code == 422, "weak password refused")

    r = c.post("/auth/login", json={"username": user, "password": pw})
    check(r.status_code == 200, f"login {r.status_code}")
    h = {"Authorization": f"Bearer {r.json()['access_token']}"}

    acct = Account.create()  # the key stays here ("device"): the server never sees it
    ch = c.post("/wallet/link/challenge", headers=h).json()
    sig = acct.sign_message(encode_defunct(text=ch["message"])).signature.hex()
    r = c.post("/wallet/link", headers=h, json={"address": acct.address, "nonce": ch["nonce"], "signature": sig})
    check(r.status_code == 200 and r.json()["address"] == acct.address, f"wallet linked by signature {r.status_code}")

    r = c.post("/banking/deposit", headers={**h, "Idempotency-Key": "smoke-1"},
               json={"amount": "25.50", "wallet_address": acct.address})
    check(r.status_code == 201 and r.json()["status"] == "awaiting_funds", f"deposit instruction {r.status_code} {r.text[:120]}")
    again = c.post("/banking/deposit", headers={**h, "Idempotency-Key": "smoke-1"},
                   json={"amount": "25.50", "wallet_address": acct.address})
    check(again.json()["operation_id"] == r.json()["operation_id"], "idempotent retry")

    r = c.get("/banking/statement", headers=h)
    check(r.status_code == 200 and len(r.json()["operations"]) == 1, "statement from the database")
    r = c.get("/banking/reserve-status")
    check(r.status_code == 200 and r.json()["total_deposits_eur"] == "0.00", "unconfirmed deposit not counted in reserves")

    other = Account.create().address
    r = c.post("/banking/deposit", headers=h, json={"amount": "1.00", "wallet_address": other})
    check(r.status_code == 403, "someone else's address refused")

    if WEB:
        r = httpx.get(WEB, timeout=30, follow_redirects=True)
        check(r.status_code == 200, f"frontend {r.status_code}")
    print("SMOKE OK")


if __name__ == "__main__":
    main()
