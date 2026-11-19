#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pool_service.py - Link between the backend and the ShieldedPool contract.

Two jobs for the regulated operator:

1. KYC CREDENTIAL ISSUANCE for the ZK circuit (`noir_circuits/spend`): signs with ECDSA-secp256k1
   Poseidon2(DOMAIN_CREDENTIAL, pseudonym, tier, jurisdiction, expiry), the same hash
   as `aegis_lib::credential` and `sdk/aegis-core.mjs`.
2. RELAYER: forwards to the contract the transactions whose proof the user generated on THEIR
   device (the server never sees spending_secret or note amounts). It pays the
   gas and receives the fee indicated in ext_data.

Configuration (env):
  POOL_ISSUER_KEY     hex private key of the KYC issuer (register it with ShieldedPool.setIssuer)
  POOL_ADDRESS        ShieldedPool address
  POOL_RELAYER_KEY    hex private key of the relayer (pays the gas)
  POOL_MIN_FEE        minimum fee in token units (default 0)
  RPC_URL, CHAIN_ID   network
Without configuration: only with AEGIS_ALLOW_MOCKS=1 (simulated keys and transactions).
"""

from __future__ import annotations

import hashlib
import os
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from eth_keys import keys

from aegis_env import mocks_allowed, require_mocks
from crypto_primitives import FIELD_PRIME, poseidon2_hash

DOMAIN_CREDENTIAL = 4
CREDENTIAL_TTL = 30 * 86_400  # short credentials: revoking = not renewing

# Bit index in the pool's jurisdiction mask (must match ShieldedPool.allowedJurisdictions).
JURISDICTIONS: Dict[str, int] = {
    "IT": 0, "DE": 1, "FR": 2, "ES": 3, "NL": 4, "BE": 5, "AT": 6, "PT": 7, "IE": 8, "FI": 9,
    "GR": 10, "LU": 11, "SI": 12, "SK": 13, "EE": 14, "LV": 15, "LT": 16, "MT": 17, "CY": 18, "HR": 19,
}


class PoolError(Exception):
    pass


_dev_keys: Dict[str, keys.PrivateKey] = {}


def _key(env: str) -> keys.PrivateKey:
    raw = os.getenv(env, "").strip().removeprefix("0x")
    if raw:
        return keys.PrivateKey(bytes.fromhex(raw))
    require_mocks(f"{env} not configured")
    if env not in _dev_keys:
        _dev_keys[env] = keys.PrivateKey(os.urandom(32))
    return _dev_keys[env]


def issuer_public_key() -> Dict[str, str]:
    pub = _key("POOL_ISSUER_KEY").public_key.to_bytes()
    return {"x": "0x" + pub[:32].hex(), "y": "0x" + pub[32:].hex(), "uncompressed": "0x04" + pub.hex()}


def credential_hash(pseudonym: int, tier: int, jurisdiction: int, expiry: int) -> int:
    return poseidon2_hash([DOMAIN_CREDENTIAL, pseudonym, tier, jurisdiction, expiry])


def issue_credential(pseudonym_hex: str, tier: int, country: Optional[str], now: Optional[int] = None) -> Dict[str, Any]:
    try:
        pseudonym = int(pseudonym_hex, 16)
    except (TypeError, ValueError):
        raise PoolError("invalid pseudonym")
    if not 0 < pseudonym < FIELD_PRIME:
        raise PoolError("pseudonym outside the field")
    if not 1 <= tier <= 3:
        raise PoolError("KYC tier not sufficient")
    if not country or country.upper() not in JURISDICTIONS:
        raise PoolError("jurisdiction not supported by the pool")
    jurisdiction = JURISDICTIONS[country.upper()]
    expiry = int(now or time.time()) + CREDENTIAL_TTL
    digest = credential_hash(pseudonym, tier, jurisdiction, expiry).to_bytes(32, "big")
    sig = _key("POOL_ISSUER_KEY").sign_msg_hash(digest)  # canonical (low-s), as the Noir circuit expects
    rs = sig.r.to_bytes(32, "big") + sig.s.to_bytes(32, "big")
    return {
        "pseudonym": "0x" + pseudonym.to_bytes(32, "big").hex(),
        "tier": tier,
        "jurisdiction": jurisdiction,
        "expiry": expiry,
        "signature": "0x" + rs.hex(),
        "issuer": issuer_public_key(),
    }


# ---------------------------------------------------------------------------
# Relayer
# ---------------------------------------------------------------------------

_POINT = [{"name": "x", "type": "uint256"}, {"name": "y", "type": "uint256"}]
POOL_ABI = [{
    "name": "transact", "type": "function", "stateMutability": "nonpayable", "outputs": [],
    "inputs": [
        {"name": "p", "type": "tuple", "components": [
            {"name": "proof", "type": "bytes"},
            {"name": "root", "type": "uint256"},
            {"name": "nullifiers", "type": "uint256[2]"},
            {"name": "outCommitments", "type": "uint256[2]"},
            {"name": "publicIn", "type": "uint64"},
            {"name": "publicOut", "type": "uint64"},
            {"name": "timestamp", "type": "uint64"},
            {"name": "issuer", "type": "tuple", "components": [{"name": "x", "type": "bytes32"}, {"name": "y", "type": "bytes32"}]},
            {"name": "taxEph", "type": "tuple", "components": _POINT},
            {"name": "taxCt", "type": "uint256[4]"},
            {"name": "amlEph", "type": "tuple", "components": _POINT},
            {"name": "amlCt", "type": "uint256[8]"},
        ]},
        {"name": "ext", "type": "tuple", "components": [
            {"name": "recipient", "type": "address"},
            {"name": "relayer", "type": "address"},
            {"name": "fee", "type": "uint64"},
            {"name": "encryptedOutput0", "type": "bytes"},
            {"name": "encryptedOutput1", "type": "bytes"},
        ]},
    ],
}]


@dataclass
class RelayResult:
    tx_hash: str
    simulated: bool


def relayer_address() -> str:
    return _key("POOL_RELAYER_KEY").public_key.to_checksum_address()


def relay(proof: Dict[str, Any], ext: Dict[str, Any]) -> RelayResult:
    """Simulate (eth_call) and then send ShieldedPool.transact signed by the relayer."""
    if ext["relayer"].lower() != relayer_address().lower():
        raise PoolError("ext_data.relayer is not this relayer")
    if int(ext["fee"]) < int(os.getenv("POOL_MIN_FEE", "0")):
        raise PoolError("fee below the relayer's minimum")
    if int(ext["fee"]) > int(proof["publicOut"]):
        raise PoolError("fee above the withdrawal")

    rpc, pool = os.getenv("RPC_URL", ""), os.getenv("POOL_ADDRESS", "")
    if not (rpc and pool):
        require_mocks("pool relay (RPC_URL/POOL_ADDRESS missing)")
        h = hashlib.sha256(repr((proof["nullifiers"], ext["recipient"])).encode()).hexdigest()
        return RelayResult("0x" + h, simulated=True)

    from web3 import Web3

    w3 = Web3(Web3.HTTPProvider(rpc))
    contract = w3.eth.contract(address=Web3.to_checksum_address(pool), abi=POOL_ABI)
    p = proof
    args = (
        (bytes.fromhex(p["proof"].removeprefix("0x")), int(p["root"]), [int(x) for x in p["nullifiers"]],
         [int(x) for x in p["outCommitments"]], int(p["publicIn"]), int(p["publicOut"]), int(p["timestamp"]),
         (bytes.fromhex(p["issuer"]["x"].removeprefix("0x")), bytes.fromhex(p["issuer"]["y"].removeprefix("0x"))),
         (int(p["taxEph"]["x"]), int(p["taxEph"]["y"])), [int(x) for x in p["taxCt"]],
         (int(p["amlEph"]["x"]), int(p["amlEph"]["y"])), [int(x) for x in p["amlCt"]]),
        (Web3.to_checksum_address(ext["recipient"]), Web3.to_checksum_address(ext["relayer"]), int(ext["fee"]),
         bytes.fromhex(ext["encryptedOutput0"].removeprefix("0x")), bytes.fromhex(ext["encryptedOutput1"].removeprefix("0x"))),
    )
    sender = relayer_address()
    fn = contract.functions.transact(*args)
    try:
        fn.call({"from": sender})  # invalid proof / nullifier already spent → no gas wasted
    except Exception as exc:  # noqa: BLE001
        raise PoolError(f"transaction rejected by the contract: {exc}")
    tx = fn.build_transaction({
        "from": sender,
        "nonce": w3.eth.get_transaction_count(sender),
        "chainId": int(os.getenv("CHAIN_ID", "80002")),
    })
    signed = w3.eth.account.sign_transaction(tx, _key("POOL_RELAYER_KEY").to_hex())
    return RelayResult(w3.eth.send_raw_transaction(signed.rawTransaction).hex(), simulated=False)


def is_configured() -> bool:
    return bool(os.getenv("POOL_ISSUER_KEY") and os.getenv("POOL_RELAYER_KEY") and os.getenv("POOL_ADDRESS")) or mocks_allowed()


__all__: List[str] = ["issue_credential", "issuer_public_key", "relay", "relayer_address", "PoolError", "JURISDICTIONS"]
