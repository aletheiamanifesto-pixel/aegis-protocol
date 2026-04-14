import hashlib
import json
import os
from pathlib import Path

import httpx

PINATA_JWT = os.getenv("PINATA_JWT", "")
PINATA_API_KEY = os.getenv("PINATA_API_KEY", "")
PINATA_SECRET_API_KEY = os.getenv("PINATA_SECRET_API_KEY", "")
_LOCAL_STORE = Path("/tmp/proofmint_ipfs")


def _local_store_data(data: dict) -> str:
    _LOCAL_STORE.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(data, sort_keys=True)
    cid = "local-" + hashlib.sha256(payload.encode()).hexdigest()
    (_LOCAL_STORE / f"{cid}.json").write_text(payload, encoding="utf-8")
    return cid


def upload_to_ipfs(data: dict) -> str:
    if PINATA_JWT or (PINATA_API_KEY and PINATA_SECRET_API_KEY):
        headers = {"Content-Type": "application/json"}
        if PINATA_JWT:
            headers["Authorization"] = f"Bearer {PINATA_JWT}"
        else:
            headers["pinata_api_key"] = PINATA_API_KEY
            headers["pinata_secret_api_key"] = PINATA_SECRET_API_KEY

        try:
            r = httpx.post(
                "https://api.pinata.cloud/pinning/pinJSONToIPFS",
                headers=headers,
                json={"pinataContent": data},
                timeout=20,
            )
            r.raise_for_status()
            return r.json().get("IpfsHash", "")
        except Exception:
            pass

    return _local_store_data(data)


def get_from_ipfs(cid: str) -> dict:
    if cid.startswith("local-"):
        local_file = _LOCAL_STORE / f"{cid}.json"
        if local_file.exists():
            return json.loads(local_file.read_text(encoding="utf-8"))
        return {}

    try:
        r = httpx.get(f"https://gateway.pinata.cloud/ipfs/{cid}", timeout=20)
        r.raise_for_status()
        return r.json()
    except Exception:
        return {}
