import hashlib
import json
import logging
import os
import time

from web3 import Web3

PROOFMINT_REGISTRY_ADDRESS = os.getenv("PROOFMINT_REGISTRY_ADDRESS", "")
PROOFMINT_PRIVATE_KEY = os.getenv("PROOFMINT_PRIVATE_KEY", "")
RPC_URL = os.getenv("RPC_URL", "")
CHAIN_ID = int(os.getenv("CHAIN_ID", "80002"))

_PROOFMINT_ABI_MINIMAL = [
    {
        "name": "createPassport",
        "type": "function",
        "inputs": [
            {"name": "productId", "type": "string"},
            {"name": "dppHash", "type": "bytes32"},
            {"name": "ipfsCid", "type": "string"},
        ],
        "outputs": [{"name": "", "type": "uint256"}],
        "stateMutability": "nonpayable",
    },
    {
        "name": "updatePassport",
        "type": "function",
        "inputs": [
            {"name": "id", "type": "uint256"},
            {"name": "newDppHash", "type": "bytes32"},
            {"name": "newIpfsCid", "type": "string"},
        ],
        "outputs": [],
        "stateMutability": "nonpayable",
    },
    {
        "name": "verifyPassport",
        "type": "function",
        "inputs": [
            {"name": "id", "type": "uint256"},
            {"name": "expectedHash", "type": "bytes32"},
        ],
        "outputs": [{"name": "", "type": "bool"}],
        "stateMutability": "view",
    },
]
logger = logging.getLogger(__name__)


def _mock_tx_hash(payload: dict) -> str:
    from aegis_env import require_mocks

    require_mocks("ProofMint on-chain write")
    raw = json.dumps(payload, sort_keys=True).encode()
    return "0x" + hashlib.sha256(raw + str(time.time()).encode()).hexdigest()


def _web3() -> Web3:
    return Web3(Web3.HTTPProvider(RPC_URL))


def _contract(w3: Web3):
    return w3.eth.contract(
        address=Web3.to_checksum_address(PROOFMINT_REGISTRY_ADDRESS),
        abi=_PROOFMINT_ABI_MINIMAL,
    )


def create_passport_onchain(product_id: str, dpp_hash: str, ipfs_cid: str) -> str:
    if not (RPC_URL and PROOFMINT_REGISTRY_ADDRESS and PROOFMINT_PRIVATE_KEY):
        return _mock_tx_hash({"op": "create", "product_id": product_id, "dpp_hash": dpp_hash, "ipfs_cid": ipfs_cid})

    try:
        w3 = _web3()
        if not w3.is_connected():
            raise RuntimeError("Web3 not connected")

        acct = w3.eth.account.from_key(PROOFMINT_PRIVATE_KEY)
        contract = _contract(w3)

        dpp_hash_bytes = Web3.to_bytes(hexstr=dpp_hash)
        tx = contract.functions.createPassport(product_id, dpp_hash_bytes, ipfs_cid).build_transaction(
            {
                "from": acct.address,
                "nonce": w3.eth.get_transaction_count(acct.address),
                "chainId": CHAIN_ID,
                "gas": 350000,
                "maxFeePerGas": w3.eth.gas_price * 2,
                "maxPriorityFeePerGas": w3.to_wei(1, "gwei"),
            }
        )
        signed = w3.eth.account.sign_transaction(tx, PROOFMINT_PRIVATE_KEY)
        tx_hash = w3.eth.send_raw_transaction(signed.rawTransaction)
        return tx_hash.hex()
    except Exception:
        logger.exception("ProofMint createPassport on-chain call failed, using mock tx hash")
        return _mock_tx_hash({"op": "create", "product_id": product_id, "dpp_hash": dpp_hash, "ipfs_cid": ipfs_cid})


def verify_passport_onchain(passport_id: int, expected_hash: str) -> bool:
    if not (RPC_URL and PROOFMINT_REGISTRY_ADDRESS):
        from aegis_env import require_mocks

        require_mocks("ProofMint on-chain verification")
        return True

    try:
        w3 = _web3()
        if not w3.is_connected():
            raise RuntimeError("Web3 not connected")
        contract = _contract(w3)
        expected_hash_bytes = Web3.to_bytes(hexstr=expected_hash)
        return bool(contract.functions.verifyPassport(passport_id, expected_hash_bytes).call())
    except Exception:
        logger.exception("ProofMint verifyPassport on-chain call failed")
        from aegis_env import mocks_allowed

        # Verification NEVER passes by default on an error: only in explicit development.
        return mocks_allowed()


def update_passport_onchain(passport_id: int, new_hash: str, new_ipfs_cid: str) -> str:
    if not (RPC_URL and PROOFMINT_REGISTRY_ADDRESS and PROOFMINT_PRIVATE_KEY):
        return _mock_tx_hash({"op": "update", "passport_id": passport_id, "new_hash": new_hash, "new_ipfs_cid": new_ipfs_cid})

    try:
        w3 = _web3()
        if not w3.is_connected():
            raise RuntimeError("Web3 not connected")

        acct = w3.eth.account.from_key(PROOFMINT_PRIVATE_KEY)
        contract = _contract(w3)

        new_hash_bytes = Web3.to_bytes(hexstr=new_hash)
        tx = contract.functions.updatePassport(passport_id, new_hash_bytes, new_ipfs_cid).build_transaction(
            {
                "from": acct.address,
                "nonce": w3.eth.get_transaction_count(acct.address),
                "chainId": CHAIN_ID,
                "gas": 350000,
                "maxFeePerGas": w3.eth.gas_price * 2,
                "maxPriorityFeePerGas": w3.to_wei(1, "gwei"),
            }
        )
        signed = w3.eth.account.sign_transaction(tx, PROOFMINT_PRIVATE_KEY)
        tx_hash = w3.eth.send_raw_transaction(signed.rawTransaction)
        return tx_hash.hex()
    except Exception:
        logger.exception("ProofMint updatePassport on-chain call failed, using mock tx hash")
        return _mock_tx_hash({"op": "update", "passport_id": passport_id, "new_hash": new_hash, "new_ipfs_cid": new_ipfs_cid})
