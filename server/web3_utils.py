"""Web3 utilities: SIWE verification, IPFS uploads via Pinata/Gateway, and Token Gating."""

from __future__ import annotations

import json
import os
import secrets
from typing import Any

from eth_account.messages import encode_defunct
from siwe import SiweMessage
from web3 import Web3


def generate_siwe_nonce() -> str:
    """Generate a cryptographic nonce for Sign-In with Ethereum."""
    return secrets.token_hex(16)


def verify_siwe_signature(
    message: str,
    signature: str,
    *,
    expected_nonce: str | None = None,
    expected_domain: str | None = None,
) -> dict[str, Any]:
    """Verify an EIP-4361 SIWE message and signature.

    Returns dict with address, chain_id, and nonce if valid.
    Raises ValueError on invalid signature or mismatched parameters.
    """
    raw_message = message
    try:
        # Normalize address in raw message text to EIP-55 checksum format if needed
        # (MetaMask window.ethereum.request('eth_requestAccounts') returns all-lowercase address,
        # but pydantic validation in siwe-py strictly requires EIP-55 mixed-case checksum format)
        lines = message.split("\n")
        if len(lines) >= 2 and lines[1].startswith("0x"):
            raw_addr = lines[1].strip()
            if Web3.is_address(raw_addr):
                lines[1] = Web3.to_checksum_address(raw_addr)
                message = "\n".join(lines)
        siwe_msg = SiweMessage.from_message(message)
    except Exception as e:
        raise ValueError(f"invalid SIWE message: {e}") from e

    if expected_nonce and siwe_msg.nonce != expected_nonce:
        raise ValueError("nonce mismatch")

    if expected_domain and siwe_msg.domain != expected_domain:
        raise ValueError(f"domain mismatch: expected {expected_domain}, got {siwe_msg.domain}")

    w3 = Web3()
    try:
        # Recover address from signature using eth_account against the EXACT text signed by user (raw_message)
        encoded_msg = encode_defunct(text=raw_message)
        recovered_address = w3.eth.account.recover_message(encoded_msg, signature=signature)
    except Exception as e:
        raise ValueError(f"signature recovery failed: {e}") from e

    if recovered_address.lower() != siwe_msg.address.lower():
        raise ValueError(f"signer address mismatch: message={siwe_msg.address}, recovered={recovered_address}")

    return {
        "address": Web3.to_checksum_address(recovered_address),
        "chain_id": siwe_msg.chain_id,
        "nonce": siwe_msg.nonce,
    }


class IpfsService:
    """Publish calendar exports to IPFS (via Pinata or mock local IPFS CID generator)."""

    def __init__(
        self,
        *,
        jwt: str | None = None,
        gateway: str = "https://gateway.pinata.cloud/ipfs/",
    ) -> None:
        self.jwt = jwt or os.environ.get("PINATA_JWT", "")
        self.gateway = gateway.rstrip("/") + "/"

    def pin_json(self, data: Any, filename: str = "calendar.json") -> dict[str, str]:
        """Upload JSON data to IPFS and return CID + gateway URL."""
        raw_bytes = json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8")
        return self.pin_file(raw_bytes, filename=filename, content_type="application/json")

    def pin_file(
        self, content: bytes, filename: str = "calendar.ics", content_type: str = "text/calendar"
    ) -> dict[str, str]:
        """Upload file bytes to IPFS."""
        if not self.jwt:
            # Deterministic/hash fallback for local/test environments
            import hashlib
            cid_hash = hashlib.sha256(content).hexdigest()
            # Construct a recognizable mock IPFS v1 CID representation
            mock_cid = f"bafybeimock{cid_hash[:32]}"
            return {
                "cid": mock_cid,
                "url": f"{self.gateway}{mock_cid}",
                "filename": filename,
                "size": str(len(content)),
                "mock": "true",
            }

        import requests

        url = "https://api.pinata.cloud/pinning/pinFileToIPFS"
        headers = {"Authorization": f"Bearer {self.jwt}"}
        files = {
            "file": (filename, content, content_type)
        }
        resp = requests.post(url, headers=headers, files=files, timeout=30)
        if resp.status_code != 200:
            raise RuntimeError(f"Pinata IPFS upload failed ({resp.status_code}): {resp.text}")

        res_json = resp.json()
        cid = res_json.get("IpfsHash", "")
        return {
            "cid": cid,
            "url": f"{self.gateway}{cid}",
            "filename": filename,
            "size": str(len(content)),
            "mock": "false",
        }


# Standard ERC-20 / ERC-721 balanceOf ABI snippet
BALANCE_OF_ABI = [
    {
        "constant": True,
        "inputs": [{"name": "_owner", "type": "address"}],
        "name": "balanceOf",
        "outputs": [{"name": "balance", "type": "uint256"}],
        "type": "function",
    }
]


class TokenGatingService:
    """Verify on-chain token or NFT ownership for gated API access / VIP limits."""

    def __init__(self, rpc_url: str | None = None) -> None:
        self.rpc_url = rpc_url or os.environ.get("WEB3_RPC_URL", "https://polygon-rpc.com")
        self._w3: Web3 | None = None

    @property
    def w3(self) -> Web3:
        if self._w3 is None:
            self._w3 = Web3(Web3.HTTPProvider(self.rpc_url))
        return self._w3

    def check_token_balance(
        self,
        wallet_address: str,
        contract_address: str,
        min_amount: int = 1,
    ) -> bool:
        """Check if wallet_address owns >= min_amount of token at contract_address."""
        if not self.w3.is_connected():
            return False

        try:
            checksum_wallet = Web3.to_checksum_address(wallet_address)
            checksum_contract = Web3.to_checksum_address(contract_address)
            contract = self.w3.eth.contract(address=checksum_contract, abi=BALANCE_OF_ABI)
            balance = contract.functions.balanceOf(checksum_wallet).call()
            return int(balance) >= min_amount
        except Exception:
            return False
