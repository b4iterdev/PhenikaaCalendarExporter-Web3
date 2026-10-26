"""Web3 utilities: SIWE verification, IPFS uploads via Pinata/Gateway, and Token Gating."""

from __future__ import annotations

import json
import os
import secrets
import time
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
        self.rpc_url = rpc_url or os.environ.get("WEB3_RPC_URL", "https://forno.celo.org")
        self._w3: Web3 | None = None
        self._balance_cache: dict[tuple[str, str], tuple[int, float]] = {}
        self.cache_ttl: float = 300.0

    @property
    def w3(self) -> Web3:
        if self._w3 is None:
            self._w3 = Web3(Web3.HTTPProvider(self.rpc_url))
        return self._w3

    def get_token_balance(
        self,
        wallet_address: str,
        contract_address: str,
        *,
        use_cache: bool = True,
    ) -> int:
        """Fetch token balance for wallet with TTL caching."""
        if not wallet_address or not contract_address:
            return 0
        try:
            checksum_wallet = Web3.to_checksum_address(wallet_address)
            checksum_contract = Web3.to_checksum_address(contract_address)
        except Exception:
            return 0

        now = time.monotonic()
        cache_key = (checksum_wallet, checksum_contract)
        if use_cache and cache_key in self._balance_cache:
            bal, exp = self._balance_cache[cache_key]
            if now < exp:
                return bal

        if not self.w3.is_connected():
            return 0

        try:
            contract = self.w3.eth.contract(address=checksum_contract, abi=BALANCE_OF_ABI)
            balance = int(contract.functions.balanceOf(checksum_wallet).call())
            self._balance_cache[cache_key] = (balance, now + self.cache_ttl)
            return balance
        except Exception:
            if cache_key in self._balance_cache:
                return self._balance_cache[cache_key][0]
            return 0

    def check_token_balance(
        self,
        wallet_address: str,
        contract_address: str,
        min_amount: int = 1,
        *,
        use_cache: bool = False,
    ) -> bool:
        """Check if wallet_address owns >= min_amount of token at contract_address."""
        return self.get_token_balance(wallet_address, contract_address, use_cache=use_cache) >= min_amount

    def verify_topup_tx(
        self,
        tx_hash: str,
        expected_recipient: str = "",
        min_confirmations: int = 1,
        credits_per_unit: int = 1000,
    ) -> dict[str, Any]:
        """Verify on-chain transfer for credit top-up."""
        cleaned_hash = tx_hash.strip().lower()
        if not cleaned_hash.startswith("0x") or len(cleaned_hash) != 66:
            raise ValueError("txHash must be a 66-character hex string starting with 0x.")

        # Development / testing mock support
        if cleaned_hash.startswith("0xmock_") or os.environ.get("WEB3_MOCK_TOPUP") == "1":
            return {
                "tx_hash": cleaned_hash,
                "sender": "0x000000000000000000000000000000000000dEaD",
                "recipient": expected_recipient or "0x000000000000000000000000000000000000bEEF",
                "value_wei": 10**18,
                "block_number": 1234567,
                "confirmations": 10,
                "credits": credits_per_unit,
            }

        if not self.w3.is_connected():
            raise RuntimeError("Web3 RPC provider is not connected.")

        try:
            tx = self.w3.eth.get_transaction(cleaned_hash)
            receipt = self.w3.eth.get_transaction_receipt(cleaned_hash)
            if tx and receipt is None:
                try:
                    receipt = self.w3.eth.wait_for_transaction_receipt(cleaned_hash, timeout=10)
                except Exception:
                    pass
        except Exception as err:
            raise ValueError(f"Could not retrieve transaction: {err}") from err

        if not tx or not receipt:
            raise ValueError("Transaction or receipt not found.")

        if receipt.get("status") != 1:
            raise ValueError("Transaction failed or reverted on-chain.")

        tx_to = tx.get("to")
        if not tx_to:
            raise ValueError("Contract creation transaction cannot be used for top-up.")

        if expected_recipient:
            if Web3.to_checksum_address(tx_to) != Web3.to_checksum_address(expected_recipient):
                raise ValueError(
                    f"Recipient mismatch: expected {expected_recipient}, got {tx_to}."
                )

        current_block = self.w3.eth.block_number
        tx_block = int(receipt.get("blockNumber") or 0)
        confirmations = max(0, current_block - tx_block + 1)
        if confirmations < min_confirmations:
            raise ValueError(
                f"Transaction requires at least {min_confirmations} confirmation(s), but has {confirmations}."
            )

        value_wei = int(tx.get("value") or 0)
        if value_wei <= 0:
            raise ValueError("Transaction value must be greater than zero.")

        credits = max(1, int(value_wei * credits_per_unit // (10**18)))
        return {
            "tx_hash": cleaned_hash,
            "sender": tx.get("from"),
            "recipient": tx_to,
            "value_wei": value_wei,
            "block_number": tx_block,
            "confirmations": confirmations,
            "credits": credits,
        }
