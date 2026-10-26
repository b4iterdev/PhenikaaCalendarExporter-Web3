"""Tests for Web3 authentication (SIWE), IPFS pinning, and token gating."""

import hashlib
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from eth_account import Account
from eth_account.messages import encode_defunct
from siwe import SiweMessage

from server.config import ServerConfig
from server.crypto import TokenVault
from server.db import Database
from server.login_broker import LoginBroker
from server.oidc import SignedSessions
from server.web import make_server, ServerApplication
from server.web3_utils import (
    IpfsService,
    TokenGatingService,
    generate_siwe_nonce,
    verify_siwe_signature,
)
from tests.test_server_web import RecordingSync


class Web3IntegrationTestCase(unittest.TestCase):
    def test_siwe_signature_verification(self):
        acct = Account.create()
        nonce = generate_siwe_nonce()
        siwe_msg = SiweMessage(
            domain="localhost",
            address=acct.address,
            statement="Sign in with Ethereum",
            uri="http://localhost",
            version="1",
            chain_id=137,
            nonce=nonce,
            issued_at="2026-10-20T12:00:00Z",
        )
        msg_str = siwe_msg.prepare_message()
        signed = acct.sign_message(encode_defunct(text=msg_str))
        sig_hex = signed.signature.hex()

        result = verify_siwe_signature(
            msg_str, sig_hex, expected_nonce=nonce, expected_domain="localhost"
        )
        self.assertEqual(result["address"].lower(), acct.address.lower())
        self.assertEqual(result["chain_id"], 137)

        # Test lowercase address normalization (MetaMask format)
        lines = msg_str.split("\n")
        lines[1] = lines[1].lower()
        lowercase_msg = "\n".join(lines)
        signed_low = acct.sign_message(encode_defunct(text=lowercase_msg))
        result_low = verify_siwe_signature(
            lowercase_msg, signed_low.signature.hex(), expected_nonce=nonce, expected_domain="localhost"
        )
        self.assertEqual(result_low["address"].lower(), acct.address.lower())

        # Nonce mismatch raises ValueError
        with self.assertRaises(ValueError):
            verify_siwe_signature(
                msg_str, sig_hex, expected_nonce="wrong_nonce", expected_domain="localhost"
            )

        # Domain mismatch raises ValueError
        with self.assertRaises(ValueError):
            verify_siwe_signature(
                msg_str, sig_hex, expected_nonce=nonce, expected_domain="otherdomain.com"
            )

    def test_ipfs_service_mock_pinning(self):
        service = IpfsService(gateway="https://ipfs.io/ipfs/")
        sample = {"events": [{"name": "Calculus", "day": "Monday"}]}
        res = service.pin_json(sample, filename="calendar.json")
        self.assertTrue(res["cid"].startswith("bafybeimock"))
        self.assertTrue(res["url"].startswith("https://ipfs.io/ipfs/bafybeimock"))
        self.assertEqual(res["mock"], "true")

    def test_token_gating_service(self):
        service = TokenGatingService(rpc_url="https://polygon-rpc.com")
        # With mocked Web3
        with patch.object(service, "_w3") as mock_w3:
            mock_w3.is_connected.return_value = True
            mock_contract = MagicMock()
            mock_contract.functions.balanceOf.return_value.call.return_value = 5
            mock_w3.eth.contract.return_value = mock_contract

            has_bal = service.check_token_balance(
                "0x0000000000000000000000000000000000000001",
                "0x0000000000000000000000000000000000000002",
                min_amount=1,
            )
            self.assertTrue(has_bal)

            mock_contract.functions.balanceOf.return_value.call.return_value = 0
            has_bal_insufficient = service.check_token_balance(
                "0x0000000000000000000000000000000000000001",
                "0x0000000000000000000000000000000000000002",
                min_amount=1,
            )
            self.assertFalse(has_bal_insufficient)

    def test_web3_siwe_endpoints_and_login_flow(self):
        import http.client
        import threading
        from http import cookies
        from pathlib import Path

        with tempfile.TemporaryDirectory() as directory:
            from cryptography.fernet import Fernet
            from server.login_broker import ProfileLocks
            from tests.test_server_web import RecordingSync

            config = ServerConfig(state_dir=Path(directory), host="127.0.0.1", port=0, auth_mode="web3")
            config.ensure_dirs()
            database = Database(config.db_path)
            vault = TokenVault(Fernet.generate_key())
            signed_sessions = SignedSessions(b"x" * 32)
            broker = LoginBroker(config, locks=ProfileLocks())
            sync = RecordingSync()
            app = ServerApplication(config, database, vault, signed_sessions, broker, sync, None)
            server = make_server(app)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()

            port = server.server_port
            host_port = f"127.0.0.1:{port}"

            try:
                # 1. Fetch Web3 login page
                conn = http.client.HTTPConnection("127.0.0.1", port)
                conn.request("GET", "/auth/login")
                resp = conn.getresponse()
                self.assertEqual(resp.status, 200)
                body = resp.read().decode("utf-8")
                self.assertIn("Web3", body)
                self.assertIn("startSiwe", body)
                conn.close()

                # 2. Request SIWE Nonce
                conn = http.client.HTTPConnection("127.0.0.1", port)
                conn.request("GET", "/auth/siwe/nonce")
                resp = conn.getresponse()
                self.assertEqual(resp.status, 200)
                set_cookie = resp.getheader("Set-Cookie")
                nonce_cookie = cookies.SimpleCookie(set_cookie)["phenikaa_siwe_nonce"].value
                data = json.loads(resp.read().decode("utf-8"))
                nonce = data.get("nonce")
                self.assertTrue(bool(nonce))
                conn.close()

                # 3. Create wallet & sign message
                acct = Account.create()
                siwe_msg = SiweMessage(
                    domain="127.0.0.1",
                    address=acct.address,
                    statement="Sign in with Ethereum to Phenikaa Calendar Web3.",
                    uri=f"http://{host_port}",
                    version="1",
                    chain_id=137,
                    nonce=nonce,
                    issued_at="2026-10-20T12:00:00Z",
                )
                msg_str = siwe_msg.prepare_message()
                signed = acct.sign_message(encode_defunct(text=msg_str))

                # 4. Post SIWE Verify
                conn = http.client.HTTPConnection("127.0.0.1", port)
                headers = {
                    "Content-Type": "application/json",
                    "Cookie": f"phenikaa_siwe_nonce={nonce_cookie}",
                    "Host": "127.0.0.1",
                }
                conn.request(
                    "POST",
                    "/auth/siwe/verify",
                    body=json.dumps({"message": msg_str, "signature": signed.signature.hex()}),
                    headers=headers,
                )
                resp = conn.getresponse()
                self.assertEqual(resp.status, 200)
                resp_cookie = resp.getheader("Set-Cookie")
                app_session_cookie = cookies.SimpleCookie(resp_cookie)["phenikaa_server_session"].value
                verify_data = json.loads(resp.read().decode("utf-8"))
                self.assertTrue(verify_data.get("ok"))
                self.assertEqual(verify_data.get("address").lower(), acct.address.lower())
                conn.close()

                # 5. Access protected dashboard using established session cookie
                conn = http.client.HTTPConnection("127.0.0.1", port)
                conn.request("GET", "/dashboard", headers={"Cookie": f"phenikaa_server_session={app_session_cookie}"})
                resp = conn.getresponse()
                self.assertEqual(resp.status, 200)
                dash_html = resp.read().decode("utf-8")
                self.assertIn("Calendar sessions", dash_html)
                conn.close()
            finally:
                server.shutdown()
                server.server_close()
                database.close()

    def test_token_gating_service_caching_and_topup_verification(self):
        service = TokenGatingService(rpc_url="https://polygon-rpc.com")
        with patch.object(service, "_w3") as mock_w3:
            mock_w3.is_connected.return_value = True
            mock_contract = MagicMock()
            mock_contract.functions.balanceOf.return_value.call.return_value = 42
            mock_w3.eth.contract.return_value = mock_contract

            wallet = "0x0000000000000000000000000000000000000001"
            contract = "0x0000000000000000000000000000000000000002"
            bal1 = service.get_token_balance(wallet, contract)
            self.assertEqual(bal1, 42)

            # Change return value to verify cache is used
            mock_contract.functions.balanceOf.return_value.call.return_value = 999
            bal2 = service.get_token_balance(wallet, contract)
            self.assertEqual(bal2, 42)  # Cached

        # Topup verification with mock hash
        mock_hash = "0xmock_" + "a" * 59
        verified = service.verify_topup_tx(
            mock_hash,
            expected_recipient="0x000000000000000000000000000000000000bEEF",
            credits_per_unit=1000,
        )
        self.assertEqual(verified["credits"], 1000)
        self.assertEqual(verified["tx_hash"], mock_hash)

        # Invalid format
        with self.assertRaises(ValueError):
            service.verify_topup_tx("invalid_tx_hash")

    def test_database_credit_operations(self):
        with tempfile.TemporaryDirectory() as directory:
            db_path = Path(directory) / "test.db"
            database = Database(db_path)
            try:
                user = database.get_or_create_user("eth:0x123", "Test User")
                uid = int(user["id"])
                self.assertEqual(database.get_user_credits(uid), 0)

                # Add credits
                tx_hash = "0x" + "1" * 64
                new_bal = database.add_user_credits(uid, 500, tx_hash=tx_hash, amount_wei=str(10**18))
                self.assertEqual(new_bal, 500)
                self.assertEqual(database.get_user_credits(uid), 500)

                # Prevent duplicate tx
                with self.assertRaises(sqlite3.IntegrityError):
                    database.add_user_credits(uid, 500, tx_hash=tx_hash)

                # Deduct credits
                deducted = database.deduct_user_credit(uid, 200)
                self.assertTrue(deducted)
                self.assertEqual(database.get_user_credits(uid), 300)

                # Deduct more than balance
                failed_deduct = database.deduct_user_credit(uid, 500)
                self.assertFalse(failed_deduct)
                self.assertEqual(database.get_user_credits(uid), 300)

                txs = database.list_credit_transactions(uid)
                self.assertEqual(len(txs), 1)
                self.assertEqual(txs[0]["tx_hash"], tx_hash)
            finally:
                database.close()

    def test_hybrid_token_gating_and_topup_api(self):
        import http.client
        import threading
        from pathlib import Path
        from cryptography.fernet import Fernet
        from server.login_broker import ProfileLocks
        from tests.test_server_web import RecordingSync

        with tempfile.TemporaryDirectory() as directory:
            config = ServerConfig(
                state_dir=Path(directory),
                host="127.0.0.1",
                port=0,
                auth_mode="web3",
                token_gate_contract="0x0000000000000000000000000000000000000002",
                token_gate_min_balance=10,
                token_gate_vip_balance=100,
            )
            config.ensure_dirs()
            database = Database(config.db_path)
            vault = TokenVault(Fernet.generate_key())
            signed_sessions = SignedSessions(b"x" * 32)
            broker = LoginBroker(config, locks=ProfileLocks())
            sync = RecordingSync()
            app = ServerApplication(config, database, vault, signed_sessions, broker, sync, None)
            server = make_server(app)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()

            port = server.server_port
            try:
                # Create user and API token
                user = database.get_or_create_user("eth:0x1111111111111111111111111111111111111111", "Web3 User")
                uid = int(user["id"])
                raw_token = "phk_testtokengatinghybrid123456789"
                thash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
                database.create_api_token(
                    token_id="tok1",
                    owner_user_id=uid,
                    token_hash=thash,
                    token_prefix=raw_token[:12],
                    scopes=["me:read", "sessions:read"],
                )

                # Mock token balance: 0 tokens, 0 credits -> 403 token_gate_failed
                with patch.object(app.token_gating, "get_token_balance", return_value=0):
                    conn = http.client.HTTPConnection("127.0.0.1", port)
                    conn.request("GET", "/api/v1/me", headers={"Authorization": f"Bearer {raw_token}"})
                    resp = conn.getresponse()
                    self.assertEqual(resp.status, 403)
                    body = json.loads(resp.read().decode("utf-8"))
                    self.assertEqual(body["error"]["code"], "token_gate_failed")
                    conn.close()

                    # Top up credits via /api/v1/account/topup
                    mock_tx = "0xmock_" + "b" * 59
                    conn = http.client.HTTPConnection("127.0.0.1", port)
                    conn.request(
                        "POST",
                        "/api/v1/account/topup",
                        body=json.dumps({"txHash": mock_tx}),
                        headers={"Authorization": f"Bearer {raw_token}", "Content-Type": "application/json"},
                    )
                    resp = conn.getresponse()
                    self.assertEqual(resp.status, 200)
                    topup_data = json.loads(resp.read().decode("utf-8"))
                    self.assertTrue(topup_data["ok"])
                    self.assertEqual(topup_data["data"]["creditsAdded"], 1000)
                    conn.close()

                    # Now with credits > 0, API call succeeds even with 0 tokens!
                    conn = http.client.HTTPConnection("127.0.0.1", port)
                    conn.request("GET", "/api/v1/me", headers={"Authorization": f"Bearer {raw_token}"})
                    resp = conn.getresponse()
                    self.assertEqual(resp.status, 200)
                    me_data = json.loads(resp.read().decode("utf-8"))
                    self.assertTrue(me_data["ok"])
                    self.assertEqual(me_data["data"]["web3"]["credits"], 1000)
                    self.assertEqual(me_data["data"]["web3"]["tier"], "standard")
                    conn.close()

                    # Check GET /api/v1/account/credits
                    conn = http.client.HTTPConnection("127.0.0.1", port)
                    conn.request("GET", "/api/v1/account/credits", headers={"Authorization": f"Bearer {raw_token}"})
                    resp = conn.getresponse()
                    self.assertEqual(resp.status, 200)
                    credits_data = json.loads(resp.read().decode("utf-8"))
                    self.assertEqual(credits_data["data"]["credits"], 1000)
                    self.assertEqual(len(credits_data["data"]["recentTransactions"]), 1)
                    conn.close()
            finally:
                server.shutdown()
                server.server_close()
                database.close()


if __name__ == "__main__":
    unittest.main()
