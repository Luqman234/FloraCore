from __future__ import annotations

from contextlib import closing
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path

from flask import Flask, jsonify

import floraos_mfa
from floraos_mfa import (
    complete_primary_auth,
    init_mfa,
    totp_code,
)


class MFATests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.db_path = self.root / "users.db"

        with closing(sqlite3.connect(self.db_path)) as db:
            db.execute(
                """
                CREATE TABLE users(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL
                )
                """
            )
            db.execute(
                "INSERT INTO users(id,email,password_hash) VALUES(1,?,?)",
                ("owner@example.test", "unused"),
            )
            db.commit()

        self.app = Flask(__name__)
        self.app.secret_key = "mfa-test-secret"
        self.app.config["TESTING"] = True
        init_mfa(self.app, self.db_path)

        self.sent = []
        self.original_sender = floraos_mfa.send_mfa_otp

        def capture(recipient, otp, *, purpose="login", expires_minutes=10):
            self.sent.append(
                {
                    "recipient": recipient,
                    "otp": otp,
                    "purpose": purpose,
                    "expires_minutes": expires_minutes,
                }
            )

        floraos_mfa.send_mfa_otp = capture

        @self.app.post("/test-primary")
        def test_primary():
            return jsonify(
                complete_primary_auth(
                    1,
                    "owner@example.test",
                    provider="password",
                    remember=False,
                    next_url="/dashboard",
                )
            )

        self.client = self.app.test_client()

    def tearDown(self):
        floraos_mfa.send_mfa_otp = self.original_sender
        self.tmp.cleanup()

    def login_settings_session(self):
        with self.client.session_transaction() as sess:
            sess.clear()
            sess["user_id"] = 1
            sess["email"] = "owner@example.test"
            sess["auth_provider"] = "password"
            sess["csrf_token"] = "csrf-test"

    @property
    def headers(self):
        return {"X-CSRF-Token": "csrf-test"}

    def security_verify(self):
        self.login_settings_session()
        sent = self.client.post(
            "/api/settings/security/send-code",
            headers=self.headers,
            json={},
        )
        self.assertEqual(sent.status_code, 200, sent.get_data(as_text=True))
        code = self.sent[-1]["otp"]
        verified = self.client.post(
            "/api/settings/security/verify-code",
            headers=self.headers,
            json={"code": code},
        )
        self.assertEqual(verified.status_code, 200, verified.get_data(as_text=True))

    def test_email_mfa_blocks_full_session_until_code_verified(self):
        self.security_verify()

        enabled = self.client.post(
            "/api/settings/mfa/email/enable",
            headers=self.headers,
            json={},
        )
        self.assertEqual(enabled.status_code, 200)

        # Simulate a fresh primary login.
        with self.client.session_transaction() as sess:
            sess.clear()

        primary = self.client.post("/test-primary")
        self.assertEqual(primary.status_code, 200)
        data = primary.get_json()
        self.assertTrue(data["mfa_required"])
        self.assertEqual(data["method"], "email")
        self.assertEqual(data["redirect"], "/mfa")

        with self.client.session_transaction() as sess:
            self.assertNotIn("user_id", sess)
            csrf = sess["csrf_token"]

        login_code = self.sent[-1]["otp"]
        verify = self.client.post(
            "/api/mfa/login/verify",
            headers={"X-CSRF-Token": csrf},
            json={"code": login_code},
        )
        self.assertEqual(verify.status_code, 200, verify.get_data(as_text=True))

        with self.client.session_transaction() as sess:
            self.assertEqual(sess["user_id"], 1)
            self.assertEqual(sess["email"], "owner@example.test")

    def test_authenticator_secret_is_encrypted_and_login_works(self):
        self.security_verify()

        start = self.client.post(
            "/api/settings/mfa/authenticator/start",
            headers=self.headers,
            json={},
        )
        self.assertEqual(start.status_code, 200)
        secret = start.get_json()["data"]["setup_key"]
        self.assertTrue(secret)

        now = int(time.time())
        setup_code = totp_code(secret, counter=now // 30)
        confirm = self.client.post(
            "/api/settings/mfa/authenticator/confirm",
            headers=self.headers,
            json={"code": setup_code},
        )
        self.assertEqual(confirm.status_code, 200, confirm.get_data(as_text=True))
        recovery_codes = confirm.get_json()["data"]["recovery_codes"]
        self.assertEqual(len(recovery_codes), 8)

        with closing(sqlite3.connect(self.db_path)) as db:
            row = db.execute(
                "SELECT totp_secret_encrypted FROM user_mfa WHERE user_id = 1"
            ).fetchone()
        self.assertIsNotNone(row)
        self.assertNotEqual(row[0], secret)
        self.assertNotIn(secret, row[0])

        with self.client.session_transaction() as sess:
            sess.clear()

        primary = self.client.post("/test-primary")
        self.assertTrue(primary.get_json()["mfa_required"])
        self.assertEqual(primary.get_json()["method"], "totp")

        with self.client.session_transaction() as sess:
            csrf = sess["csrf_token"]

        login_now = int(time.time())
        login_code = totp_code(secret, counter=login_now // 30)
        verify = self.client.post(
            "/api/mfa/login/verify",
            headers={"X-CSRF-Token": csrf},
            json={"code": login_code},
        )
        self.assertEqual(verify.status_code, 200, verify.get_data(as_text=True))

        with self.client.session_transaction() as sess:
            self.assertEqual(sess["user_id"], 1)

    def test_recovery_code_is_one_time(self):
        self.security_verify()
        start = self.client.post(
            "/api/settings/mfa/authenticator/start",
            headers=self.headers,
            json={},
        )
        secret = start.get_json()["data"]["setup_key"]
        now = int(time.time())
        confirm = self.client.post(
            "/api/settings/mfa/authenticator/confirm",
            headers=self.headers,
            json={"code": totp_code(secret, counter=now // 30)},
        )
        recovery = confirm.get_json()["data"]["recovery_codes"][0]

        # First recovery use succeeds.
        with self.client.session_transaction() as sess:
            sess.clear()
        self.client.post("/test-primary")
        with self.client.session_transaction() as sess:
            csrf = sess["csrf_token"]

        first = self.client.post(
            "/api/mfa/login/verify",
            headers={"X-CSRF-Token": csrf},
            json={"recovery_code": recovery},
        )
        self.assertEqual(first.status_code, 200)

        # The same recovery code cannot be used again.
        with self.client.session_transaction() as sess:
            sess.clear()
        self.client.post("/test-primary")
        with self.client.session_transaction() as sess:
            csrf = sess["csrf_token"]

        second = self.client.post(
            "/api/mfa/login/verify",
            headers={"X-CSRF-Token": csrf},
            json={"recovery_code": recovery},
        )
        self.assertEqual(second.status_code, 401)
        self.assertEqual(
            second.get_json()["error"]["code"],
            "invalid_mfa_code",
        )

    def test_settings_changes_require_email_reverification(self):
        self.login_settings_session()

        blocked = self.client.post(
            "/api/settings/mfa/email/enable",
            headers=self.headers,
            json={},
        )
        self.assertEqual(blocked.status_code, 403)
        self.assertEqual(
            blocked.get_json()["error"]["code"],
            "security_verification_required",
        )


if __name__ == "__main__":
    unittest.main()
