from __future__ import annotations

from contextlib import closing
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path

from flask import Flask, jsonify, session
from werkzeug.security import check_password_hash, generate_password_hash

import floraos_account_security
from floraos_account_security import (
    init_account_security,
    login_rate_guard,
    mark_new_session,
    note_login_failure,
)


class AccountSecurityTests(unittest.TestCase):
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
                """
                CREATE TABLE device_ownership(
                    user_id INTEGER NOT NULL,
                    device_id TEXT NOT NULL
                )
                """
            )
            db.execute(
                """
                CREATE TABLE device_messages(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id TEXT NOT NULL,
                    message_type TEXT NOT NULL,
                    received_at INTEGER NOT NULL
                )
                """
            )
            db.execute(
                """
                CREATE TABLE device_state(
                    device_id TEXT PRIMARY KEY,
                    command_protocol INTEGER
                )
                """
            )
            db.execute(
                "INSERT INTO users(id,email,password_hash) VALUES(1,?,?)",
                ("owner@example.test", generate_password_hash("old-password-123", method="scrypt")),
            )
            db.commit()

        self.app = Flask(__name__)
        self.app.secret_key = "account-security-test-secret"
        self.app.config["TESTING"] = True
        self.app.config["SECURITY_EMAIL_ALERTS"] = False

        init_account_security(self.app, self.db_path)

        @self.app.get("/protected")
        def protected():
            if "user_id" not in session:
                return jsonify(error="not authenticated"), 401
            return jsonify(ok=True)

        self.client = self.app.test_client()

        self.original_reset_sender = floraos_account_security.send_password_reset_otp
        self.sent_reset = []

        def fake_reset(recipient, otp, *, expires_minutes=10):
            self.sent_reset.append((recipient, otp, expires_minutes))

        floraos_account_security.send_password_reset_otp = fake_reset

    def tearDown(self):
        floraos_account_security.send_password_reset_otp = self.original_reset_sender
        self.tmp.cleanup()

    def authenticated_session(self, *, security_verified=False, new_session=True):
        with self.client.session_transaction() as sess:
            sess.clear()
            sess["user_id"] = 1
            sess["email"] = "owner@example.test"
            sess["auth_provider"] = "password"
            sess["csrf_token"] = "csrf-test"
            if new_session:
                sess["security_new_session"] = True
            if security_verified:
                sess["mfa_settings_verified_until"] = int(time.time()) + 600

    def test_authenticated_browser_is_registered_server_side(self):
        self.authenticated_session(new_session=True)
        response = self.client.get("/protected")
        self.assertEqual(response.status_code, 200)

        with closing(sqlite3.connect(self.db_path)) as db:
            row = db.execute(
                "SELECT user_id, revoked_at FROM account_sessions WHERE user_id = 1"
            ).fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row[0], 1)
        self.assertIsNone(row[1])

    def test_revoked_session_is_rejected_on_next_request(self):
        self.authenticated_session(new_session=True)
        self.client.get("/protected")

        with self.client.session_transaction() as sess:
            sid = sess["account_session_id"]

        with closing(sqlite3.connect(self.db_path)) as db:
            db.execute(
                "UPDATE account_sessions SET revoked_at = ? WHERE session_id = ?",
                (int(time.time()), sid),
            )
            db.commit()

        response = self.client.get("/protected", follow_redirects=False)
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login", response.headers["Location"])

    def test_password_change_requires_recent_security_verification(self):
        self.authenticated_session(security_verified=False)
        self.client.get("/protected")

        response = self.client.post(
            "/api/settings/password/change",
            headers={"X-CSRF-Token": "csrf-test"},
            json={
                "current_password": "old-password-123",
                "new_password": "new-password-456",
                "confirm_password": "new-password-456",
            },
        )
        self.assertEqual(response.status_code, 403)

    def test_password_change_revokes_other_sessions(self):
        self.authenticated_session(security_verified=True)
        self.client.get("/protected")

        # Add a second active session directly.
        now = int(time.time())
        with closing(sqlite3.connect(self.db_path)) as db:
            db.execute(
                """
                INSERT INTO account_sessions(
                    session_id, session_token_hash, user_id, provider,
                    created_at, last_seen_at, expires_at,
                    ip_address, user_agent
                ) VALUES ('sess_other', 'token-other', 1, 'password', ?, ?, ?, '127.0.0.1', 'Other')
                """,
                (now, now, now + 3600),
            )
            db.commit()

        response = self.client.post(
            "/api/settings/password/change",
            headers={"X-CSRF-Token": "csrf-test"},
            json={
                "current_password": "old-password-123",
                "new_password": "new-password-456",
                "confirm_password": "new-password-456",
            },
        )
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        self.assertGreaterEqual(response.get_json()["other_sessions_revoked"], 1)

        with closing(sqlite3.connect(self.db_path)) as db:
            user = db.execute(
                "SELECT password_hash FROM users WHERE id = 1"
            ).fetchone()
            other = db.execute(
                "SELECT revoked_at FROM account_sessions WHERE session_id = 'sess_other'"
            ).fetchone()

        self.assertTrue(check_password_hash(user[0], "new-password-456"))
        self.assertIsNotNone(other[0])

    def test_password_reset_revokes_all_sessions(self):
        with self.client.session_transaction() as sess:
            sess["csrf_token"] = "csrf-reset"

        start = self.client.post(
            "/api/password-reset/start",
            headers={"X-CSRF-Token": "csrf-reset"},
            json={"email": "owner@example.test"},
        )
        self.assertEqual(start.status_code, 200, start.get_data(as_text=True))
        self.assertEqual(len(self.sent_reset), 1)
        otp = self.sent_reset[0][1]

        # Existing active session belonging to the user.
        now = int(time.time())
        with closing(sqlite3.connect(self.db_path)) as db:
            db.execute(
                """
                INSERT INTO account_sessions(
                    session_id, session_token_hash, user_id, provider,
                    created_at, last_seen_at, expires_at,
                    ip_address, user_agent
                ) VALUES ('sess_existing', 'token-existing', 1, 'password', ?, ?, ?, '127.0.0.1', 'Browser')
                """,
                (now, now, now + 3600),
            )
            db.commit()

        complete = self.client.post(
            "/api/password-reset/complete",
            headers={"X-CSRF-Token": "csrf-reset"},
            json={
                "code": otp,
                "new_password": "reset-password-789",
                "confirm_password": "reset-password-789",
            },
        )
        self.assertEqual(complete.status_code, 200, complete.get_data(as_text=True))

        with closing(sqlite3.connect(self.db_path)) as db:
            user = db.execute(
                "SELECT password_hash FROM users WHERE id = 1"
            ).fetchone()
            active = db.execute(
                """
                SELECT COUNT(*) FROM account_sessions
                WHERE user_id = 1 AND revoked_at IS NULL
                """
            ).fetchone()[0]

        self.assertTrue(check_password_hash(user[0], "reset-password-789"))
        self.assertEqual(active, 0)

    def test_account_aware_login_rate_limit_activates(self):
        with self.app.test_request_context(
            "/api/login",
            headers={"CF-Connecting-IP": "203.0.113.20"},
        ):
            for _ in range(8):
                note_login_failure("owner@example.test")
            limited = login_rate_guard("owner@example.test")

        self.assertIsNotNone(limited)
        self.assertGreaterEqual(limited[1], 60)


if __name__ == "__main__":
    unittest.main()
