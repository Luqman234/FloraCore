from __future__ import annotations

from contextlib import closing
import hashlib
import json
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path

from flask import Flask

from floraos_public_api import (
    DEFAULT_SCOPES,
    create_personal_access_token,
    init_public_api,
)


class PublicApiV11Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp.name) / "users.db"
        self.now = int(time.time())
        self.device_id = "floracore-test000001"

        with closing(sqlite3.connect(self.db_path)) as db:
            db.execute("PRAGMA foreign_keys = ON")
            db.execute(
                "CREATE TABLE users(id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL)"
            )
            db.executemany(
                "INSERT INTO users(id, email, password_hash) VALUES (?, ?, 'unused')",
                [(1, "owner@example.test"), (2, "other@example.test")],
            )
            db.execute(
                """
                CREATE TABLE device_ownership(
                    device_id TEXT PRIMARY KEY,
                    user_id INTEGER NOT NULL,
                    claimed_at INTEGER NOT NULL,
                    nickname TEXT,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
                )
                """
            )
            db.execute(
                """
                CREATE TABLE device_messages(
                    device_id TEXT NOT NULL,
                    message_id TEXT NOT NULL,
                    message_type TEXT NOT NULL,
                    client_ts INTEGER NOT NULL,
                    received_at INTEGER NOT NULL,
                    PRIMARY KEY(device_id, message_id)
                )
                """
            )
            db.execute(
                """
                CREATE TABLE device_telemetry(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id TEXT NOT NULL,
                    message_id TEXT NOT NULL,
                    received_at INTEGER NOT NULL,
                    payload_json TEXT NOT NULL
                )
                """
            )
            db.execute(
                """
                CREATE TABLE device_state(
                    device_id TEXT PRIMARY KEY,
                    last_seen INTEGER NOT NULL,
                    last_message_type TEXT NOT NULL,
                    last_message_id TEXT NOT NULL
                )
                """
            )
            db.execute(
                "INSERT INTO device_ownership(device_id,user_id,claimed_at,nickname) VALUES(?,?,?,?)",
                (self.device_id, 1, self.now - 500, "Mint Pot"),
            )
            db.execute(
                "INSERT INTO device_messages VALUES(?,?,?,?,?)",
                (self.device_id, "hb-1", "heartbeat", 0, self.now - 60),
            )
            db.execute(
                "INSERT INTO device_state VALUES(?,?,?,?)",
                (self.device_id, self.now - 20, "telemetry", "tel-1"),
            )
            db.execute(
                "INSERT INTO device_telemetry(device_id,message_id,received_at,payload_json) VALUES(?,?,?,?)",
                (
                    self.device_id,
                    "tel-1",
                    self.now - 20,
                    json.dumps({"soil_percent": 47, "pump_on": False}),
                ),
            )
            db.commit()

        self.app = Flask(__name__)
        self.app.secret_key = "test-secret"
        self.app.config["TESTING"] = True
        init_public_api(self.app, self.db_path)
        self.client = self.app.test_client()

    def tearDown(self):
        self.tmp.cleanup()

    def pat(self, user_id=1, scopes=DEFAULT_SCOPES):
        return create_personal_access_token(
            self.db_path,
            user_id=user_id,
            name="Test token",
            scopes=tuple(scopes),
            lifetime_days=30,
            now=self.now,
        )

    def auth(self, token):
        return {"Authorization": f"Bearer {token}"}

    def test_raw_pat_is_not_stored(self):
        created = self.pat()
        raw = created["token"]
        with closing(sqlite3.connect(self.db_path)) as db:
            row = db.execute("SELECT token_hash, token_prefix FROM api_tokens").fetchone()
        self.assertNotEqual(row[0], raw.encode())
        self.assertEqual(row[0], hashlib.sha256(raw.encode()).digest())
        self.assertTrue(raw.startswith(row[1]))

    def test_me_uses_existing_numeric_user_id(self):
        created = self.pat()
        response = self.client.get("/api/v1/me", headers=self.auth(created["token"]))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["data"]["user_id"], 1)

    def test_online_uses_authenticated_heartbeat(self):
        created = self.pat()
        response = self.client.get("/api/v1/devices", headers=self.auth(created["token"]))
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.get_json()["data"][0]["online"])

        with closing(sqlite3.connect(self.db_path)) as db:
            db.execute(
                "UPDATE device_messages SET received_at = ? WHERE message_type='heartbeat'",
                (int(time.time()) - 121,),
            )
            db.commit()
        response = self.client.get("/api/v1/devices", headers=self.auth(created["token"]))
        self.assertFalse(response.get_json()["data"][0]["online"])

    def test_other_user_gets_404_not_ownership_leak(self):
        created = self.pat(user_id=2)
        response = self.client.get(
            f"/api/v1/devices/{self.device_id}",
            headers=self.auth(created["token"]),
        )
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.get_json()["error"]["code"], "device_not_found")

    def test_read_token_does_not_gain_write_scope(self):
        created = self.pat()
        response = self.client.patch(
            f"/api/v1/devices/{self.device_id}",
            headers={**self.auth(created["token"]), "Content-Type": "application/json"},
            json={"nickname": "Peppermint Pot"},
        )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.get_json()["error"]["code"], "insufficient_scope")

    def test_device_metadata_write_and_plant_crud(self):
        scopes = (
            "devices:read",
            "devices:write",
            "plants:read",
            "plants:write",
            "telemetry:read",
        )
        created = self.pat(scopes=scopes)
        headers = self.auth(created["token"])

        response = self.client.patch(
            f"/api/v1/devices/{self.device_id}",
            headers=headers,
            json={"nickname": "Peppermint Pot"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["data"]["nickname"], "Peppermint Pot")

        response = self.client.put(
            f"/api/v1/devices/{self.device_id}/plant",
            headers=headers,
            json={
                "name": "Minty",
                "species": "Mentha × piperita",
                "notes": "Peppermint test plant",
            },
        )
        self.assertEqual(response.status_code, 201)

        response = self.client.get(
            f"/api/v1/devices/{self.device_id}/plant", headers=headers
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["data"]["name"], "Minty")

        response = self.client.delete(
            f"/api/v1/devices/{self.device_id}/plant", headers=headers
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.get_json()["data"]["deleted"])

        # Device ownership remains after deleting only the plant profile.
        response = self.client.get(
            f"/api/v1/devices/{self.device_id}", headers=headers
        )
        self.assertEqual(response.status_code, 200)

    def test_session_token_management_is_owner_scoped_and_csrf_protected(self):
        with self.client.session_transaction() as sess:
            sess["user_id"] = 1
            sess["email"] = "owner@example.test"
            sess["csrf_token"] = "csrf-1"

        response = self.client.post(
            "/api/developer/tokens",
            json={"name": "Home Assistant", "expires_in_days": 90},
        )
        self.assertEqual(response.status_code, 403)

        response = self.client.post(
            "/api/developer/tokens",
            json={"name": "Home Assistant", "expires_in_days": 90},
            headers={"X-CSRF-Token": "csrf-1"},
        )
        self.assertEqual(response.status_code, 201)
        raw = response.get_json()["data"]["token"]
        self.assertTrue(raw.startswith("flora_pat_"))

        listing = self.client.get("/api/developer/tokens")
        self.assertEqual(listing.status_code, 200)
        self.assertNotIn(raw, json.dumps(listing.get_json()))


if __name__ == "__main__":
    unittest.main()
