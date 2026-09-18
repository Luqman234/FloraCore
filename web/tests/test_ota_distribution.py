from __future__ import annotations

from contextlib import closing
import json
import os
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import Flask

from device_enrollment import init_enrollment_api
from floraos_device_api import init_device_api
from floraos_ota import (
    init_ota,
    register_release,
)
from publish_firmware import ESP_APP_DESC_MAGIC, inspect_esp_app_image


DEVICE_ID = "floracore-test0001"
D2S = bytes.fromhex("11" * 32)
S2D = bytes.fromhex("22" * 32)
PATH = "/api/device/v1/message"
LABEL = "floraos-e2ee-v1"


def aad(device_id: str, direction: str) -> bytes:
    return f"{LABEL}|{device_id}|{direction}|{PATH}".encode()


class OtaDistributionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.db_path = self.root / "users.db"
        self.keys_path = self.root / "device_keys.json"
        self.keys_path.write_text(
            json.dumps(
                {
                    DEVICE_ID: {
                        "d2s_key": D2S.hex(),
                        "s2d_key": S2D.hex(),
                    }
                }
            ),
            encoding="utf-8",
        )
        self.old_keys = os.environ.get("FLORAOS_DEVICE_KEYS_FILE")
        os.environ["FLORAOS_DEVICE_KEYS_FILE"] = str(self.keys_path)

        with closing(sqlite3.connect(self.db_path)) as db:
            db.execute(
                """
                CREATE TABLE users(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    created_at INTEGER NOT NULL
                )
                """
            )
            db.execute(
                "INSERT INTO users(email, password_hash, created_at) VALUES (?, ?, ?)",
                ("owner@example.com", "x", int(time.time())),
            )
            db.commit()

        self.app = Flask(__name__)
        self.app.secret_key = "test-secret"
        init_enrollment_api(self.app, self.db_path)
        init_ota(
            self.app,
            self.db_path,
            firmware_root=self.root / "firmware" / "floracore",
        )
        init_device_api(self.app, self.db_path)

        with closing(sqlite3.connect(self.db_path)) as db:
            db.execute(
                """
                INSERT INTO device_ownership(device_id, user_id, claimed_at)
                VALUES (?, 1, ?)
                """,
                (DEVICE_ID, int(time.time())),
            )
            db.commit()

        register_release(
            self.db_path,
            product="FloraCore",
            target="esp32s3",
            version="1.1.0",
            channel="stable",
            binary_path="firmware/floracore/stable/1.1.0/FloraCore.bin",
            binary_url="https://floraos.life/firmware/floracore/stable/1.1.0/FloraCore.bin",
            sha256="ab" * 32,
            byte_size=1324464,
            release_notes="Test release",
        )

        self.client = self.app.test_client()
        self.counter = 0

    def tearDown(self):
        if self.old_keys is None:
            os.environ.pop("FLORAOS_DEVICE_KEYS_FILE", None)
        else:
            os.environ["FLORAOS_DEVICE_KEYS_FILE"] = self.old_keys
        self.temp.cleanup()

    def send_device(self, message_type: str, payload: dict):
        self.counter += 1
        message_id = f"{self.counter:032x}"
        inner = {
            "message_id": message_id,
            "type": message_type,
            "ts": int(time.time()),
            "payload": payload,
        }
        nonce = bytes([self.counter % 255 or 1]) * 12
        ciphertext = AESGCM(D2S).encrypt(
            nonce,
            json.dumps(inner, separators=(",", ":")).encode(),
            aad(DEVICE_ID, "d2s"),
        )
        response = self.client.post(
            PATH,
            json={
                "v": 1,
                "device_id": DEVICE_ID,
                "nonce": nonce.hex(),
                "ciphertext": ciphertext.hex(),
            },
        )
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        envelope = response.get_json()
        plain = AESGCM(S2D).decrypt(
            bytes.fromhex(envelope["nonce"]),
            bytes.fromhex(envelope["ciphertext"]),
            aad(DEVICE_ID, "s2d"),
        )
        return json.loads(plain)

    def normal_heartbeat(self, **extra):
        payload = {
            "product": "FloraCore",
            "target": "esp32s3",
            "firmware_version": "1.0.1",
            "firmware_channel": "stable",
            "mode": "NORMAL",
        }
        payload.update(extra)
        return self.send_device("heartbeat", payload)

    def test_authenticated_heartbeat_receives_server_selected_offer(self):
        reply = self.normal_heartbeat()
        self.assertTrue(reply["ok"])
        self.assertEqual(reply["commands"], [])
        self.assertTrue(reply["ota"]["available"])
        self.assertEqual(reply["ota"]["version"], "1.1.0")
        self.assertEqual(reply["ota"]["size"], 1324464)
        self.assertEqual(reply["ota"]["sha256"], "ab" * 32)

    def test_setup_state_never_receives_ota(self):
        reply = self.normal_heartbeat(mode="SETUP_CLAIMING")
        self.assertFalse(reply["ota"]["available"])

    def test_claim_response_never_contains_ota_offer(self):
        reply = self.send_device("claim", {"token": "not-a-valid-token"})
        self.assertFalse(reply["ok"])
        self.assertNotIn("ota", reply)

    def test_rollback_is_recorded_and_same_release_is_not_reoffered(self):
        first = self.normal_heartbeat()
        self.assertTrue(first["ota"]["available"])

        report = self.send_device(
            "ota_status",
            {
                "status": "rolled_back",
                "from_version": "1.0.1",
                "target_version": "1.1.0",
                "error": "candidate_failed_health_gate",
            },
        )
        self.assertFalse(report["ota"]["available"])

        second = self.normal_heartbeat()
        self.assertFalse(second["ota"]["available"])

        with closing(sqlite3.connect(self.db_path)) as db:
            row = db.execute(
                """
                SELECT status, error
                FROM device_ota_history
                WHERE device_id = ?
                ORDER BY id DESC LIMIT 1
                """,
                (DEVICE_ID,),
            ).fetchone()
        self.assertEqual(row[0], "rolled_back")
        self.assertEqual(row[1], "candidate_failed_health_gate")

    def test_publisher_accepts_app_image_and_rejects_non_app_image(self):
        good = self.root / "FloraCore.bin"
        data = bytearray(70 * 1024)
        data[0] = 0xE9
        data[32:36] = ESP_APP_DESC_MAGIC.to_bytes(4, "little")
        data[48:48 + len(b"1.1.0")] = b"1.1.0"
        data[80:80 + len(b"FloraCore")] = b"FloraCore"
        good.write_bytes(data)

        info = inspect_esp_app_image(good)
        self.assertEqual(info["project"], "FloraCore")
        self.assertEqual(info["version"], "1.1.0")

        bad = self.root / "bootloader.bin"
        bad_data = bytearray(70 * 1024)
        bad_data[0] = 0xE9
        bad.write_bytes(bad_data)

        with self.assertRaises(ValueError):
            inspect_esp_app_image(bad)

    def test_release_identity_is_immutable_in_database(self):
        with self.assertRaises(ValueError):
            register_release(
                self.db_path,
                product="FloraCore",
                target="esp32s3",
                version="1.1.0",
                channel="stable",
                binary_path="different.bin",
                binary_url="https://example.invalid/different.bin",
                sha256="cd" * 32,
                byte_size=123456,
            )


if __name__ == "__main__":
    unittest.main()
