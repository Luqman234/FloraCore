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
from floraos_ota import init_ota, register_release
from floraos_public_api import create_personal_access_token, init_public_api


DEVICE_ID = "floracore-v12test0001"
OTHER_DEVICE_ID = "floracore-v12other001"
D2S = bytes.fromhex("31" * 32)
S2D = bytes.fromhex("42" * 32)
OTHER_D2S = bytes.fromhex("53" * 32)
OTHER_S2D = bytes.fromhex("64" * 32)
DEVICE_PATH = "/api/device/v1/message"
PROTOCOL_LABEL = "floraos-e2ee-v1"


def aad(device_id: str, direction: str) -> bytes:
    return f"{PROTOCOL_LABEL}|{device_id}|{direction}|{DEVICE_PATH}".encode()


class PublicApiV12Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.db_path = self.root / "users.db"
        self.keys_path = self.root / "device_keys.json"
        self.now = int(time.time())
        self.counter = 0

        self.keys_path.write_text(
            json.dumps(
                {
                    DEVICE_ID: {
                        "d2s_key": D2S.hex(),
                        "s2d_key": S2D.hex(),
                    },
                    OTHER_DEVICE_ID: {
                        "d2s_key": OTHER_D2S.hex(),
                        "s2d_key": OTHER_S2D.hex(),
                    },
                }
            ),
            encoding="utf-8",
        )
        self.old_keys = os.environ.get("FLORAOS_DEVICE_KEYS_FILE")
        os.environ["FLORAOS_DEVICE_KEYS_FILE"] = str(self.keys_path)

        with closing(sqlite3.connect(self.db_path)) as db:
            db.execute("PRAGMA foreign_keys = ON")
            db.execute(
                """
                CREATE TABLE users(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL
                )
                """
            )
            db.executemany(
                "INSERT INTO users(id,email,password_hash) VALUES(?,?,?)",
                [
                    (1, "owner@example.test", "unused"),
                    (2, "other@example.test", "unused"),
                ],
            )
            db.commit()

        self.app = Flask(__name__)
        self.app.secret_key = "test-secret"
        self.app.config["TESTING"] = True

        init_enrollment_api(self.app, self.db_path)
        init_ota(
            self.app,
            self.db_path,
            firmware_root=self.root / "firmware" / "floracore",
        )
        init_device_api(self.app, self.db_path)
        init_public_api(self.app, self.db_path)

        with closing(sqlite3.connect(self.db_path)) as db:
            db.execute(
                """
                INSERT INTO device_ownership(device_id,user_id,claimed_at,nickname)
                VALUES(?,?,?,?)
                """,
                (DEVICE_ID, 1, self.now - 100, "Mint Pot"),
            )
            db.execute(
                """
                INSERT INTO device_ownership(device_id,user_id,claimed_at,nickname)
                VALUES(?,?,?,?)
                """,
                (OTHER_DEVICE_ID, 2, self.now - 100, "Other Pot"),
            )
            db.commit()

        self.client = self.app.test_client()
        self.control_token = self.create_pat(
            1,
            (
                "devices:read",
                "devices:control",
                "telemetry:read",
                "firmware:read",
            ),
        )
        self.read_token = self.create_pat(
            1,
            ("devices:read", "telemetry:read"),
        )
        self.other_control_token = self.create_pat(
            2,
            ("devices:read", "devices:control"),
        )

        # Device must explicitly advertise command protocol support before the
        # public control API will queue anything.
        self.send_device(
            DEVICE_ID,
            D2S,
            S2D,
            "heartbeat",
            {
                "product": "FloraCore",
                "target": "esp32s3",
                "firmware_version": "1.0.1",
                "firmware_channel": "stable",
                "command_protocol": 1,
                "mode": "NORMAL",
            },
        )

    def tearDown(self):
        if self.old_keys is None:
            os.environ.pop("FLORAOS_DEVICE_KEYS_FILE", None)
        else:
            os.environ["FLORAOS_DEVICE_KEYS_FILE"] = self.old_keys
        self.tmp.cleanup()

    def create_pat(self, user_id: int, scopes: tuple[str, ...]) -> str:
        created = create_personal_access_token(
            self.db_path,
            user_id=user_id,
            name="v1.2 test token",
            scopes=scopes,
            lifetime_days=30,
            now=self.now,
        )
        return created["token"]

    @staticmethod
    def auth(token: str, **extra: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {token}", **extra}

    def send_device(
        self,
        device_id: str,
        d2s_key: bytes,
        s2d_key: bytes,
        message_type: str,
        payload: dict,
    ) -> dict:
        self.counter += 1
        message_id = f"{self.counter:032x}"
        nonce = self.counter.to_bytes(12, "big")
        inner = {
            "message_id": message_id,
            "type": message_type,
            "ts": int(time.time()),
            "payload": payload,
        }
        ciphertext = AESGCM(d2s_key).encrypt(
            nonce,
            json.dumps(inner, separators=(",", ":")).encode(),
            aad(device_id, "d2s"),
        )
        response = self.client.post(
            DEVICE_PATH,
            json={
                "v": 1,
                "device_id": device_id,
                "nonce": nonce.hex(),
                "ciphertext": ciphertext.hex(),
            },
        )
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        envelope = response.get_json()
        plaintext = AESGCM(s2d_key).decrypt(
            bytes.fromhex(envelope["nonce"]),
            bytes.fromhex(envelope["ciphertext"]),
            aad(device_id, "s2d"),
        )
        return json.loads(plaintext)

    def post_command(self, body: dict, key: str = "request-key-0001", token: str | None = None):
        return self.client.post(
            f"/api/v1/devices/{DEVICE_ID}/commands",
            headers=self.auth(
                token or self.control_token,
                **{"Idempotency-Key": key},
            ),
            json=body,
        )

    def test_discovery_reports_v12_control_but_not_ota_control(self):
        response = self.client.get("/api/v1")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()["data"]
        self.assertEqual(data["version"], "1.2")
        self.assertTrue(data["physical_device_control"])
        self.assertFalse(data["ota_control"])
        scopes = {item["scope"] for item in data["scopes"]}
        self.assertIn("devices:control", scopes)
        self.assertIn("firmware:read", scopes)

    def test_existing_read_token_does_not_gain_control_scope(self):
        response = self.post_command(
            {"type": "water", "parameters": {"duration_ms": 1000}},
            token=self.read_token,
        )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.get_json()["error"]["code"], "insufficient_scope")

    def test_water_command_queues_delivers_and_completes(self):
        response = self.post_command(
            {"type": "water", "parameters": {"duration_ms": 1500}},
            key="watering-request-0001",
        )
        self.assertEqual(response.status_code, 201, response.get_data(as_text=True))
        command = response.get_json()["data"]
        command_id = command["command_id"]
        self.assertEqual(command["status"], "queued")

        # Retry of the exact same HTTP action is idempotent.
        retry = self.post_command(
            {"type": "water", "parameters": {"duration_ms": 1500}},
            key="watering-request-0001",
        )
        self.assertEqual(retry.status_code, 200)
        self.assertEqual(retry.get_json()["data"]["command_id"], command_id)
        self.assertTrue(retry.get_json()["meta"]["idempotent_replay"])

        reply = self.send_device(
            DEVICE_ID,
            D2S,
            S2D,
            "heartbeat",
            {
                "product": "FloraCore",
                "target": "esp32s3",
                "firmware_version": "1.0.1",
                "firmware_channel": "stable",
                "command_protocol": 1,
                "mode": "NORMAL",
            },
        )
        self.assertEqual(len(reply["commands"]), 1)
        self.assertEqual(reply["commands"][0]["id"], command_id)
        self.assertEqual(reply["commands"][0]["type"], "water")
        self.assertFalse(reply["ota"]["available"])

        result_reply = self.send_device(
            DEVICE_ID,
            D2S,
            S2D,
            "command_result",
            {
                "command_id": command_id,
                "status": "completed",
                "result": {"duration_ms": 1500},
            },
        )
        self.assertTrue(result_reply["command_result_received"])

        status = self.client.get(
            f"/api/v1/devices/{DEVICE_ID}/commands/{command_id}",
            headers=self.auth(self.control_token),
        )
        self.assertEqual(status.status_code, 200)
        self.assertEqual(status.get_json()["data"]["status"], "completed")

    def test_same_idempotency_key_cannot_mean_a_different_action(self):
        first = self.post_command(
            {"type": "grow_light", "parameters": {"state": "off"}},
            key="same-key-different-body",
        )
        self.assertEqual(first.status_code, 201)
        second = self.post_command(
            {
                "type": "grow_light",
                "parameters": {"state": "on", "duration_seconds": 600},
            },
            key="same-key-different-body",
        )
        self.assertEqual(second.status_code, 409)
        self.assertEqual(second.get_json()["error"]["code"], "idempotency_conflict")

    def test_ota_raw_gpio_and_unbounded_water_are_rejected(self):
        for command_type in ("ota", "set_gpio", "raw_command"):
            response = self.post_command(
                {"type": command_type, "parameters": {}},
                key=f"reject-{command_type}-0001",
            )
            self.assertEqual(response.status_code, 400)
            self.assertEqual(response.get_json()["error"]["code"], "unsupported_command")

        response = self.post_command(
            {"type": "water", "parameters": {"duration_ms": 999999}},
            key="unsafe-water-0001",
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()["error"]["code"], "unsafe_command")

    def test_setup_state_does_not_receive_queued_command(self):
        response = self.post_command(
            {
                "type": "grow_light",
                "parameters": {"state": "on", "duration_seconds": 300},
            },
            key="setup-block-0001",
        )
        self.assertEqual(response.status_code, 201)

        reply = self.send_device(
            DEVICE_ID,
            D2S,
            S2D,
            "heartbeat",
            {
                "command_protocol": 1,
                "mode": "SETUP_CLAIMING",
            },
        )
        self.assertEqual(reply["commands"], [])

    def test_offline_and_no_command_protocol_are_rejected(self):
        with closing(sqlite3.connect(self.db_path)) as db:
            db.execute(
                "UPDATE device_messages SET received_at = ? WHERE device_id = ? AND message_type = 'heartbeat'",
                (int(time.time()) - 121, DEVICE_ID),
            )
            db.commit()
        response = self.post_command(
            {"type": "grow_light", "parameters": {"state": "off"}},
            key="offline-test-0001",
        )
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.get_json()["error"]["code"], "device_offline")

        # Restore heartbeat but remove protocol capability.
        self.send_device(
            DEVICE_ID,
            D2S,
            S2D,
            "heartbeat",
            {"mode": "NORMAL"},
        )
        with closing(sqlite3.connect(self.db_path)) as db:
            db.execute(
                "UPDATE device_state SET command_protocol = NULL WHERE device_id = ?",
                (DEVICE_ID,),
            )
            db.commit()
        response = self.post_command(
            {"type": "grow_light", "parameters": {"state": "off"}},
            key="protocol-test-0001",
        )
        self.assertEqual(response.status_code, 409)
        self.assertEqual(
            response.get_json()["error"]["code"],
            "command_protocol_unavailable",
        )

    def test_other_user_cannot_learn_or_control_owner_device(self):
        response = self.post_command(
            {"type": "grow_light", "parameters": {"state": "off"}},
            key="other-owner-0001",
            token=self.other_control_token,
        )
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.get_json()["error"]["code"], "device_not_found")

    def test_firmware_visibility_has_separate_scope(self):
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
            release_notes="Stable test release",
        )

        response = self.client.get(
            f"/api/v1/devices/{DEVICE_ID}/firmware",
            headers=self.auth(self.control_token),
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["data"]["installed"], "1.0.1")
        self.assertEqual(response.get_json()["data"]["available"], "1.1.0")

        denied = self.client.get(
            f"/api/v1/devices/{DEVICE_ID}/firmware",
            headers=self.auth(self.read_token),
        )
        self.assertEqual(denied.status_code, 403)
        self.assertEqual(denied.get_json()["error"]["code"], "insufficient_scope")

    def test_only_queued_command_can_be_cancelled_safely(self):
        response = self.post_command(
            {"type": "grow_light", "parameters": {"state": "off"}},
            key="cancel-before-delivery",
        )
        command_id = response.get_json()["data"]["command_id"]
        cancelled = self.client.delete(
            f"/api/v1/devices/{DEVICE_ID}/commands/{command_id}",
            headers=self.auth(self.control_token),
        )
        self.assertEqual(cancelled.status_code, 200)
        self.assertEqual(cancelled.get_json()["data"]["status"], "cancelled")

        second = self.post_command(
            {"type": "grow_light", "parameters": {"state": "off"}},
            key="cannot-cancel-delivered",
        )
        delivered_id = second.get_json()["data"]["command_id"]
        self.send_device(
            DEVICE_ID,
            D2S,
            S2D,
            "heartbeat",
            {"command_protocol": 1, "mode": "NORMAL"},
        )
        refused = self.client.delete(
            f"/api/v1/devices/{DEVICE_ID}/commands/{delivered_id}",
            headers=self.auth(self.control_token),
        )
        self.assertEqual(refused.status_code, 409)
        self.assertEqual(
            refused.get_json()["error"]["code"],
            "command_already_delivered",
        )


if __name__ == "__main__":
    unittest.main()
