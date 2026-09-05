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
from floraos_automations import (
    init_automations,
    validate_graph,
    AutomationValidationError,
)
from floraos_device_api import init_device_api
from floraos_ota import init_ota


DEVICE_ID = "floracore-autotest0001"
D2S = bytes.fromhex("71" * 32)
S2D = bytes.fromhex("82" * 32)
DEVICE_PATH = "/api/device/v1/message"
PROTOCOL_LABEL = "floraos-e2ee-v1"


def aad(device_id: str, direction: str) -> bytes:
    return f"{PROTOCOL_LABEL}|{device_id}|{direction}|{DEVICE_PATH}".encode()


def water_graph() -> dict:
    return {
        "version": 1,
        "nodes": [
            {
                "id": "trigger",
                "type": "trigger_soil_below",
                "x": 100,
                "y": 100,
                "config": {"percent": 35},
            },
            {
                "id": "cooldown",
                "type": "cooldown",
                "x": 360,
                "y": 100,
                "config": {"seconds": 3600},
            },
            {
                "id": "water",
                "type": "action_water",
                "x": 620,
                "y": 100,
                "config": {"duration_ms": 5000},
            },
        ],
        "edges": [
            {"from": "trigger", "to": "cooldown"},
            {"from": "cooldown", "to": "water"},
        ],
    }


class AutomationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.db_path = self.root / "users.db"
        self.keys_path = self.root / "device_keys.json"
        self.counter = 0
        self.now = int(time.time())

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
                    password_hash TEXT NOT NULL
                )
                """
            )
            db.execute(
                "INSERT INTO users(id,email,password_hash) VALUES(1,?,?)",
                ("owner@example.test", "unused"),
            )
            db.commit()

        self.app = Flask(__name__, template_folder=str(self.root / "templates"))
        self.app.secret_key = "automation-test-secret"
        self.app.config["TESTING"] = True

        init_enrollment_api(self.app, self.db_path)
        init_ota(
            self.app,
            self.db_path,
            firmware_root=self.root / "firmware" / "floracore",
        )
        init_automations(self.app, self.db_path)
        init_device_api(self.app, self.db_path)

        with closing(sqlite3.connect(self.db_path)) as db:
            db.execute(
                """
                INSERT INTO device_ownership(device_id,user_id,claimed_at,nickname)
                VALUES(?,?,?,?)
                """,
                (DEVICE_ID, 1, self.now - 100, "Automation Pot"),
            )
            db.commit()

        self.client = self.app.test_client()
        with self.client.session_transaction() as sess:
            sess["user_id"] = 1
            sess["email"] = "owner@example.test"
            sess["csrf_token"] = "csrf-test-token"

        # Command delivery is fail-closed until firmware advertises protocol v1.
        self.send_device(
            "heartbeat",
            {
                "command_protocol": 1,
                "mode": "NORMAL",
                "product": "FloraCore",
                "target": "esp32s3",
                "firmware_version": "1.0.1",
                "firmware_channel": "stable",
            },
        )

    def tearDown(self):
        if self.old_keys is None:
            os.environ.pop("FLORAOS_DEVICE_KEYS_FILE", None)
        else:
            os.environ["FLORAOS_DEVICE_KEYS_FILE"] = self.old_keys
        self.tmp.cleanup()

    @property
    def csrf_headers(self) -> dict[str, str]:
        return {"X-CSRF-Token": "csrf-test-token"}

    def send_device(self, message_type: str, payload: dict) -> dict:
        self.counter += 1
        message_id = f"{self.counter:032x}"
        nonce = self.counter.to_bytes(12, "big")
        inner = {
            "message_id": message_id,
            "type": message_type,
            "ts": int(time.time()),
            "payload": payload,
        }
        ciphertext = AESGCM(D2S).encrypt(
            nonce,
            json.dumps(inner, separators=(",", ":")).encode(),
            aad(DEVICE_ID, "d2s"),
        )
        response = self.client.post(
            DEVICE_PATH,
            json={
                "v": 1,
                "device_id": DEVICE_ID,
                "nonce": nonce.hex(),
                "ciphertext": ciphertext.hex(),
            },
        )
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        envelope = response.get_json()
        plaintext = AESGCM(S2D).decrypt(
            bytes.fromhex(envelope["nonce"]),
            bytes.fromhex(envelope["ciphertext"]),
            aad(DEVICE_ID, "s2d"),
        )
        return json.loads(plaintext)

    def create_and_enable(self) -> str:
        response = self.client.post(
            "/api/automations",
            headers=self.csrf_headers,
            json={
                "name": "Water dry plant",
                "device_id": DEVICE_ID,
                "timezone": "UTC",
                "graph": water_graph(),
            },
        )
        self.assertEqual(response.status_code, 201, response.get_data(as_text=True))
        automation_id = response.get_json()["data"]["automation_id"]

        response = self.client.post(
            f"/api/automations/{automation_id}/enabled",
            headers=self.csrf_headers,
            json={
                "enabled": True,
                "acknowledge_advanced_control": True,
            },
        )
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        self.assertTrue(response.get_json()["data"]["enabled"])
        return automation_id

    def test_graph_rejects_branching(self):
        graph = water_graph()
        graph["nodes"].insert(
            1,
            {
                "id": "extra",
                "type": "condition_light_below",
                "x": 240,
                "y": 220,
                "config": {"lux": 1000},
            },
        )
        graph["edges"] = [
            {"from": "trigger", "to": "cooldown"},
            {"from": "trigger", "to": "extra"},
            {"from": "cooldown", "to": "water"},
        ]
        with self.assertRaises(AutomationValidationError):
            validate_graph(graph)

    def test_enable_requires_explicit_advanced_acknowledgement(self):
        response = self.client.post(
            "/api/automations",
            headers=self.csrf_headers,
            json={
                "name": "Water dry plant",
                "device_id": DEVICE_ID,
                "timezone": "UTC",
                "graph": water_graph(),
            },
        )
        automation_id = response.get_json()["data"]["automation_id"]

        refused = self.client.post(
            f"/api/automations/{automation_id}/enabled",
            headers=self.csrf_headers,
            json={"enabled": True},
        )
        self.assertEqual(refused.status_code, 409)
        self.assertEqual(
            refused.get_json()["error"]["code"],
            "advanced_acknowledgement_required",
        )

    def test_authenticated_telemetry_queues_and_delivers_normal_command(self):
        automation_id = self.create_and_enable()

        reply = self.send_device(
            "telemetry",
            {
                "soil_percent": 20,
                "light_lux": 5000,
                "mode": "NORMAL",
                "command_protocol": 1,
            },
        )

        self.assertEqual(len(reply["commands"]), 1)
        self.assertEqual(reply["commands"][0]["type"], "water")
        self.assertEqual(reply["commands"][0]["parameters"]["duration_ms"], 5000)
        self.assertFalse(reply["ota"]["available"])

        history = self.client.get(f"/api/automations/{automation_id}/runs")
        self.assertEqual(history.status_code, 200)
        runs = history.get_json()["data"]
        self.assertEqual(len(runs), 1)
        self.assertIn(runs[0]["status"], {"queued", "delivered"})
        self.assertTrue(runs[0]["command_id"].startswith("cmd_"))

    def test_dry_run_simulation_never_queues_a_command(self):
        before = None
        with closing(sqlite3.connect(self.db_path)) as db:
            before = db.execute(
                "SELECT COUNT(*) FROM device_commands WHERE device_id = ?",
                (DEVICE_ID,),
            ).fetchone()[0]

        response = self.client.post(
            "/api/automations/simulate",
            headers=self.csrf_headers,
            json={
                "automation_id": None,
                "device_id": DEVICE_ID,
                "timezone": "UTC",
                "graph": water_graph(),
                "source": "custom",
                "inputs": {
                    "soil_percent": 20,
                    "light_lux": 5000,
                    "local_time": "12:00",
                },
            },
        )
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        data = response.get_json()["data"]

        self.assertTrue(data["dry_run"])
        self.assertFalse(data["command_queued"])
        self.assertTrue(data["logic_passed"])
        self.assertEqual(data["outcome"], "would_execute")
        self.assertEqual(data["action"]["type"], "water")
        self.assertEqual(data["action"]["parameters"]["duration_ms"], 5000)

        with closing(sqlite3.connect(self.db_path)) as db:
            after = db.execute(
                "SELECT COUNT(*) FROM device_commands WHERE device_id = ?",
                (DEVICE_ID,),
            ).fetchone()[0]
        self.assertEqual(after, before)

    def test_dry_run_reports_where_the_flow_stops(self):
        response = self.client.post(
            "/api/automations/simulate",
            headers=self.csrf_headers,
            json={
                "device_id": DEVICE_ID,
                "timezone": "UTC",
                "graph": water_graph(),
                "source": "custom",
                "inputs": {
                    "soil_percent": 80,
                    "light_lux": 5000,
                    "local_time": "12:00",
                },
            },
        )
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        data = response.get_json()["data"]

        self.assertFalse(data["logic_passed"])
        self.assertEqual(data["outcome"], "stopped")
        self.assertEqual(data["steps"][0]["status"], "failed")
        self.assertEqual(data["steps"][-1]["status"], "not_reached")
        self.assertIsNone(data["action"])

    def test_setup_state_blocks_automation(self):
        self.create_and_enable()

        reply = self.send_device(
            "telemetry",
            {
                "soil_percent": 10,
                "mode": "SETUP_CLAIMING",
                "command_protocol": 1,
            },
        )
        self.assertEqual(reply["commands"], [])

        with closing(sqlite3.connect(self.db_path)) as db:
            count = db.execute(
                "SELECT COUNT(*) FROM device_commands WHERE device_id = ?",
                (DEVICE_ID,),
            ).fetchone()[0]
        self.assertEqual(count, 0)

    def test_automation_cooldown_prevents_repeated_watering(self):
        self.create_and_enable()

        first = self.send_device(
            "telemetry",
            {
                "soil_percent": 20,
                "mode": "NORMAL",
                "command_protocol": 1,
            },
        )
        self.assertEqual(len(first["commands"]), 1)

        second = self.send_device(
            "telemetry",
            {
                "soil_percent": 20,
                "mode": "NORMAL",
                "command_protocol": 1,
            },
        )
        self.assertEqual(second["commands"], [])

        with closing(sqlite3.connect(self.db_path)) as db:
            count = db.execute(
                "SELECT COUNT(*) FROM device_commands WHERE device_id = ?",
                (DEVICE_ID,),
            ).fetchone()[0]
        self.assertEqual(count, 1)


if __name__ == "__main__":
    unittest.main()
