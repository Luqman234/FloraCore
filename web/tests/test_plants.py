from __future__ import annotations

from contextlib import closing
import json
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path

from flask import Flask

from floraos_plants import init_plants


class PlantProfileTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.db_path = self.root / "users.db"

        now = int(time.time())

        with closing(sqlite3.connect(self.db_path)) as db:
            db.executescript(
                """
                CREATE TABLE users(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT NOT NULL
                );

                CREATE TABLE device_ownership(
                    user_id INTEGER NOT NULL,
                    device_id TEXT NOT NULL,
                    nickname TEXT
                );

                CREATE TABLE device_telemetry(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id TEXT NOT NULL,
                    message_id TEXT,
                    received_at INTEGER NOT NULL,
                    payload_json TEXT NOT NULL
                );

                CREATE TABLE device_messages(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id TEXT NOT NULL,
                    message_type TEXT NOT NULL,
                    received_at INTEGER NOT NULL
                );
                """
            )
            db.execute(
                "INSERT INTO users(id,email) VALUES(1,'owner@example.test')"
            )
            db.execute(
                "INSERT INTO users(id,email) VALUES(2,'other@example.test')"
            )
            db.execute(
                """
                INSERT INTO device_ownership(user_id,device_id,nickname)
                VALUES(1,'flora-a','Kitchen Pot')
                """
            )
            db.execute(
                """
                INSERT INTO device_ownership(user_id,device_id,nickname)
                VALUES(2,'flora-b','Other Pot')
                """
            )
            db.execute(
                """
                INSERT INTO device_messages(device_id,message_type,received_at)
                VALUES('flora-a','heartbeat',?)
                """,
                (now,),
            )
            db.execute(
                """
                INSERT INTO device_telemetry(device_id,message_id,received_at,payload_json)
                VALUES('flora-a','msg-1',?,?)
                """,
                (
                    now,
                    json.dumps(
                        {
                            "telemetry": {
                                "soil_percent": 50,
                                "light_lux": 12000,
                                "temperature_c": 24,
                                "humidity_percent": 55,
                                "water_level_percent": 72,
                                "fertilizer_level_percent": 61,
                            }
                        }
                    ),
                ),
            )
            db.commit()

        self.app = Flask(
            __name__,
            template_folder=str(self.root / "templates"),
        )
        self.app.secret_key = "plants-test-secret"
        self.app.config["TESTING"] = True
        init_plants(self.app, self.db_path)
        self.client = self.app.test_client()

        with self.client.session_transaction() as sess:
            sess["user_id"] = 1
            sess["csrf_token"] = "csrf-test"

    def tearDown(self):
        self.tmp.cleanup()

    @staticmethod
    def peppermint_payload():
        return {
            "plant_name": "Mint One",
            "species_key": "peppermint",
            "growth_stage": "mature",
            "soil_min": 40,
            "soil_max": 65,
            "light_min_lux": 8000,
            "light_max_lux": 20000,
            "temperature_min_c": 18,
            "temperature_max_c": 27,
            "humidity_min": 40,
            "humidity_max": 70,
            "reservoir_low_percent": 20,
            "fertilizer_low_percent": 20,
        }

    def test_catalog_is_authenticated_and_contains_presets(self):
        response = self.client.get("/api/plants/catalog")
        self.assertEqual(response.status_code, 200)
        keys = {item["key"] for item in response.get_json()["data"]}
        self.assertIn("peppermint", keys)
        self.assertIn("custom", keys)

    def test_profile_create_and_care_analysis(self):
        create = self.client.put(
            "/api/plants/flora-a",
            headers={"X-CSRF-Token": "csrf-test"},
            json=self.peppermint_payload(),
        )
        self.assertEqual(create.status_code, 200, create.get_data(as_text=True))
        self.assertEqual(create.get_json()["data"]["species_key"], "peppermint")

        care = self.client.get("/api/plants/flora-a/care")
        self.assertEqual(care.status_code, 200, care.get_data(as_text=True))
        payload = care.get_json()["data"]

        self.assertTrue(payload["care"]["online"])
        self.assertEqual(payload["care"]["score"], 100)
        self.assertEqual(payload["care"]["confidence_percent"], 100)

        statuses = {
            metric["key"]: metric["status"]
            for metric in payload["care"]["metrics"]
        }
        self.assertEqual(statuses["soil"], "ideal")
        self.assertEqual(statuses["light"], "ideal")

    def test_profile_update_is_upsert_not_duplicate(self):
        first = self.client.put(
            "/api/plants/flora-a",
            headers={"X-CSRF-Token": "csrf-test"},
            json=self.peppermint_payload(),
        )
        self.assertEqual(first.status_code, 200)

        updated = self.peppermint_payload()
        updated["plant_name"] = "Mint Updated"
        second = self.client.put(
            "/api/plants/flora-a",
            headers={"X-CSRF-Token": "csrf-test"},
            json=updated,
        )
        self.assertEqual(second.status_code, 200)
        self.assertEqual(second.get_json()["data"]["plant_name"], "Mint Updated")

        with closing(sqlite3.connect(self.db_path)) as db:
            count = db.execute(
                """
                SELECT COUNT(*)
                FROM floraos_plant_profiles
                WHERE user_id = 1 AND device_id = 'flora-a'
                """
            ).fetchone()[0]
        self.assertEqual(count, 1)

    def test_other_users_device_is_404(self):
        response = self.client.get("/api/plants/flora-b/care")
        self.assertEqual(response.status_code, 404)

        response = self.client.put(
            "/api/plants/flora-b",
            headers={"X-CSRF-Token": "csrf-test"},
            json=self.peppermint_payload(),
        )
        self.assertEqual(response.status_code, 404)

    def test_profile_write_requires_csrf(self):
        response = self.client.put(
            "/api/plants/flora-a",
            json=self.peppermint_payload(),
        )
        self.assertEqual(response.status_code, 403)

    def test_invalid_target_range_is_rejected(self):
        body = self.peppermint_payload()
        body["soil_min"] = 80
        body["soil_max"] = 20

        response = self.client.put(
            "/api/plants/flora-a",
            headers={"X-CSRF-Token": "csrf-test"},
            json=body,
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("minimum", response.get_json()["error"].lower())

    def test_no_profile_returns_no_care_instead_of_fabricating(self):
        response = self.client.get("/api/plants/flora-a/care")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()["data"]
        self.assertIsNone(data["profile"])
        self.assertIsNone(data["care"])

    def test_delete_profile(self):
        self.client.put(
            "/api/plants/flora-a",
            headers={"X-CSRF-Token": "csrf-test"},
            json=self.peppermint_payload(),
        )

        delete = self.client.delete(
            "/api/plants/flora-a",
            headers={"X-CSRF-Token": "csrf-test"},
        )
        self.assertEqual(delete.status_code, 200)
        self.assertTrue(delete.get_json()["deleted"])

        care = self.client.get("/api/plants/flora-a/care")
        self.assertIsNone(care.get_json()["data"]["profile"])


if __name__ == "__main__":
    unittest.main()
