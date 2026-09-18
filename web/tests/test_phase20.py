from __future__ import annotations

from contextlib import closing
from pathlib import Path
import json
import sqlite3
import tempfile
import time
import unittest

from flask import Flask

from floraos_commands import init_command_schema
from floraos_insights import care_score_v2, connect, save_runtime_from_authenticated_payload
from floraos_notifications import create_notification_in_transaction, init_notification_schema, sweep_offline
from floraos_automation_v2 import AutomationV2Error, validate_graph
from floraos_web_phase20 import fertilizer_parameters, init_phase20


class Phase20Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.db_path = self.root / "users.db"
        self.now = int(time.time())
        with closing(sqlite3.connect(self.db_path)) as db:
            db.executescript(
                """
                PRAGMA foreign_keys=ON;
                CREATE TABLE users(id INTEGER PRIMARY KEY, email TEXT NOT NULL, password_hash TEXT DEFAULT 'x');
                CREATE TABLE device_ownership(device_id TEXT PRIMARY KEY,user_id INTEGER NOT NULL,claimed_at INTEGER NOT NULL,nickname TEXT);
                CREATE TABLE device_messages(device_id TEXT NOT NULL,message_id TEXT NOT NULL,message_type TEXT NOT NULL,client_ts INTEGER NOT NULL,received_at INTEGER NOT NULL,PRIMARY KEY(device_id,message_id));
                CREATE TABLE device_telemetry(id INTEGER PRIMARY KEY AUTOINCREMENT,device_id TEXT NOT NULL,message_id TEXT NOT NULL,received_at INTEGER NOT NULL,payload_json TEXT NOT NULL);
                CREATE TABLE device_state(device_id TEXT PRIMARY KEY,last_seen INTEGER NOT NULL,last_message_type TEXT NOT NULL,last_message_id TEXT NOT NULL);
                CREATE TABLE floraos_plant_profiles(
                    id INTEGER PRIMARY KEY AUTOINCREMENT, profile_id TEXT UNIQUE NOT NULL,
                    user_id INTEGER NOT NULL, device_id TEXT NOT NULL, plant_name TEXT NOT NULL,
                    species_key TEXT NOT NULL, growth_stage TEXT NOT NULL, soil_min REAL NOT NULL,
                    soil_max REAL NOT NULL, light_min_lux REAL NOT NULL, light_max_lux REAL NOT NULL,
                    temperature_min_c REAL NOT NULL, temperature_max_c REAL NOT NULL,
                    humidity_min REAL NOT NULL, humidity_max REAL NOT NULL,
                    reservoir_low_percent REAL NOT NULL, fertilizer_low_percent REAL NOT NULL,
                    created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, UNIQUE(user_id,device_id)
                );
                """
            )
            db.executemany("INSERT INTO users(id,email) VALUES(?,?)", [(1,"owner@test"),(2,"other@test")])
            db.execute("INSERT INTO device_ownership VALUES('flora-a',1,?,'Mint Pot')", (self.now-1000,))
            db.execute("INSERT INTO device_ownership VALUES('flora-b',2,?,'Other Pot')", (self.now-1000,))
            db.execute("INSERT INTO device_messages VALUES('flora-a','hb1','heartbeat',0,?)", (self.now-30,))
            db.execute("INSERT INTO device_state(device_id,last_seen,last_message_type,last_message_id) VALUES('flora-a',?,'telemetry','tel1')", (self.now,))
            db.execute(
                """INSERT INTO floraos_plant_profiles(profile_id,user_id,device_id,plant_name,species_key,growth_stage,soil_min,soil_max,light_min_lux,light_max_lux,temperature_min_c,temperature_max_c,humidity_min,humidity_max,reservoir_low_percent,fertilizer_low_percent,created_at,updated_at)
                VALUES('plant1',1,'flora-a','Mint','peppermint','mature',40,65,8000,20000,18,27,40,70,20,20,?,?)""",
                (self.now, self.now),
            )
            for i in range(60):
                t = self.now - (59-i)*60
                payload = {"soil_adc": 3000-i*10, "soil_percent": 50-i*.15, "light_lux": 12000, "water_level_percent": 75-i*.25}
                db.execute("INSERT INTO device_telemetry(device_id,message_id,received_at,payload_json) VALUES('flora-a',?,?,?)", (f"t{i}",t,json.dumps(payload)))
            db.commit()

        init_command_schema(self.db_path)
        self.app = Flask(__name__, template_folder=str(self.root / "templates"))
        self.app.secret_key = "test"
        self.app.config["TESTING"] = True
        init_phase20(self.app, self.db_path)
        self.client = self.app.test_client()
        with self.client.session_transaction() as sess:
            sess["user_id"] = 1
            sess["email"] = "owner@test"
            sess["csrf_token"] = "csrf"
        with closing(connect(self.db_path)) as db:
            db.execute("UPDATE device_state SET command_protocol=1,command_protocol_reported_at=? WHERE device_id='flora-a'", (self.now,))
            db.commit()

    def tearDown(self):
        self.tmp.cleanup()

    @property
    def headers(self):
        return {"X-CSRF-Token":"csrf"}

    def test_history_is_owner_scoped_and_summarized(self):
        r = self.client.get("/api/intelligence/devices/flora-a/history?range=1h")
        self.assertEqual(r.status_code, 200, r.get_data(as_text=True))
        data = r.get_json()["data"]
        self.assertGreater(data["raw_sample_count"], 20)
        self.assertIsNotNone(data["summary"]["soil"]["average"])
        self.assertLessEqual(len(data["points"]), 320)
        self.assertEqual(self.client.get("/api/intelligence/devices/flora-b/history?range=1h").status_code, 404)

    def test_care_v2_missing_climate_is_not_a_failure(self):
        with closing(connect(self.db_path)) as db:
            care = care_score_v2(db, 1, "flora-a", self.now)
        self.assertIsNotNone(care["score"])
        self.assertIsNone(care["components"]["climate"]["score"])
        self.assertGreater(care["components"]["soil"]["score"], 0)

    def test_two_point_soil_calibration_endpoint(self):
        r = self.client.put(
            "/api/intelligence/devices/flora-a/calibrations/soil",
            headers=self.headers,
            json={"type":"two_point_percent","config":{"raw_zero":4000,"raw_full":2000}},
        )
        self.assertEqual(r.status_code, 200, r.get_data(as_text=True))

    def test_notification_dedup(self):
        init_notification_schema(self.db_path)
        with closing(connect(self.db_path)) as db:
            a = create_notification_in_transaction(db,user_id=1,device_id="flora-a",category="plant_warning",severity="warning",title="Dry",message="Dry",dedup_key="dry:a",now=self.now)
            b = create_notification_in_transaction(db,user_id=1,device_id="flora-a",category="plant_warning",severity="warning",title="Dry",message="Dry",dedup_key="dry:a",now=self.now+10)
            db.commit()
        self.assertIsNotNone(a)
        self.assertIsNone(b)

    def test_offline_sweep_uses_only_authenticated_heartbeat(self):
        with closing(connect(self.db_path)) as db:
            db.execute("UPDATE device_messages SET received_at=? WHERE device_id='flora-a' AND message_type='heartbeat'", (self.now-121,))
            db.commit()
        self.assertEqual(sweep_offline(self.db_path, now=self.now), 2)  # flora-a and flora-b(no heartbeat)

    def test_branching_graph_valid_and_cycle_rejected(self):
        graph = {"version":2,"nodes":[
            {"id":"t","type":"trigger_telemetry","config":{}},
            {"id":"c","type":"condition_water_above","config":{"percent":20}},
            {"id":"ok","type":"action_notify","config":{"severity":"info","title":"OK","message":"Water is sufficient"}},
            {"id":"low","type":"action_notify","config":{"severity":"warning","title":"Low","message":"Refill water"}},
        ],"edges":[
            {"from":"t","to":"c","when":"always"},{"from":"c","to":"ok","when":"true"},{"from":"c","to":"low","when":"false"},
        ]}
        valid = validate_graph(graph)
        self.assertEqual(valid["version"],2)
        graph["edges"].append({"from":"ok","to":"c","when":"always"})
        with self.assertRaises(AutomationV2Error): validate_graph(graph)

    def test_recommendation_installs_disabled(self):
        r = self.client.post(
            "/api/intelligence/devices/flora-a/recommendations/keep-soil-in-range/install",
            headers=self.headers,
            json={"timezone":"UTC"},
        )
        self.assertEqual(r.status_code,200,r.get_data(as_text=True))
        self.assertFalse(r.get_json()["data"]["enabled"])

    def test_fertilizer_fails_closed_without_authenticated_capability(self):
        with closing(connect(self.db_path)) as db:
            with self.assertRaises(AutomationV2Error) as ctx:
                fertilizer_parameters(db,user_id=1,device_id="flora-a",volume_ml=2,now=self.now)
        self.assertEqual(ctx.exception.code,"fertilizer_capability_unavailable")

    def test_fertilizer_requires_capability_and_calibration_then_calculates_runtime(self):
        with closing(connect(self.db_path)) as db:
            save_runtime_from_authenticated_payload(db,"flora-a",{"capabilities":{"actuators":{"fertilizer_pump":True},"commands":{"fertilize":1}}},self.now)
            db.execute("INSERT INTO floraos_device_calibrations(user_id,device_id,sensor_key,calibration_type,config_json,updated_at) VALUES(1,'flora-a','fertilizer_pump','pump_flow',?,?)",(json.dumps({"ml_per_second":1,"max_single_ml":10,"max_daily_ml":20}),self.now))
            db.commit()
            params = fertilizer_parameters(db,user_id=1,device_id="flora-a",volume_ml=2.5,now=self.now)
        self.assertEqual(params["duration_ms"],2500)
        self.assertEqual(params["volume_ml"],2.5)

    def test_manual_water_uses_existing_command_queue(self):
        r = self.client.post(
            "/api/intelligence/devices/flora-a/commands",
            headers=self.headers,
            json={"type":"water","parameters":{"duration_ms":1000},"idempotency_key":"test-command-0001"},
        )
        self.assertEqual(r.status_code,200,r.get_data(as_text=True))
        self.assertEqual(r.get_json()["data"]["command"]["type"],"water")


if __name__ == "__main__":
    unittest.main()
