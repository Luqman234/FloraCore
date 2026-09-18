from __future__ import annotations

from collections import defaultdict
from contextlib import closing
from statistics import median
from pathlib import Path
from typing import Any
import json
import math
import sqlite3
import time

ONLINE_SECONDS = 120
TELEMETRY_STALE_SECONDS = 15 * 60
MAX_HISTORY_SECONDS = 90 * 24 * 60 * 60
MAX_HISTORY_POINTS = 320
RANGES = {
    "1h": 3600,
    "24h": 86400,
    "7d": 7 * 86400,
    "30d": 30 * 86400,
}

METRICS: dict[str, dict[str, Any]] = {
    "soil": {
        "label": "Soil moisture",
        "unit": "%",
        "aliases": ("soil_percent", "soil_moisture_percent", "soil_moisture", "soil"),
        "raw_aliases": ("soil_adc", "soil_raw", "soil_moisture_raw"),
    },
    "light": {
        "label": "Light",
        "unit": "lux",
        "aliases": ("light_lux", "lux", "illuminance_lux", "illuminance"),
        "raw_aliases": ("light_raw",),
    },
    "temperature": {
        "label": "Temperature",
        "unit": "°C",
        "aliases": ("temperature_c", "temperature", "temp_c", "air_temperature_c"),
        "raw_aliases": (),
    },
    "humidity": {
        "label": "Humidity",
        "unit": "%",
        "aliases": ("humidity_percent", "humidity", "relative_humidity", "rh_percent"),
        "raw_aliases": (),
    },
    "water": {
        "label": "Water reservoir",
        "unit": "%",
        "aliases": ("water_level_percent", "water_percent", "reservoir_percent", "reservoir_level_percent"),
        "raw_aliases": ("water_level_raw", "water_raw", "reservoir_raw"),
    },
    "fertilizer": {
        "label": "Fertilizer reservoir",
        "unit": "%",
        "aliases": ("fertilizer_level_percent", "fertilizer_percent", "nutrient_percent", "nutrient_level_percent"),
        "raw_aliases": ("fertilizer_level_raw", "fertilizer_raw", "nutrient_raw"),
    },
}


def connect(db_path: str | Path) -> sqlite3.Connection:
    db = sqlite3.connect(Path(db_path), timeout=5)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    db.execute("PRAGMA busy_timeout = 5000")
    return db


def table_exists(db: sqlite3.Connection, name: str) -> bool:
    return db.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=? LIMIT 1", (name,)
    ).fetchone() is not None


def table_columns(db: sqlite3.Connection, name: str) -> set[str]:
    if not table_exists(db, name):
        return set()
    return {str(row["name"]) for row in db.execute(f'PRAGMA table_info("{name}")')}


def json_object(raw: Any) -> dict[str, Any]:
    if isinstance(raw, dict):
        return dict(raw)
    if raw is None:
        return {}
    try:
        value = json.loads(str(raw))
    except (TypeError, ValueError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def nested_sources(payload: dict[str, Any]) -> list[dict[str, Any]]:
    result = [payload]
    for key in ("telemetry", "sensors", "state", "diagnostics"):
        value = payload.get(key)
        if isinstance(value, dict):
            result.append(value)
    return result


def numeric(payload: dict[str, Any] | None, aliases: tuple[str, ...]) -> float | None:
    if not isinstance(payload, dict):
        return None
    for source in nested_sources(payload):
        for key in aliases:
            value = source.get(key)
            if isinstance(value, bool):
                continue
            if isinstance(value, (int, float)) and math.isfinite(float(value)):
                return float(value)
    return None


def init_insights_schema(db_path: str | Path) -> None:
    with closing(connect(db_path)) as db:
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS floraos_schema_migrations (
                migration_id TEXT PRIMARY KEY,
                applied_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS floraos_device_runtime (
                device_id TEXT PRIMARY KEY,
                capabilities_json TEXT NOT NULL DEFAULT '{}',
                diagnostics_json TEXT NOT NULL DEFAULT '{}',
                capabilities_reported_at INTEGER,
                diagnostics_reported_at INTEGER,
                updated_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS floraos_device_calibrations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                device_id TEXT NOT NULL,
                sensor_key TEXT NOT NULL,
                calibration_type TEXT NOT NULL,
                config_json TEXT NOT NULL,
                updated_at INTEGER NOT NULL,
                UNIQUE(user_id, device_id, sensor_key),
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS floraos_plant_details (
                user_id INTEGER NOT NULL,
                device_id TEXT NOT NULL,
                scientific_name TEXT,
                planted_at INTEGER,
                notes TEXT,
                avatar TEXT,
                updated_at INTEGER NOT NULL,
                PRIMARY KEY(user_id, device_id),
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS floraos_reservoir_refills (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                refill_id TEXT UNIQUE NOT NULL,
                user_id INTEGER NOT NULL,
                device_id TEXT NOT NULL,
                reservoir TEXT NOT NULL,
                amount_ml REAL,
                level_percent REAL,
                notes TEXT,
                created_at INTEGER NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_floraos_refills_device
                ON floraos_reservoir_refills(user_id, device_id, reservoir, created_at DESC);
            """
        )
        db.execute(
            "INSERT OR IGNORE INTO floraos_schema_migrations(migration_id, applied_at) VALUES('phase20-insights-v1', ?)",
            (int(time.time()),),
        )
        db.commit()


def owned_device(db: sqlite3.Connection, user_id: int, device_id: str) -> sqlite3.Row | None:
    return db.execute(
        "SELECT device_id, user_id, claimed_at, nickname FROM device_ownership WHERE user_id=? AND device_id=? LIMIT 1",
        (int(user_id), device_id),
    ).fetchone()


def owner_for_device(db: sqlite3.Connection, device_id: str) -> int | None:
    row = db.execute("SELECT user_id FROM device_ownership WHERE device_id=? LIMIT 1", (device_id,)).fetchone()
    return int(row["user_id"]) if row else None


def online_status(db: sqlite3.Connection, device_id: str, now: int | None = None) -> tuple[bool, int | None]:
    current = int(time.time()) if now is None else int(now)
    row = db.execute(
        "SELECT MAX(received_at) AS t FROM device_messages WHERE device_id=? AND message_type='heartbeat'",
        (device_id,),
    ).fetchone()
    if row is None or row["t"] is None:
        return False, None
    age = current - int(row["t"])
    return 0 <= age <= ONLINE_SECONDS, max(0, age)


def latest_telemetry(db: sqlite3.Connection, device_id: str) -> tuple[dict[str, Any] | None, int | None]:
    row = db.execute(
        "SELECT received_at, payload_json FROM device_telemetry WHERE device_id=? ORDER BY received_at DESC, id DESC LIMIT 1",
        (device_id,),
    ).fetchone()
    if row is None:
        return None, None
    return json_object(row["payload_json"]), int(row["received_at"])


def calibration(db: sqlite3.Connection, user_id: int, device_id: str, sensor_key: str) -> dict[str, Any] | None:
    row = db.execute(
        "SELECT calibration_type, config_json, updated_at FROM floraos_device_calibrations WHERE user_id=? AND device_id=? AND sensor_key=? LIMIT 1",
        (int(user_id), device_id, sensor_key),
    ).fetchone()
    if row is None:
        return None
    return {"type": str(row["calibration_type"]), "config": json_object(row["config_json"]), "updated_at": int(row["updated_at"])}


def calibrated_metric(db: sqlite3.Connection, user_id: int, device_id: str, metric_key: str, payload: dict[str, Any]) -> float | None:
    metric = METRICS[metric_key]
    cal = calibration(db, user_id, device_id, metric_key)
    if cal and metric["raw_aliases"]:
        raw = numeric(payload, tuple(metric["raw_aliases"]))
        if raw is not None and cal["type"] == "two_point_percent":
            try:
                zero = float(cal["config"]["raw_zero"])
                full = float(cal["config"]["raw_full"])
            except (KeyError, TypeError, ValueError):
                zero = full = 0.0
            if full != zero:
                return max(0.0, min(100.0, (raw - zero) / (full - zero) * 100.0))
        if raw is not None and cal["type"] == "linear":
            try:
                scale = float(cal["config"].get("scale", 1.0))
                offset = float(cal["config"].get("offset", 0.0))
            except (TypeError, ValueError):
                scale, offset = 1.0, 0.0
            value = raw * scale + offset
            return value if math.isfinite(value) else None
    return numeric(payload, tuple(metric["aliases"]))


def save_runtime_from_authenticated_payload(db: sqlite3.Connection, device_id: str, payload: dict[str, Any], now: int) -> None:
    existing = db.execute(
        "SELECT capabilities_json, diagnostics_json, capabilities_reported_at, diagnostics_reported_at FROM floraos_device_runtime WHERE device_id=?",
        (device_id,),
    ).fetchone()
    old_cap = json_object(existing["capabilities_json"]) if existing else {}
    old_diag = json_object(existing["diagnostics_json"]) if existing else {}

    cap_supplied = isinstance(payload.get("capabilities"), dict)
    capabilities = dict(payload["capabilities"]) if cap_supplied else old_cap

    diagnostics: dict[str, Any] = {}
    nested_diag = payload.get("diagnostics")
    if isinstance(nested_diag, dict):
        diagnostics.update({k: v for k, v in nested_diag.items() if isinstance(v, (str, int, float, bool)) or v is None})
    for key in (
        "wifi_rssi_dbm", "uptime_seconds", "free_heap_bytes", "min_free_heap_bytes",
        "psram_free_bytes", "psram_used_bytes", "reset_reason", "hardware_revision",
        "firmware_version", "project_name", "command_protocol", "mode", "rtc_valid",
    ):
        for source in nested_sources(payload):
            if key in source and (isinstance(source[key], (str, int, float, bool)) or source[key] is None):
                diagnostics[key] = source[key]
                break
    merged_diag = {**old_diag, **diagnostics}

    db.execute(
        """
        INSERT INTO floraos_device_runtime(device_id, capabilities_json, diagnostics_json,
            capabilities_reported_at, diagnostics_reported_at, updated_at)
        VALUES(?,?,?,?,?,?)
        ON CONFLICT(device_id) DO UPDATE SET
            capabilities_json=excluded.capabilities_json,
            diagnostics_json=excluded.diagnostics_json,
            capabilities_reported_at=CASE WHEN excluded.capabilities_reported_at IS NOT NULL THEN excluded.capabilities_reported_at ELSE floraos_device_runtime.capabilities_reported_at END,
            diagnostics_reported_at=CASE WHEN excluded.diagnostics_reported_at IS NOT NULL THEN excluded.diagnostics_reported_at ELSE floraos_device_runtime.diagnostics_reported_at END,
            updated_at=excluded.updated_at
        """,
        (
            device_id,
            json.dumps(capabilities, separators=(",", ":"), sort_keys=True),
            json.dumps(merged_diag, separators=(",", ":"), sort_keys=True),
            int(now) if cap_supplied else None,
            int(now) if diagnostics else None,
            int(now),
        ),
    )


def runtime_profile(db: sqlite3.Connection, device_id: str) -> dict[str, Any]:
    row = db.execute("SELECT * FROM floraos_device_runtime WHERE device_id=? LIMIT 1", (device_id,)).fetchone()
    if not row:
        return {"capabilities": {}, "diagnostics": {}, "capabilities_reported_at": None, "diagnostics_reported_at": None}
    return {
        "capabilities": json_object(row["capabilities_json"]),
        "diagnostics": json_object(row["diagnostics_json"]),
        "capabilities_reported_at": row["capabilities_reported_at"],
        "diagnostics_reported_at": row["diagnostics_reported_at"],
    }


def plant_profile(db: sqlite3.Connection, user_id: int, device_id: str) -> dict[str, Any] | None:
    required = {
        "user_id", "device_id", "plant_name", "species_key", "growth_stage", "soil_min", "soil_max",
        "light_min_lux", "light_max_lux", "temperature_min_c", "temperature_max_c", "humidity_min",
        "humidity_max", "reservoir_low_percent", "fertilizer_low_percent",
    }
    if not required.issubset(table_columns(db, "floraos_plant_profiles")):
        return None
    row = db.execute("SELECT * FROM floraos_plant_profiles WHERE user_id=? AND device_id=? LIMIT 1", (int(user_id), device_id)).fetchone()
    if not row:
        return None
    details = db.execute(
        "SELECT * FROM floraos_plant_details WHERE user_id=? AND device_id=? LIMIT 1", (int(user_id), device_id)
    ).fetchone()
    return {
        "plant_name": str(row["plant_name"]),
        "species_key": str(row["species_key"]),
        "growth_stage": str(row["growth_stage"]),
        "soil_min": float(row["soil_min"]), "soil_max": float(row["soil_max"]),
        "light_min": float(row["light_min_lux"]), "light_max": float(row["light_max_lux"]),
        "temperature_min": float(row["temperature_min_c"]), "temperature_max": float(row["temperature_max_c"]),
        "humidity_min": float(row["humidity_min"]), "humidity_max": float(row["humidity_max"]),
        "water_low": float(row["reservoir_low_percent"]), "fertilizer_low": float(row["fertilizer_low_percent"]),
        "scientific_name": str(details["scientific_name"]) if details and details["scientific_name"] else None,
        "planted_at": int(details["planted_at"]) if details and details["planted_at"] else None,
        "notes": str(details["notes"]) if details and details["notes"] else "",
        "avatar": str(details["avatar"]) if details and details["avatar"] else "🌱",
    }


def target_for(profile: dict[str, Any] | None, metric: str) -> tuple[float, float] | None:
    if not profile:
        return None
    mapping = {
        "soil": ("soil_min", "soil_max"), "light": ("light_min", "light_max"),
        "temperature": ("temperature_min", "temperature_max"), "humidity": ("humidity_min", "humidity_max"),
    }
    keys = mapping.get(metric)
    return (float(profile[keys[0]]), float(profile[keys[1]])) if keys else None


def history_samples(db: sqlite3.Connection, user_id: int, device_id: str, start: int, end: int) -> list[dict[str, Any]]:
    rows = db.execute(
        "SELECT received_at, payload_json FROM device_telemetry WHERE device_id=? AND received_at BETWEEN ? AND ? ORDER BY received_at ASC, id ASC",
        (device_id, int(start), int(end)),
    ).fetchall()
    result = []
    for row in rows:
        payload = json_object(row["payload_json"])
        item: dict[str, Any] = {"t": int(row["received_at"])}
        for key in METRICS:
            item[key] = calibrated_metric(db, user_id, device_id, key, payload)
        result.append(item)
    return result


def downsample(samples: list[dict[str, Any]], start: int, end: int, max_points: int = MAX_HISTORY_POINTS) -> list[dict[str, Any]]:
    if len(samples) <= max_points:
        return samples
    bucket_size = max(1, math.ceil(max(1, end - start) / max_points))
    buckets: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for item in samples:
        buckets[(int(item["t"]) - start) // bucket_size].append(item)
    output = []
    for bucket in sorted(buckets):
        group = buckets[bucket]
        point: dict[str, Any] = {"t": round(sum(int(x["t"]) for x in group) / len(group))}
        for key in METRICS:
            values = [float(x[key]) for x in group if isinstance(x.get(key), (int, float)) and math.isfinite(float(x[key]))]
            point[key] = sum(values) / len(values) if values else None
        output.append(point)
    return output


def metric_summary(samples: list[dict[str, Any]], metric: str, target: tuple[float, float] | None) -> dict[str, Any]:
    values = [float(x[metric]) for x in samples if isinstance(x.get(metric), (int, float)) and math.isfinite(float(x[metric]))]
    if not values:
        return {"count": 0, "min": None, "max": None, "average": None, "median": None, "time_in_target_percent": None}
    in_target = None
    if target:
        low, high = target
        in_target = round(100 * sum(1 for v in values if low <= v <= high) / len(values), 1)
    return {
        "count": len(values), "min": min(values), "max": max(values),
        "average": sum(values) / len(values), "median": median(values), "time_in_target_percent": in_target,
    }


def slope_per_second(samples: list[dict[str, Any]], metric: str) -> tuple[float | None, int]:
    points = [(float(x["t"]), float(x[metric])) for x in samples if isinstance(x.get(metric), (int, float))]
    if len(points) < 4:
        return None, len(points)
    origin = points[0][0]
    xs = [x - origin for x, _ in points]
    ys = [y for _, y in points]
    mx, my = sum(xs) / len(xs), sum(ys) / len(ys)
    denom = sum((x - mx) ** 2 for x in xs)
    if denom <= 0:
        return None, len(points)
    return sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / denom, len(points)


def trend_analysis(samples: list[dict[str, Any]], profile: dict[str, Any] | None, now: int | None = None) -> dict[str, Any]:
    current = int(time.time()) if now is None else int(now)
    result: dict[str, Any] = {"metrics": {}, "insights": []}
    for key, spec in METRICS.items():
        target = target_for(profile, key)
        stats = metric_summary(samples, key, target)
        slope, count = slope_per_second(samples, key)
        per_hour = slope * 3600 if slope is not None else None
        per_day = slope * 86400 if slope is not None else None
        confidence = "high" if count >= 48 else "medium" if count >= 12 else "low" if count >= 4 else "insufficient"
        data = {**stats, "slope_per_hour": per_hour, "slope_per_day": per_day, "confidence": confidence}

        if key == "soil" and target and slope is not None and slope < 0:
            last = next((float(x[key]) for x in reversed(samples) if isinstance(x.get(key), (int, float))), None)
            if last is not None and last > target[0]:
                seconds = (target[0] - last) / slope
                if 0 < seconds <= 7 * 86400:
                    data["estimated_lower_threshold_at"] = current + round(seconds)
                    result["insights"].append({
                        "severity": "info", "confidence": confidence,
                        "title": "Soil is trending toward its lower target",
                        "detail": f"Recent dry-down is about {abs(per_hour or 0):.2f}%/hour. If that continues, the lower target may be crossed in {seconds/3600:.1f} hours.",
                    })
        if key == "light" and stats["count"] >= 6 and stats["time_in_target_percent"] is not None and stats["time_in_target_percent"] < 50:
            result["insights"].append({
                "severity": "warning", "confidence": confidence,
                "title": "Light has often been outside target",
                "detail": f"Only {stats['time_in_target_percent']:.1f}% of recorded light samples were inside the configured range.",
            })
        if key in {"water", "fertilizer"} and per_day is not None and per_day < -0.2:
            result["insights"].append({
                "severity": "info", "confidence": confidence,
                "title": f"{spec['label']} is declining",
                "detail": f"Recent level trend is about {abs(per_day):.1f} percentage points/day.",
            })
        result["metrics"][key] = data
    return result


def _range_score(value: float | None, low: float, high: float) -> float | None:
    if value is None:
        return None
    if low <= value <= high:
        return 100.0
    span = max(high - low, 1e-6)
    distance = (low - value) / span if value < low else (value - high) / span
    return max(0.0, 100.0 - 75.0 * distance)


def care_score_v2(db: sqlite3.Connection, user_id: int, device_id: str, now: int | None = None) -> dict[str, Any]:
    current = int(time.time()) if now is None else int(now)
    profile = plant_profile(db, user_id, device_id)
    payload, telemetry_at = latest_telemetry(db, device_id)
    online, heartbeat_age = online_status(db, device_id, current)
    telemetry_age = max(0, current - telemetry_at) if telemetry_at is not None else None

    if not profile:
        return {"score": None, "status": "profile_required", "confidence_percent": 0, "components": {}, "seven_day_average": None, "online": online, "heartbeat_age_seconds": heartbeat_age, "telemetry_age_seconds": telemetry_age}

    values = {key: calibrated_metric(db, user_id, device_id, key, payload or {}) for key in METRICS}
    soil = _range_score(values["soil"], profile["soil_min"], profile["soil_max"])
    light = _range_score(values["light"], profile["light_min"], profile["light_max"])
    temp = _range_score(values["temperature"], profile["temperature_min"], profile["temperature_max"])
    humidity = _range_score(values["humidity"], profile["humidity_min"], profile["humidity_max"])
    climates = [x for x in (temp, humidity) if x is not None]
    climate = sum(climates) / len(climates) if climates else None
    supplies = []
    for key, threshold in (("water", profile["water_low"]), ("fertilizer", profile["fertilizer_low"])):
        value = values[key]
        if value is not None:
            supplies.append(100.0 if value >= threshold else max(0.0, 100.0 * value / max(1.0, threshold)))
    supply = sum(supplies) / len(supplies) if supplies else None

    components = {
        "soil": {"score": soil, "weight": .40}, "light": {"score": light, "weight": .25},
        "climate": {"score": climate, "weight": .25}, "supplies": {"score": supply, "weight": .10},
    }
    available = [x for x in components.values() if x["score"] is not None]
    score = None
    if available:
        denominator = sum(float(x["weight"]) for x in available)
        score = round(sum(float(x["score"]) * float(x["weight"]) for x in available) / denominator)
    freshness = 1.0 if telemetry_age is not None and telemetry_age <= TELEMETRY_STALE_SECONDS else .5 if telemetry_age is not None else 0.0
    confidence = round(100 * len(available) / 4 * freshness)

    history = history_samples(db, user_id, device_id, current - 7 * 86400, current)
    historical = []
    for sample in history:
        sample_scores = [
            _range_score(sample["soil"], profile["soil_min"], profile["soil_max"]),
            _range_score(sample["light"], profile["light_min"], profile["light_max"]),
            _range_score(sample["temperature"], profile["temperature_min"], profile["temperature_max"]),
            _range_score(sample["humidity"], profile["humidity_min"], profile["humidity_max"]),
        ]
        sample_scores = [x for x in sample_scores if x is not None]
        if sample_scores:
            historical.append(sum(sample_scores) / len(sample_scores))
    seven_day = round(sum(historical) / len(historical)) if historical else None
    status = "unknown" if score is None else "optimal" if score >= 90 else "good" if score >= 75 else "attention" if score >= 55 else "critical"
    return {
        "score": score, "status": status, "confidence_percent": confidence,
        "components": components, "seven_day_average": seven_day, "online": online,
        "heartbeat_age_seconds": heartbeat_age, "telemetry_age_seconds": telemetry_age,
        "current": values, "profile": profile,
        "disclaimer": "Care Score v2 measures how authenticated sensor readings match configured targets. It does not diagnose disease or guarantee biological plant health.",
    }


def reservoir_summary(db: sqlite3.Connection, user_id: int, device_id: str, now: int | None = None) -> dict[str, Any]:
    current = int(time.time()) if now is None else int(now)
    samples = history_samples(db, user_id, device_id, current - 7 * 86400, current)
    latest = samples[-1] if samples else {}
    profile = plant_profile(db, user_id, device_id)
    result: dict[str, Any] = {}
    for key, pkey in (("water", "water_low"), ("fertilizer", "fertilizer_low")):
        slope, count = slope_per_second(samples, key)
        per_day = slope * 86400 if slope is not None else None
        value = latest.get(key)
        threshold = float(profile[pkey]) if profile else 20.0
        eta = None
        if isinstance(value, (int, float)) and per_day is not None and per_day < -.05 and float(value) > threshold:
            candidate = (threshold - float(value)) / per_day
            eta = candidate if 0 <= candidate <= 90 else None
        refill = db.execute(
            "SELECT * FROM floraos_reservoir_refills WHERE user_id=? AND device_id=? AND reservoir=? ORDER BY created_at DESC, id DESC LIMIT 1",
            (int(user_id), device_id, key),
        ).fetchone()
        result[key] = {
            "percent": value, "warning_threshold": threshold, "trend_percent_per_day": per_day,
            "estimated_days_to_warning": eta, "sample_count": count,
            "last_refill": ({"refill_id": str(refill["refill_id"]), "amount_ml": refill["amount_ml"], "level_percent": refill["level_percent"], "notes": refill["notes"], "created_at": int(refill["created_at"])} if refill else None),
        }
    return result
