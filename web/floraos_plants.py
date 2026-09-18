from __future__ import annotations

from contextlib import closing
from pathlib import Path
from typing import Any
import json
import math
import os
import secrets
import sqlite3
import time

from flask import Blueprint, current_app, jsonify, redirect, render_template, request, session


HEARTBEAT_ONLINE_SECONDS = 120
TELEMETRY_STALE_SECONDS = 15 * 60

GROWTH_STAGES = (
    "seedling",
    "vegetative",
    "flowering",
    "fruiting",
    "mature",
    "dormant",
    "other",
)

# These are editable starting presets, not botanical diagnoses or guarantees.
# Real thresholds vary with substrate, sensor calibration, cultivar, season,
# enclosure, and local conditions.
PLANT_CATALOG: dict[str, dict[str, Any]] = {
    "generic_houseplant": {
        "name": "Generic houseplant",
        "description": "Balanced starting point for a typical indoor foliage plant.",
        "soil_min": 30.0,
        "soil_max": 60.0,
        "light_min_lux": 1500.0,
        "light_max_lux": 12000.0,
        "temperature_min_c": 18.0,
        "temperature_max_c": 29.0,
        "humidity_min": 35.0,
        "humidity_max": 70.0,
        "reservoir_low_percent": 20.0,
        "fertilizer_low_percent": 20.0,
    },
    "peppermint": {
        "name": "Peppermint",
        "description": "Moisture-loving herb with moderate-to-bright light preferences.",
        "soil_min": 40.0,
        "soil_max": 65.0,
        "light_min_lux": 8000.0,
        "light_max_lux": 20000.0,
        "temperature_min_c": 18.0,
        "temperature_max_c": 27.0,
        "humidity_min": 40.0,
        "humidity_max": 70.0,
        "reservoir_low_percent": 20.0,
        "fertilizer_low_percent": 20.0,
    },
    "basil": {
        "name": "Basil",
        "description": "Warm-growing herb that generally prefers bright light and even moisture.",
        "soil_min": 40.0,
        "soil_max": 65.0,
        "light_min_lux": 10000.0,
        "light_max_lux": 25000.0,
        "temperature_min_c": 20.0,
        "temperature_max_c": 30.0,
        "humidity_min": 40.0,
        "humidity_max": 70.0,
        "reservoir_low_percent": 20.0,
        "fertilizer_low_percent": 20.0,
    },
    "pothos": {
        "name": "Pothos",
        "description": "Tolerant indoor vine suited to lower light and moderate drying between watering.",
        "soil_min": 25.0,
        "soil_max": 55.0,
        "light_min_lux": 1000.0,
        "light_max_lux": 10000.0,
        "temperature_min_c": 18.0,
        "temperature_max_c": 29.0,
        "humidity_min": 35.0,
        "humidity_max": 70.0,
        "reservoir_low_percent": 20.0,
        "fertilizer_low_percent": 20.0,
    },
    "snake_plant": {
        "name": "Snake plant",
        "description": "Drought-tolerant foliage plant that should not be kept continuously wet.",
        "soil_min": 15.0,
        "soil_max": 35.0,
        "light_min_lux": 500.0,
        "light_max_lux": 12000.0,
        "temperature_min_c": 18.0,
        "temperature_max_c": 30.0,
        "humidity_min": 30.0,
        "humidity_max": 60.0,
        "reservoir_low_percent": 15.0,
        "fertilizer_low_percent": 15.0,
    },
    "peace_lily": {
        "name": "Peace lily",
        "description": "Indoor foliage plant that generally prefers even moisture and higher humidity.",
        "soil_min": 40.0,
        "soil_max": 65.0,
        "light_min_lux": 1000.0,
        "light_max_lux": 8000.0,
        "temperature_min_c": 18.0,
        "temperature_max_c": 29.0,
        "humidity_min": 50.0,
        "humidity_max": 80.0,
        "reservoir_low_percent": 20.0,
        "fertilizer_low_percent": 20.0,
    },
    "tomato": {
        "name": "Tomato",
        "description": "High-light fruiting plant with relatively consistent moisture needs.",
        "soil_min": 45.0,
        "soil_max": 70.0,
        "light_min_lux": 20000.0,
        "light_max_lux": 45000.0,
        "temperature_min_c": 18.0,
        "temperature_max_c": 30.0,
        "humidity_min": 40.0,
        "humidity_max": 70.0,
        "reservoir_low_percent": 25.0,
        "fertilizer_low_percent": 25.0,
    },
    "chili_pepper": {
        "name": "Chili pepper",
        "description": "Warm, bright-light fruiting plant with moderate moisture requirements.",
        "soil_min": 40.0,
        "soil_max": 65.0,
        "light_min_lux": 15000.0,
        "light_max_lux": 35000.0,
        "temperature_min_c": 20.0,
        "temperature_max_c": 32.0,
        "humidity_min": 40.0,
        "humidity_max": 70.0,
        "reservoir_low_percent": 25.0,
        "fertilizer_low_percent": 25.0,
    },
    "orchid": {
        "name": "Orchid",
        "description": "General orchid starting profile; customize for the actual species and growing medium.",
        "soil_min": 25.0,
        "soil_max": 50.0,
        "light_min_lux": 5000.0,
        "light_max_lux": 15000.0,
        "temperature_min_c": 18.0,
        "temperature_max_c": 27.0,
        "humidity_min": 50.0,
        "humidity_max": 75.0,
        "reservoir_low_percent": 20.0,
        "fertilizer_low_percent": 20.0,
    },
    "custom": {
        "name": "Custom",
        "description": "Start with neutral defaults and tune every threshold yourself.",
        "soil_min": 30.0,
        "soil_max": 60.0,
        "light_min_lux": 2000.0,
        "light_max_lux": 15000.0,
        "temperature_min_c": 18.0,
        "temperature_max_c": 30.0,
        "humidity_min": 35.0,
        "humidity_max": 70.0,
        "reservoir_low_percent": 20.0,
        "fertilizer_low_percent": 20.0,
    },
}

plants = Blueprint("floraos_plants", __name__)


def _connect(db_path: str | Path) -> sqlite3.Connection:
    db = sqlite3.connect(Path(db_path), timeout=5)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    db.execute("PRAGMA busy_timeout = 5000")
    return db


def _db_path() -> Path:
    configured = current_app.config.get("FLORAOS_PLANTS_DB_PATH")
    if not configured:
        raise RuntimeError("FLORAOS_PLANTS_DB_PATH is not configured.")
    return Path(configured)


def init_plants_schema(db_path: str | Path) -> None:
    with closing(_connect(db_path)) as db:
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS floraos_plant_profiles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                profile_id TEXT NOT NULL UNIQUE,
                user_id INTEGER NOT NULL,
                device_id TEXT NOT NULL,
                plant_name TEXT NOT NULL,
                species_key TEXT NOT NULL,
                growth_stage TEXT NOT NULL,
                soil_min REAL NOT NULL,
                soil_max REAL NOT NULL,
                light_min_lux REAL NOT NULL,
                light_max_lux REAL NOT NULL,
                temperature_min_c REAL NOT NULL,
                temperature_max_c REAL NOT NULL,
                humidity_min REAL NOT NULL,
                humidity_max REAL NOT NULL,
                reservoir_low_percent REAL NOT NULL,
                fertilizer_low_percent REAL NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                UNIQUE(user_id, device_id),
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            """
        )
        db.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_floraos_plant_profiles_user
            ON floraos_plant_profiles(user_id, updated_at DESC)
            """
        )
        db.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_floraos_plant_profiles_device
            ON floraos_plant_profiles(device_id, user_id)
            """
        )
        db.commit()


def init_plants(app, db_path: str | Path) -> None:
    app.config["FLORAOS_PLANTS_DB_PATH"] = str(Path(db_path))
    init_plants_schema(db_path)
    app.register_blueprint(plants)


@plants.after_request
def _plants_no_store(response):
    response.headers["Cache-Control"] = "no-store, max-age=0"
    response.headers["Pragma"] = "no-cache"
    return response


def _user_id() -> int | None:
    raw = session.get("user_id")
    try:
        return int(raw) if raw is not None else None
    except (TypeError, ValueError):
        return None


def _ensure_csrf() -> str:
    value = session.get("csrf_token")
    if not isinstance(value, str) or not value:
        value = secrets.token_urlsafe(32)
        session["csrf_token"] = value
    return value


def _csrf_ok() -> bool:
    supplied = request.headers.get("X-CSRF-Token", "")
    expected = session.get("csrf_token", "")
    return bool(
        isinstance(supplied, str)
        and isinstance(expected, str)
        and supplied
        and expected
        and secrets.compare_digest(supplied, expected)
    )


def _json_auth():
    user_id = _user_id()
    if user_id is None:
        return None, (jsonify(error="Not authenticated."), 401)
    return user_id, None


def _table_columns(db: sqlite3.Connection, table: str) -> set[str]:
    return {str(row["name"]) for row in db.execute(f"PRAGMA table_info({table})")}


def _owned_devices(db: sqlite3.Connection, user_id: int) -> list[dict[str, Any]]:
    ownership_columns = _table_columns(db, "device_ownership")
    has_nickname = "nickname" in ownership_columns
    select = "device_id, nickname" if has_nickname else "device_id"
    rows = db.execute(
        f"SELECT {select} FROM device_ownership WHERE user_id = ? ORDER BY device_id",
        (int(user_id),),
    ).fetchall()

    result = []
    for row in rows:
        nickname = (
            str(row["nickname"]).strip()
            if has_nickname and row["nickname"] is not None
            else ""
        )
        result.append(
            {
                "device_id": str(row["device_id"]),
                "nickname": nickname,
            }
        )
    return result


def _owns_device(db: sqlite3.Connection, user_id: int, device_id: str) -> bool:
    return (
        db.execute(
            """
            SELECT 1
            FROM device_ownership
            WHERE user_id = ? AND device_id = ?
            LIMIT 1
            """,
            (int(user_id), device_id),
        ).fetchone()
        is not None
    )


def _profile_row(
    db: sqlite3.Connection,
    *,
    user_id: int,
    device_id: str,
) -> sqlite3.Row | None:
    return db.execute(
        """
        SELECT *
        FROM floraos_plant_profiles
        WHERE user_id = ? AND device_id = ?
        LIMIT 1
        """,
        (int(user_id), device_id),
    ).fetchone()


def _profile_dict(row: sqlite3.Row | None) -> dict[str, Any] | None:
    if row is None:
        return None

    return {
        "profile_id": str(row["profile_id"]),
        "device_id": str(row["device_id"]),
        "plant_name": str(row["plant_name"]),
        "species_key": str(row["species_key"]),
        "species_name": PLANT_CATALOG.get(
            str(row["species_key"]),
            PLANT_CATALOG["custom"],
        )["name"],
        "growth_stage": str(row["growth_stage"]),
        "targets": {
            "soil": {
                "min": float(row["soil_min"]),
                "max": float(row["soil_max"]),
                "unit": "%",
            },
            "light": {
                "min": float(row["light_min_lux"]),
                "max": float(row["light_max_lux"]),
                "unit": "lux",
            },
            "temperature": {
                "min": float(row["temperature_min_c"]),
                "max": float(row["temperature_max_c"]),
                "unit": "°C",
            },
            "humidity": {
                "min": float(row["humidity_min"]),
                "max": float(row["humidity_max"]),
                "unit": "%",
            },
            "reservoir_low_percent": float(row["reservoir_low_percent"]),
            "fertilizer_low_percent": float(row["fertilizer_low_percent"]),
        },
        "created_at": int(row["created_at"]),
        "updated_at": int(row["updated_at"]),
    }


def _finite_number(
    body: dict[str, Any],
    key: str,
    *,
    minimum: float,
    maximum: float,
) -> float:
    value = body.get(key)
    if isinstance(value, bool):
        raise ValueError(f"{key} must be a number.")
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{key} must be a number.") from exc
    if not math.isfinite(number) or not minimum <= number <= maximum:
        raise ValueError(f"{key} must be between {minimum:g} and {maximum:g}.")
    return number


def _validate_profile_payload(body: dict[str, Any]) -> dict[str, Any]:
    plant_name = str(body.get("plant_name", "")).strip()
    if not plant_name:
        raise ValueError("Plant name is required.")
    if len(plant_name) > 64:
        raise ValueError("Plant name must be 64 characters or fewer.")

    species_key = str(body.get("species_key", "")).strip().lower()
    if species_key not in PLANT_CATALOG:
        raise ValueError("Choose a valid plant preset.")

    growth_stage = str(body.get("growth_stage", "mature")).strip().lower()
    if growth_stage not in GROWTH_STAGES:
        raise ValueError("Choose a valid growth stage.")

    values = {
        "soil_min": _finite_number(body, "soil_min", minimum=0, maximum=100),
        "soil_max": _finite_number(body, "soil_max", minimum=0, maximum=100),
        "light_min_lux": _finite_number(
            body,
            "light_min_lux",
            minimum=0,
            maximum=200000,
        ),
        "light_max_lux": _finite_number(
            body,
            "light_max_lux",
            minimum=0,
            maximum=200000,
        ),
        "temperature_min_c": _finite_number(
            body,
            "temperature_min_c",
            minimum=-10,
            maximum=60,
        ),
        "temperature_max_c": _finite_number(
            body,
            "temperature_max_c",
            minimum=-10,
            maximum=60,
        ),
        "humidity_min": _finite_number(
            body,
            "humidity_min",
            minimum=0,
            maximum=100,
        ),
        "humidity_max": _finite_number(
            body,
            "humidity_max",
            minimum=0,
            maximum=100,
        ),
        "reservoir_low_percent": _finite_number(
            body,
            "reservoir_low_percent",
            minimum=0,
            maximum=100,
        ),
        "fertilizer_low_percent": _finite_number(
            body,
            "fertilizer_low_percent",
            minimum=0,
            maximum=100,
        ),
    }

    pairs = (
        ("soil_min", "soil_max", "soil"),
        ("light_min_lux", "light_max_lux", "light"),
        ("temperature_min_c", "temperature_max_c", "temperature"),
        ("humidity_min", "humidity_max", "humidity"),
    )
    for low_key, high_key, label in pairs:
        if values[low_key] >= values[high_key]:
            raise ValueError(f"{label.title()} minimum must be lower than maximum.")

    return {
        "plant_name": plant_name,
        "species_key": species_key,
        "growth_stage": growth_stage,
        **values,
    }


def _nested_telemetry(payload: dict[str, Any]) -> list[dict[str, Any]]:
    candidates = [payload]
    for key in ("telemetry", "sensors", "state"):
        nested = payload.get(key)
        if isinstance(nested, dict):
            candidates.append(nested)
    return candidates


def _metric(
    payload: dict[str, Any] | None,
    aliases: tuple[str, ...],
) -> float | None:
    if not isinstance(payload, dict):
        return None

    for source in _nested_telemetry(payload):
        for key in aliases:
            value = source.get(key)
            if isinstance(value, bool):
                continue
            if isinstance(value, (int, float)) and math.isfinite(float(value)):
                return float(value)
    return None


def _latest_telemetry(
    db: sqlite3.Connection,
    device_id: str,
) -> tuple[dict[str, Any] | None, int | None]:
    row = db.execute(
        """
        SELECT received_at, payload_json
        FROM device_telemetry
        WHERE device_id = ?
        ORDER BY received_at DESC, id DESC
        LIMIT 1
        """,
        (device_id,),
    ).fetchone()
    if row is None:
        return None, None

    try:
        payload = json.loads(str(row["payload_json"]))
    except (TypeError, ValueError, json.JSONDecodeError):
        payload = None

    return (
        payload if isinstance(payload, dict) else None,
        int(row["received_at"]),
    )


def _online_status(
    db: sqlite3.Connection,
    device_id: str,
    *,
    now: int,
) -> tuple[bool, int | None]:
    row = db.execute(
        """
        SELECT received_at
        FROM device_messages
        WHERE device_id = ? AND message_type = 'heartbeat'
        ORDER BY received_at DESC, id DESC
        LIMIT 1
        """,
        (device_id,),
    ).fetchone()

    if row is None:
        return False, None

    age = max(0, now - int(row["received_at"]))
    return age <= HEARTBEAT_ONLINE_SECONDS, age


def _range_condition(
    *,
    key: str,
    label: str,
    value: float | None,
    low: float,
    high: float,
    unit: str,
    weight: float,
) -> dict[str, Any]:
    result = {
        "key": key,
        "label": label,
        "value": value,
        "min": float(low),
        "max": float(high),
        "unit": unit,
        "weight": weight,
        "status": "unknown",
        "score": None,
    }
    if value is None:
        return result

    span = max(float(high) - float(low), 1e-6)
    if low <= value <= high:
        result["status"] = "ideal"
        result["score"] = 100.0
        return result

    if value < low:
        distance = (low - value) / span
        result["status"] = "low"
    else:
        distance = (value - high) / span
        result["status"] = "high"

    result["score"] = max(0.0, 100.0 - 75.0 * distance)
    return result


def _supply_condition(
    *,
    key: str,
    label: str,
    value: float | None,
    low_threshold: float,
) -> dict[str, Any]:
    status = "unknown"
    if value is not None:
        status = "low" if value < low_threshold else "ok"
    return {
        "key": key,
        "label": label,
        "value": value,
        "low_threshold": float(low_threshold),
        "unit": "%",
        "status": status,
    }


def _condition_insight(
    metric: dict[str, Any],
    *,
    low_text: str,
    high_text: str,
    low_action: str,
    high_action: str,
) -> dict[str, str] | None:
    status = metric["status"]
    if status == "ideal" or status == "unknown":
        return None

    value = metric["value"]
    low = metric["min"]
    high = metric["max"]
    span = max(high - low, 1e-6)
    ratio = ((low - value) / span) if status == "low" else ((value - high) / span)
    severity = "critical" if ratio >= 0.6 else "warning"

    unit = str(metric["unit"])
    separator = " " if unit == "lux" else ""

    return {
        "severity": severity,
        "title": low_text if status == "low" else high_text,
        "detail": (
            f"Current {metric['label'].lower()} is {value:g}{separator}{unit}; "
            f"configured target is {low:g}–{high:g}{separator}{unit}."
        ),
        "action": low_action if status == "low" else high_action,
        "metric": metric["key"],
    }


def _care_analysis(
    *,
    profile: dict[str, Any],
    payload: dict[str, Any] | None,
    received_at: int | None,
    online: bool,
    heartbeat_age: int | None,
    now: int,
) -> dict[str, Any]:
    targets = profile["targets"]

    values = {
        "soil": _metric(
            payload,
            (
                "soil_percent",
                "soil_moisture_percent",
                "soil_moisture",
                "soil",
            ),
        ),
        "light": _metric(
            payload,
            (
                "light_lux",
                "lux",
                "illuminance_lux",
                "illuminance",
            ),
        ),
        "temperature": _metric(
            payload,
            (
                "temperature_c",
                "temperature",
                "temp_c",
                "air_temperature_c",
            ),
        ),
        "humidity": _metric(
            payload,
            (
                "humidity_percent",
                "humidity",
                "relative_humidity",
                "rh_percent",
            ),
        ),
        "reservoir": _metric(
            payload,
            (
                "water_level_percent",
                "water_percent",
                "reservoir_percent",
                "reservoir_level_percent",
            ),
        ),
        "fertilizer": _metric(
            payload,
            (
                "fertilizer_level_percent",
                "fertilizer_percent",
                "nutrient_percent",
                "nutrient_level_percent",
            ),
        ),
    }

    condition_metrics = [
        _range_condition(
            key="soil",
            label="Soil moisture",
            value=values["soil"],
            low=targets["soil"]["min"],
            high=targets["soil"]["max"],
            unit="%",
            weight=0.40,
        ),
        _range_condition(
            key="light",
            label="Light",
            value=values["light"],
            low=targets["light"]["min"],
            high=targets["light"]["max"],
            unit="lux",
            weight=0.25,
        ),
        _range_condition(
            key="temperature",
            label="Temperature",
            value=values["temperature"],
            low=targets["temperature"]["min"],
            high=targets["temperature"]["max"],
            unit="°C",
            weight=0.20,
        ),
        _range_condition(
            key="humidity",
            label="Humidity",
            value=values["humidity"],
            low=targets["humidity"]["min"],
            high=targets["humidity"]["max"],
            unit="%",
            weight=0.15,
        ),
    ]

    available = [metric for metric in condition_metrics if metric["score"] is not None]
    if available:
        denominator = sum(float(metric["weight"]) for metric in available)
        score = round(
            sum(float(metric["score"]) * float(metric["weight"]) for metric in available)
            / denominator
        )
        confidence = round(100 * len(available) / len(condition_metrics))
    else:
        score = None
        confidence = 0

    if score is None:
        status = "unknown"
        headline = "Waiting for plant telemetry"
    elif score >= 90:
        status = "optimal"
        headline = "Conditions match this profile well"
    elif score >= 75:
        status = "good"
        headline = "Conditions are mostly on target"
    elif score >= 55:
        status = "attention"
        headline = "Some conditions need attention"
    else:
        status = "critical"
        headline = "Conditions are far from target"

    supplies = [
        _supply_condition(
            key="reservoir",
            label="Water reservoir",
            value=values["reservoir"],
            low_threshold=targets["reservoir_low_percent"],
        ),
        _supply_condition(
            key="fertilizer",
            label="Fertilizer reservoir",
            value=values["fertilizer"],
            low_threshold=targets["fertilizer_low_percent"],
        ),
    ]

    insights: list[dict[str, str]] = []

    insight_specs = {
        "soil": (
            "Soil is drier than target",
            "Soil is wetter than target",
            "Consider watering if the sensor reading is trustworthy.",
            "Pause watering and allow the growing medium to dry.",
        ),
        "light": (
            "Light is below target",
            "Light is above target",
            "Increase useful light or extend the grow-light period.",
            "Reduce intense exposure if the plant shows light stress.",
        ),
        "temperature": (
            "Temperature is below target",
            "Temperature is above target",
            "Move the plant toward a warmer stable environment.",
            "Reduce heat exposure and improve ventilation.",
        ),
        "humidity": (
            "Humidity is below target",
            "Humidity is above target",
            "Increase local humidity if appropriate for this plant.",
            "Improve airflow and reduce persistent excess humidity.",
        ),
    }

    for metric in condition_metrics:
        spec = insight_specs[metric["key"]]
        insight = _condition_insight(
            metric,
            low_text=spec[0],
            high_text=spec[1],
            low_action=spec[2],
            high_action=spec[3],
        )
        if insight:
            insights.append(insight)

    for supply in supplies:
        if supply["status"] == "low":
            insights.append(
                {
                    "severity": "warning",
                    "title": f"{supply['label']} is low",
                    "detail": (
                        f"Current level is {supply['value']:g}%; "
                        f"warning threshold is {supply['low_threshold']:g}%."
                    ),
                    "action": "Refill the service reservoir before automated care depends on it.",
                    "metric": supply["key"],
                }
            )

    telemetry_age = (
        max(0, now - int(received_at))
        if received_at is not None
        else None
    )
    stale = telemetry_age is None or telemetry_age > TELEMETRY_STALE_SECONDS

    if not online:
        insights.insert(
            0,
            {
                "severity": "critical",
                "title": "FloraCore is offline",
                "detail": (
                    "No authenticated heartbeat has arrived within 120 seconds."
                    if heartbeat_age is not None
                    else "No authenticated heartbeat has been recorded."
                ),
                "action": "Restore device connectivity before relying on live care decisions.",
                "metric": "device",
            },
        )

    if stale:
        insights.insert(
            0 if online else 1,
            {
                "severity": "warning",
                "title": "Plant telemetry is stale",
                "detail": (
                    f"The latest telemetry sample is {telemetry_age} seconds old."
                    if telemetry_age is not None
                    else "No telemetry sample is available yet."
                ),
                "action": "Treat the care score as unavailable until fresh sensor data arrives.",
                "metric": "telemetry",
            },
        )

    if not insights and score is not None:
        insights.append(
            {
                "severity": "good",
                "title": "No immediate care warning",
                "detail": "Available sensor readings are inside the configured target ranges.",
                "action": "Keep monitoring trends and adjust thresholds as the plant responds.",
                "metric": "overall",
            }
        )

    severity_order = {"critical": 0, "warning": 1, "good": 2}
    insights.sort(key=lambda item: severity_order.get(item["severity"], 9))

    return {
        "score": score,
        "status": status,
        "headline": headline,
        "confidence_percent": confidence,
        "online": bool(online),
        "heartbeat_age_seconds": heartbeat_age,
        "telemetry_received_at": received_at,
        "telemetry_age_seconds": telemetry_age,
        "telemetry_stale": stale,
        "metrics": condition_metrics,
        "supplies": supplies,
        "insights": insights,
        "disclaimer": (
            "Care score measures how current sensor readings match your configured "
            "targets. It is not a plant-health or disease diagnosis."
        ),
    }


@plants.get("/plants")
def plants_page():
    user_id = _user_id()
    if user_id is None:
        return redirect("/login")

    with closing(_connect(_db_path())) as db:
        devices = _owned_devices(db, user_id)
        user = db.execute(
            "SELECT email FROM users WHERE id = ? LIMIT 1",
            (user_id,),
        ).fetchone()

    return render_template(
        "plants.html",
        user_id=user_id,
        user_email=str(user["email"]) if user is not None else "",
        connect_only=not bool(devices),
        csrf_token=_ensure_csrf(),
    )


@plants.get("/api/plants/catalog")
def plant_catalog_api():
    user_id, error = _json_auth()
    if error:
        return error

    data = []
    for key, item in PLANT_CATALOG.items():
        data.append(
            {
                "key": key,
                **item,
            }
        )

    return jsonify(
        data=data,
        growth_stages=list(GROWTH_STAGES),
        notice=(
            "Presets are editable starting points. Calibrate them to the actual plant, "
            "substrate, sensor placement, and growing environment."
        ),
    )


@plants.get("/api/plants")
def plants_list_api():
    user_id, error = _json_auth()
    if error:
        return error

    with closing(_connect(_db_path())) as db:
        devices = _owned_devices(db, user_id)
        profiles = {
            str(row["device_id"]): _profile_dict(row)
            for row in db.execute(
                """
                SELECT *
                FROM floraos_plant_profiles
                WHERE user_id = ?
                ORDER BY updated_at DESC
                """,
                (user_id,),
            ).fetchall()
        }

    for device in devices:
        device["profile"] = profiles.get(device["device_id"])

    return jsonify(data=devices)


@plants.get("/api/plants/<device_id>/care")
def plant_care_api(device_id: str):
    user_id, error = _json_auth()
    if error:
        return error
    if not device_id or len(device_id) > 128:
        return jsonify(error="Invalid device id."), 400

    now = int(time.time())

    with closing(_connect(_db_path())) as db:
        if not _owns_device(db, user_id, device_id):
            return jsonify(error="Device not found."), 404

        row = _profile_row(db, user_id=user_id, device_id=device_id)
        profile = _profile_dict(row)

        payload, received_at = _latest_telemetry(db, device_id)
        online, heartbeat_age = _online_status(db, device_id, now=now)

    care = (
        _care_analysis(
            profile=profile,
            payload=payload,
            received_at=received_at,
            online=online,
            heartbeat_age=heartbeat_age,
            now=now,
        )
        if profile is not None
        else None
    )

    return jsonify(
        data={
            "device_id": device_id,
            "profile": profile,
            "care": care,
        }
    )


@plants.put("/api/plants/<device_id>")
def plant_profile_upsert_api(device_id: str):
    user_id, error = _json_auth()
    if error:
        return error
    if not _csrf_ok():
        return jsonify(error="Invalid or expired security token."), 403
    if not device_id or len(device_id) > 128:
        return jsonify(error="Invalid device id."), 400

    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return jsonify(error="A JSON object is required."), 400

    try:
        profile = _validate_profile_payload(body)
    except ValueError as exc:
        return jsonify(error=str(exc)), 400

    now = int(time.time())

    with closing(_connect(_db_path())) as db:
        db.execute("BEGIN IMMEDIATE")

        if not _owns_device(db, user_id, device_id):
            db.rollback()
            return jsonify(error="Device not found."), 404

        existing = _profile_row(db, user_id=user_id, device_id=device_id)

        if existing is None:
            profile_id = "plant_" + secrets.token_urlsafe(12)
            db.execute(
                """
                INSERT INTO floraos_plant_profiles(
                    profile_id, user_id, device_id, plant_name, species_key,
                    growth_stage, soil_min, soil_max, light_min_lux,
                    light_max_lux, temperature_min_c, temperature_max_c,
                    humidity_min, humidity_max, reservoir_low_percent,
                    fertilizer_low_percent, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    profile_id,
                    user_id,
                    device_id,
                    profile["plant_name"],
                    profile["species_key"],
                    profile["growth_stage"],
                    profile["soil_min"],
                    profile["soil_max"],
                    profile["light_min_lux"],
                    profile["light_max_lux"],
                    profile["temperature_min_c"],
                    profile["temperature_max_c"],
                    profile["humidity_min"],
                    profile["humidity_max"],
                    profile["reservoir_low_percent"],
                    profile["fertilizer_low_percent"],
                    now,
                    now,
                ),
            )
        else:
            db.execute(
                """
                UPDATE floraos_plant_profiles
                SET
                    plant_name = ?,
                    species_key = ?,
                    growth_stage = ?,
                    soil_min = ?,
                    soil_max = ?,
                    light_min_lux = ?,
                    light_max_lux = ?,
                    temperature_min_c = ?,
                    temperature_max_c = ?,
                    humidity_min = ?,
                    humidity_max = ?,
                    reservoir_low_percent = ?,
                    fertilizer_low_percent = ?,
                    updated_at = ?
                WHERE user_id = ? AND device_id = ?
                """,
                (
                    profile["plant_name"],
                    profile["species_key"],
                    profile["growth_stage"],
                    profile["soil_min"],
                    profile["soil_max"],
                    profile["light_min_lux"],
                    profile["light_max_lux"],
                    profile["temperature_min_c"],
                    profile["temperature_max_c"],
                    profile["humidity_min"],
                    profile["humidity_max"],
                    profile["reservoir_low_percent"],
                    profile["fertilizer_low_percent"],
                    now,
                    user_id,
                    device_id,
                ),
            )

        saved = _profile_row(db, user_id=user_id, device_id=device_id)
        db.commit()

    return jsonify(data=_profile_dict(saved))


@plants.delete("/api/plants/<device_id>")
def plant_profile_delete_api(device_id: str):
    user_id, error = _json_auth()
    if error:
        return error
    if not _csrf_ok():
        return jsonify(error="Invalid or expired security token."), 403

    with closing(_connect(_db_path())) as db:
        db.execute("BEGIN IMMEDIATE")

        if not _owns_device(db, user_id, device_id):
            db.rollback()
            return jsonify(error="Device not found."), 404

        cursor = db.execute(
            """
            DELETE FROM floraos_plant_profiles
            WHERE user_id = ? AND device_id = ?
            """,
            (user_id, device_id),
        )
        db.commit()

    return jsonify(deleted=bool(cursor.rowcount))


__all__ = [
    "GROWTH_STAGES",
    "PLANT_CATALOG",
    "init_plants",
    "init_plants_schema",
    "_care_analysis",
]
