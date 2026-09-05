from __future__ import annotations

from contextlib import closing
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
import hmac
import json
import math
import re
import secrets
import sqlite3
import time

from flask import Blueprint, current_app, jsonify, redirect, render_template, request, session

from floraos_commands import (
    COMMAND_DEFAULT_TTL_SECONDS,
    COMMAND_MAX_PENDING_PER_DEVICE,
    WATER_COMMAND_COOLDOWN_SECONDS,
    CommandValidationError,
    command_readiness,
    enqueue_command_in_transaction,
    validate_command,
)


AUTOMATION_ID_PREFIX = "aut_"
AUTOMATION_ID_BYTES = 18
RUN_ID_PREFIX = "run_"
RUN_ID_BYTES = 18

MAX_AUTOMATIONS_PER_USER = 32
MAX_NODES = 12
MAX_GRAPH_BYTES = 32 * 1024

MIN_WATER_AUTOMATION_COOLDOWN_SECONDS = 15 * 60
MIN_LIGHT_AUTOMATION_COOLDOWN_SECONDS = 5 * 60
MAX_AUTOMATION_COOLDOWN_SECONDS = 7 * 24 * 60 * 60
DEFAULT_SCHEDULE_GRACE_MINUTES = 10

BLOCKED_SETUP_STATES = {
    "SETUP_IDLE",
    "SETUP_CONNECTING",
    "SETUP_WIFI_CONNECTED",
    "SETUP_CLAIMING",
}

TRIGGER_TYPES = frozenset(
    {
        "trigger_soil_below",
        "trigger_soil_above",
        "trigger_light_below",
        "trigger_light_above",
        "trigger_schedule",
        "trigger_telemetry",
    }
)
CONDITION_TYPES = frozenset(
    {
        "condition_soil_below",
        "condition_soil_above",
        "condition_light_below",
        "condition_light_above",
        "condition_time_between",
    }
)
FLOW_TYPES = frozenset({"cooldown"})
ACTION_TYPES = frozenset({"action_water", "action_grow_light"})
ALL_NODE_TYPES = TRIGGER_TYPES | CONDITION_TYPES | FLOW_TYPES | ACTION_TYPES

NODE_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,48}$")
TIME_RE = re.compile(r"^(?:[01]\d|2[0-3]):[0-5]\d$")

automation_api = Blueprint("floraos_automations", __name__)


class AutomationValidationError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def _db_path() -> Path:
    configured = current_app.config.get("FLORAOS_DB_PATH")
    if not configured:
        raise RuntimeError("FLORAOS_DB_PATH is not configured")
    return Path(configured)


def _connect_path(path: str | Path) -> sqlite3.Connection:
    db = sqlite3.connect(Path(path), timeout=5)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    db.execute("PRAGMA busy_timeout = 5000")
    return db


def init_automation_schema(db_path: str | Path) -> None:
    """Install the automation model additively; no existing FloraOS table is rebuilt."""
    with closing(_connect_path(db_path)) as db:
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS automations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                automation_id TEXT UNIQUE NOT NULL,
                user_id INTEGER NOT NULL,
                device_id TEXT NOT NULL,
                name TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 0,
                graph_json TEXT NOT NULL,
                timezone TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                last_triggered_at INTEGER,
                last_evaluated_at INTEGER,
                advanced_acknowledged_at INTEGER,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                UNIQUE(user_id, automation_id)
            )
            """
        )
        db.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_automations_device_enabled
            ON automations(device_id, enabled, id)
            """
        )
        db.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_automations_owner
            ON automations(user_id, updated_at DESC)
            """
        )

        db.execute(
            """
            CREATE TABLE IF NOT EXISTS automation_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT UNIQUE NOT NULL,
                automation_id TEXT NOT NULL,
                user_id INTEGER NOT NULL,
                device_id TEXT NOT NULL,
                trigger_json TEXT,
                command_id TEXT,
                started_at INTEGER NOT NULL,
                completed_at INTEGER,
                status TEXT NOT NULL,
                result_json TEXT,
                error TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            """
        )
        db.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_automation_runs_automation
            ON automation_runs(automation_id, id DESC)
            """
        )
        db.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_automation_runs_device
            ON automation_runs(device_id, id DESC)
            """
        )
        db.commit()


def init_automations(app, db_path: str | Path) -> None:
    resolved = Path(db_path)
    app.config["FLORAOS_DB_PATH"] = str(resolved)
    init_automation_schema(resolved)
    app.register_blueprint(automation_api)


def _new_automation_id() -> str:
    return AUTOMATION_ID_PREFIX + secrets.token_urlsafe(AUTOMATION_ID_BYTES)


def _new_run_id() -> str:
    return RUN_ID_PREFIX + secrets.token_urlsafe(RUN_ID_BYTES)


def _session_user_id() -> int | None:
    raw = session.get("user_id")
    try:
        return int(raw) if raw is not None else None
    except (TypeError, ValueError):
        return None


def _ensure_csrf_token() -> str:
    token = session.get("csrf_token")
    if not isinstance(token, str) or not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


def _csrf_valid() -> bool:
    supplied = request.headers.get("X-CSRF-Token", "")
    expected = session.get("csrf_token", "")
    return bool(
        isinstance(supplied, str)
        and isinstance(expected, str)
        and supplied
        and expected
        and hmac.compare_digest(supplied, expected)
    )


def _api_error(code: str, message: str, status: int):
    return jsonify(error={"code": code, "message": message}), status


def _owned_device(
    db: sqlite3.Connection,
    *,
    user_id: int,
    device_id: str,
) -> sqlite3.Row | None:
    return db.execute(
        """
        SELECT device_id, nickname, claimed_at
        FROM device_ownership
        WHERE user_id = ? AND device_id = ?
        LIMIT 1
        """,
        (int(user_id), device_id),
    ).fetchone()


def _clean_name(value: Any) -> str:
    if not isinstance(value, str):
        raise AutomationValidationError("invalid_name", "Automation name is required.")
    name = value.strip()
    if not 1 <= len(name) <= 80:
        raise AutomationValidationError(
            "invalid_name",
            "Automation name must be between 1 and 80 characters.",
        )
    return name


def _clean_device_id(value: Any) -> str:
    if not isinstance(value, str):
        raise AutomationValidationError("invalid_device", "A FloraCore device is required.")
    device_id = value.strip()
    if not device_id or len(device_id) > 64:
        raise AutomationValidationError("invalid_device", "Invalid FloraCore device.")
    return device_id


def _clean_timezone(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise AutomationValidationError("invalid_timezone", "A timezone is required.")
    timezone = value.strip()
    if len(timezone) > 80:
        raise AutomationValidationError("invalid_timezone", "Timezone is invalid.")
    try:
        ZoneInfo(timezone)
    except ZoneInfoNotFoundError as exc:
        raise AutomationValidationError(
            "invalid_timezone",
            "Timezone is not recognized by the server.",
        ) from exc
    return timezone


def _number(
    value: Any,
    *,
    name: str,
    minimum: float,
    maximum: float,
) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise AutomationValidationError("invalid_graph", f"{name} must be a number.")
    result = float(value)
    if not math.isfinite(result) or not minimum <= result <= maximum:
        raise AutomationValidationError(
            "invalid_graph",
            f"{name} must be between {minimum:g} and {maximum:g}.",
        )
    return result


def _integer(
    value: Any,
    *,
    name: str,
    minimum: int,
    maximum: int,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise AutomationValidationError("invalid_graph", f"{name} must be an integer.")
    if not minimum <= value <= maximum:
        raise AutomationValidationError(
            "invalid_graph",
            f"{name} must be between {minimum} and {maximum}.",
        )
    return int(value)


def _time_string(value: Any, name: str) -> str:
    if not isinstance(value, str) or TIME_RE.fullmatch(value.strip()) is None:
        raise AutomationValidationError(
            "invalid_graph",
            f"{name} must use 24-hour HH:MM format.",
        )
    return value.strip()


def _normalize_node(node: Any) -> dict[str, Any]:
    if not isinstance(node, dict):
        raise AutomationValidationError("invalid_graph", "Every node must be an object.")

    node_id = node.get("id")
    node_type = node.get("type")
    config = node.get("config", {})

    if not isinstance(node_id, str) or NODE_ID_RE.fullmatch(node_id) is None:
        raise AutomationValidationError("invalid_graph", "Node id is invalid.")
    if node_type not in ALL_NODE_TYPES:
        raise AutomationValidationError("invalid_graph", "Unsupported automation block.")
    if not isinstance(config, dict):
        raise AutomationValidationError("invalid_graph", "Node config must be an object.")

    x = _number(node.get("x", 0), name="node x", minimum=-500, maximum=5000)
    y = _number(node.get("y", 0), name="node y", minimum=-500, maximum=5000)

    normalized_config: dict[str, Any] = {}

    if node_type.endswith("soil_below") or node_type.endswith("soil_above"):
        normalized_config["percent"] = _number(
            config.get("percent"),
            name="soil percent",
            minimum=0,
            maximum=100,
        )

    elif node_type.endswith("light_below") or node_type.endswith("light_above"):
        normalized_config["lux"] = _number(
            config.get("lux"),
            name="light lux",
            minimum=0,
            maximum=250_000,
        )

    elif node_type == "trigger_schedule":
        normalized_config["time"] = _time_string(config.get("time"), "schedule time")
        normalized_config["grace_minutes"] = _integer(
            config.get("grace_minutes", DEFAULT_SCHEDULE_GRACE_MINUTES),
            name="schedule grace",
            minimum=1,
            maximum=60,
        )

    elif node_type == "trigger_telemetry":
        normalized_config = {}

    elif node_type == "condition_time_between":
        normalized_config["start"] = _time_string(config.get("start"), "start time")
        normalized_config["end"] = _time_string(config.get("end"), "end time")

    elif node_type == "cooldown":
        normalized_config["seconds"] = _integer(
            config.get("seconds"),
            name="cooldown seconds",
            minimum=60,
            maximum=MAX_AUTOMATION_COOLDOWN_SECONDS,
        )

    elif node_type == "action_water":
        duration = _integer(
            config.get("duration_ms"),
            name="watering duration_ms",
            minimum=1,
            maximum=1_000_000,
        )
        try:
            _, normalized_config = validate_command(
                "water",
                {"duration_ms": duration},
            )
        except CommandValidationError as exc:
            raise AutomationValidationError(exc.code, exc.message) from exc

    elif node_type == "action_grow_light":
        state = config.get("state")
        parameters: dict[str, Any] = {"state": state}
        if state == "on":
            parameters["duration_seconds"] = config.get("duration_seconds")
        try:
            _, normalized_config = validate_command("grow_light", parameters)
        except CommandValidationError as exc:
            raise AutomationValidationError(exc.code, exc.message) from exc

    return {
        "id": node_id,
        "type": node_type,
        "x": round(x, 2),
        "y": round(y, 2),
        "config": normalized_config,
    }


def validate_graph(graph: Any) -> dict[str, Any]:
    if not isinstance(graph, dict):
        raise AutomationValidationError("invalid_graph", "Automation graph is required.")

    raw_nodes = graph.get("nodes")
    raw_edges = graph.get("edges")

    if not isinstance(raw_nodes, list) or not isinstance(raw_edges, list):
        raise AutomationValidationError(
            "invalid_graph",
            "Automation graph requires nodes and edges arrays.",
        )
    if not 2 <= len(raw_nodes) <= MAX_NODES:
        raise AutomationValidationError(
            "invalid_graph",
            f"Automation must contain between 2 and {MAX_NODES} blocks.",
        )

    nodes = [_normalize_node(node) for node in raw_nodes]
    node_map = {node["id"]: node for node in nodes}
    if len(node_map) != len(nodes):
        raise AutomationValidationError("invalid_graph", "Node ids must be unique.")

    triggers = [node for node in nodes if node["type"] in TRIGGER_TYPES]
    actions = [node for node in nodes if node["type"] in ACTION_TYPES]
    if len(triggers) != 1:
        raise AutomationValidationError(
            "invalid_graph",
            "Exactly one trigger block is required.",
        )
    if len(actions) != 1:
        raise AutomationValidationError(
            "invalid_graph",
            "Exactly one action block is required.",
        )

    if len(raw_edges) != len(nodes) - 1:
        raise AutomationValidationError(
            "invalid_graph",
            "Blocks must form one continuous flow from trigger to action.",
        )

    outgoing: dict[str, str] = {}
    incoming: dict[str, str] = {}
    edges: list[dict[str, str]] = []

    for raw in raw_edges:
        if not isinstance(raw, dict):
            raise AutomationValidationError("invalid_graph", "Every edge must be an object.")
        source = raw.get("from")
        target = raw.get("to")
        if source not in node_map or target not in node_map or source == target:
            raise AutomationValidationError("invalid_graph", "Automation edge is invalid.")
        if source in outgoing or target in incoming:
            raise AutomationValidationError(
                "invalid_graph",
                "Automation v1 supports one linear path; branching is not enabled yet.",
            )
        outgoing[source] = target
        incoming[target] = source
        edges.append({"from": source, "to": target})

    trigger = triggers[0]
    action = actions[0]

    if trigger["id"] in incoming:
        raise AutomationValidationError("invalid_graph", "Trigger must be the first block.")
    if action["id"] in outgoing:
        raise AutomationValidationError("invalid_graph", "Action must be the final block.")

    ordered: list[dict[str, Any]] = []
    seen: set[str] = set()
    cursor = trigger["id"]

    while True:
        if cursor in seen:
            raise AutomationValidationError("invalid_graph", "Automation graph contains a cycle.")
        seen.add(cursor)
        node = node_map[cursor]
        ordered.append(node)
        if cursor == action["id"]:
            break
        next_id = outgoing.get(cursor)
        if next_id is None:
            raise AutomationValidationError(
                "invalid_graph",
                "Automation flow is disconnected.",
            )
        cursor = next_id

    if len(seen) != len(nodes):
        raise AutomationValidationError(
            "invalid_graph",
            "Every block must belong to the trigger-to-action path.",
        )

    for node in ordered[1:-1]:
        if node["type"] not in CONDITION_TYPES and node["type"] not in FLOW_TYPES:
            raise AutomationValidationError(
                "invalid_graph",
                "Only conditions and cooldown blocks may appear between trigger and action.",
            )

    normalized = {
        "version": 1,
        "nodes": nodes,
        "edges": edges,
    }
    encoded = json.dumps(normalized, separators=(",", ":"), sort_keys=True).encode()
    if len(encoded) > MAX_GRAPH_BYTES:
        raise AutomationValidationError("invalid_graph", "Automation graph is too large.")

    return normalized


def _ordered_nodes(graph: dict[str, Any]) -> list[dict[str, Any]]:
    nodes = {node["id"]: node for node in graph["nodes"]}
    next_by_id = {edge["from"]: edge["to"] for edge in graph["edges"]}
    trigger = next(node for node in graph["nodes"] if node["type"] in TRIGGER_TYPES)
    ordered = [trigger]
    cursor = trigger["id"]
    while cursor in next_by_id:
        cursor = next_by_id[cursor]
        ordered.append(nodes[cursor])
    return ordered


def _setup_blocks_automation(payload: dict[str, Any]) -> bool:
    if not isinstance(payload, dict):
        return False
    for key in ("setup_state", "state", "mode"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip().upper() in BLOCKED_SETUP_STATES:
            return True
    return False


def _telemetry_payload(
    db: sqlite3.Connection,
    *,
    device_id: str,
    message_type: str,
    payload: dict[str, Any],
) -> dict[str, Any] | None:
    if message_type == "telemetry":
        return payload

    row = db.execute(
        """
        SELECT payload_json
        FROM device_telemetry
        WHERE device_id = ?
        ORDER BY received_at DESC, id DESC
        LIMIT 1
        """,
        (device_id,),
    ).fetchone()
    if row is None:
        return None
    try:
        decoded = json.loads(str(row["payload_json"]))
    except (TypeError, ValueError, json.JSONDecodeError):
        return None
    return decoded if isinstance(decoded, dict) else None


def _sensor_value(payload: dict[str, Any] | None, key: str) -> float | None:
    if not isinstance(payload, dict):
        return None

    candidates = [payload]
    nested = payload.get("telemetry")
    if isinstance(nested, dict):
        candidates.append(nested)

    for source in candidates:
        value = source.get(key)
        if isinstance(value, bool):
            continue
        if isinstance(value, (int, float)) and math.isfinite(float(value)):
            return float(value)
    return None


def _local_datetime(now: int, timezone: str) -> datetime:
    return datetime.fromtimestamp(int(now), tz=ZoneInfo(timezone))


def _minutes(hhmm: str) -> int:
    hour, minute = hhmm.split(":", 1)
    return int(hour) * 60 + int(minute)


def _time_between(now: int, timezone: str, start: str, end: str) -> bool:
    local = _local_datetime(now, timezone)
    current = local.hour * 60 + local.minute
    start_min = _minutes(start)
    end_min = _minutes(end)

    if start_min == end_min:
        return True
    if start_min < end_min:
        return start_min <= current < end_min
    return current >= start_min or current < end_min


def _trigger_matches(
    trigger: dict[str, Any],
    *,
    message_type: str,
    telemetry: dict[str, Any] | None,
    now: int,
    timezone: str,
    last_triggered_at: int | None,
) -> tuple[bool, dict[str, Any]]:
    node_type = trigger["type"]
    config = trigger["config"]

    if node_type == "trigger_telemetry":
        return message_type == "telemetry", {"type": node_type}

    if node_type in {"trigger_soil_below", "trigger_soil_above"}:
        if message_type != "telemetry":
            return False, {}
        value = _sensor_value(telemetry, "soil_percent")
        if value is None:
            return False, {}
        threshold = float(config["percent"])
        matched = value < threshold if node_type.endswith("below") else value > threshold
        return matched, {
            "type": node_type,
            "soil_percent": value,
            "threshold": threshold,
        }

    if node_type in {"trigger_light_below", "trigger_light_above"}:
        if message_type != "telemetry":
            return False, {}
        value = _sensor_value(telemetry, "light_lux")
        if value is None:
            return False, {}
        threshold = float(config["lux"])
        matched = value < threshold if node_type.endswith("below") else value > threshold
        return matched, {
            "type": node_type,
            "light_lux": value,
            "threshold": threshold,
        }

    if node_type == "trigger_schedule":
        local = _local_datetime(now, timezone)
        hour, minute = (int(part) for part in str(config["time"]).split(":", 1))
        grace = int(config["grace_minutes"])

        target_today = local.replace(
            hour=hour,
            minute=minute,
            second=0,
            microsecond=0,
        )
        candidates = (target_today, target_today - timedelta(days=1))
        matched_target = next(
            (
                target
                for target in candidates
                if target <= local <= target + timedelta(minutes=grace)
            ),
            None,
        )
        if matched_target is None:
            return False, {}

        if last_triggered_at is not None:
            previous = _local_datetime(last_triggered_at, timezone)
            if previous >= matched_target:
                return False, {}

        return True, {
            "type": node_type,
            "scheduled_time": config["time"],
            "timezone": timezone,
            "schedule_date": matched_target.date().isoformat(),
        }

    return False, {}


def _condition_matches(
    node: dict[str, Any],
    *,
    telemetry: dict[str, Any] | None,
    now: int,
    timezone: str,
) -> bool:
    node_type = node["type"]
    config = node["config"]

    if node_type in {"condition_soil_below", "condition_soil_above"}:
        value = _sensor_value(telemetry, "soil_percent")
        if value is None:
            return False
        threshold = float(config["percent"])
        return value < threshold if node_type.endswith("below") else value > threshold

    if node_type in {"condition_light_below", "condition_light_above"}:
        value = _sensor_value(telemetry, "light_lux")
        if value is None:
            return False
        threshold = float(config["lux"])
        return value < threshold if node_type.endswith("below") else value > threshold

    if node_type == "condition_time_between":
        return _time_between(
            now,
            timezone,
            str(config["start"]),
            str(config["end"]),
        )

    return True


def _automation_cooldown(ordered: list[dict[str, Any]]) -> int:
    configured = max(
        [
            int(node["config"]["seconds"])
            for node in ordered
            if node["type"] == "cooldown"
        ]
        or [0]
    )

    action = ordered[-1]
    if action["type"] == "action_water":
        safety_floor = MIN_WATER_AUTOMATION_COOLDOWN_SECONDS
    else:
        safety_floor = MIN_LIGHT_AUTOMATION_COOLDOWN_SECONDS

    return max(configured, safety_floor)


def _action_command(action: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    if action["type"] == "action_water":
        return validate_command(
            "water",
            {"duration_ms": int(action["config"]["duration_ms"])},
        )

    parameters = {"state": action["config"]["state"]}
    if action["config"]["state"] == "on":
        parameters["duration_seconds"] = int(action["config"]["duration_seconds"])
    return validate_command("grow_light", parameters)



def _human_duration(seconds: int) -> str:
    seconds = max(0, int(seconds))
    if seconds % 86400 == 0 and seconds >= 86400:
        days = seconds // 86400
        return f"{days} day" + ("" if days == 1 else "s")
    if seconds % 3600 == 0 and seconds >= 3600:
        hours = seconds // 3600
        return f"{hours} hour" + ("" if hours == 1 else "s")
    if seconds % 60 == 0 and seconds >= 60:
        minutes = seconds // 60
        return f"{minutes} minute" + ("" if minutes == 1 else "s")
    return f"{seconds} second" + ("" if seconds == 1 else "s")


def _node_label(node_type: str) -> str:
    labels = {
        "trigger_soil_below": "Soil below",
        "trigger_soil_above": "Soil above",
        "trigger_light_below": "Light below",
        "trigger_light_above": "Light above",
        "trigger_schedule": "Schedule",
        "trigger_telemetry": "Telemetry received",
        "condition_soil_below": "Soil below",
        "condition_soil_above": "Soil above",
        "condition_light_below": "Light below",
        "condition_light_above": "Light above",
        "condition_time_between": "Time window",
        "cooldown": "Cooldown",
        "action_water": "Water",
        "action_grow_light": "Grow light",
    }
    return labels.get(node_type, node_type)


def _latest_telemetry_snapshot(
    db: sqlite3.Connection,
    *,
    device_id: str,
) -> tuple[dict[str, Any] | None, int | None]:
    row = db.execute(
        """
        SELECT payload_json, received_at
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
        return None, int(row["received_at"])
    return (payload if isinstance(payload, dict) else None), int(row["received_at"])


def _simulation_timestamp(timezone: str, local_time: str | None) -> int:
    tz = ZoneInfo(timezone)
    local_now = datetime.now(tz)
    if local_time is None:
        return int(local_now.timestamp())

    parsed = _time_string(local_time, "simulation time")
    hour, minute = (int(part) for part in parsed.split(":", 1))
    simulated = local_now.replace(
        hour=hour,
        minute=minute,
        second=0,
        microsecond=0,
    )
    return int(simulated.timestamp())


def _threshold_simulation(
    node: dict[str, Any],
    telemetry: dict[str, Any] | None,
) -> tuple[bool, str]:
    node_type = str(node["type"])
    config = node["config"]

    if "soil_" in node_type:
        value = _sensor_value(telemetry, "soil_percent")
        if value is None:
            return False, "soil_percent is unavailable."
        threshold = float(config["percent"])
        passed = value < threshold if node_type.endswith("below") else value > threshold
        operator = "<" if node_type.endswith("below") else ">"
        return passed, f"{value:g}% {operator} {threshold:g}%"

    value = _sensor_value(telemetry, "light_lux")
    if value is None:
        return False, "light_lux is unavailable."
    threshold = float(config["lux"])
    passed = value < threshold if node_type.endswith("below") else value > threshold
    operator = "<" if node_type.endswith("below") else ">"
    return passed, f"{value:g} lux {operator} {threshold:g} lux"


def _schedule_simulation(
    node: dict[str, Any],
    *,
    now: int,
    timezone: str,
    last_triggered_at: int | None,
) -> tuple[bool, str]:
    local = _local_datetime(now, timezone)
    config = node["config"]
    hour, minute = (int(part) for part in str(config["time"]).split(":", 1))
    grace = int(config["grace_minutes"])

    target_today = local.replace(
        hour=hour,
        minute=minute,
        second=0,
        microsecond=0,
    )
    candidates = (target_today, target_today - timedelta(days=1))
    matched_target = next(
        (
            target
            for target in candidates
            if target <= local <= target + timedelta(minutes=grace)
        ),
        None,
    )

    local_clock = local.strftime("%H:%M")
    end_clock = (target_today + timedelta(minutes=grace)).strftime("%H:%M")

    if matched_target is None:
        return (
            False,
            f"{local_clock} is outside the {config['time']}–{end_clock} schedule window.",
        )

    if last_triggered_at is not None:
        previous = _local_datetime(last_triggered_at, timezone)
        if previous >= matched_target:
            return False, "This saved automation already triggered for this schedule window."

    return True, f"{local_clock} is inside the {config['time']}–{end_clock} schedule window."


def _cooldown_simulation(
    *,
    required_seconds: int,
    last_triggered_at: int | None,
    now: int,
) -> tuple[bool, str, int]:
    if last_triggered_at is None:
        return (
            True,
            f"No previous run. A {_human_duration(required_seconds)} cooldown would start after execution.",
            0,
        )

    elapsed = int(now) - int(last_triggered_at)
    if elapsed < 0:
        return (
            False,
            "The simulated time is earlier than this automation's previous run.",
            int(required_seconds),
        )

    remaining = max(0, int(required_seconds) - elapsed)
    if remaining > 0:
        return (
            False,
            f"{_human_duration(remaining)} remains in the effective cooldown.",
            remaining,
        )

    return True, f"Effective {_human_duration(required_seconds)} cooldown is satisfied.", 0


def _command_delivery_simulation(
    db: sqlite3.Connection,
    *,
    device_id: str,
    command_type: str,
    now: int,
) -> dict[str, Any]:
    ready, reason = command_readiness(
        db,
        device_id=device_id,
        now=int(now),
        heartbeat_max_age_seconds=120,
    )
    if not ready:
        messages = {
            "device_offline": "The device is currently offline.",
            "command_protocol_unavailable": "The device has not reported command protocol v1.",
            "ota_in_progress": "An OTA install is currently in progress.",
        }
        return {
            "ready": False,
            "reason": reason,
            "message": messages.get(reason, "Device control is currently unavailable."),
        }

    pending_count = int(
        db.execute(
            """
            SELECT COUNT(*) AS n
            FROM device_commands
            WHERE device_id = ?
              AND status IN ('queued', 'delivered')
              AND expires_at >= ?
            """,
            (device_id, int(now)),
        ).fetchone()["n"]
    )
    if pending_count >= COMMAND_MAX_PENDING_PER_DEVICE:
        return {
            "ready": False,
            "reason": "command_queue_full",
            "message": "The device command queue is currently full.",
        }

    if command_type == "water":
        recent_water = db.execute(
            """
            SELECT created_at
            FROM device_commands
            WHERE device_id = ?
              AND command_type = 'water'
              AND status NOT IN ('failed', 'cancelled')
            ORDER BY created_at DESC, id DESC
            LIMIT 1
            """,
            (device_id,),
        ).fetchone()
        if recent_water is not None:
            age = int(now) - int(recent_water["created_at"])
            if 0 <= age < WATER_COMMAND_COOLDOWN_SECONDS:
                remaining = WATER_COMMAND_COOLDOWN_SECONDS - age
                return {
                    "ready": False,
                    "reason": "command_cooldown",
                    "message": f"Water command safety cooldown has {remaining}s remaining.",
                }

        active_water = db.execute(
            """
            SELECT 1
            FROM device_commands
            WHERE device_id = ?
              AND command_type = 'water'
              AND status IN ('queued', 'delivered', 'acknowledged')
              AND completed_at IS NULL
            LIMIT 1
            """,
            (device_id,),
        ).fetchone()
        if active_water is not None:
            return {
                "ready": False,
                "reason": "command_in_progress",
                "message": "A watering command is already in progress.",
            }

    return {
        "ready": True,
        "reason": None,
        "message": "The device is currently ready to receive this validated command.",
    }


def _action_preview(action: dict[str, Any]) -> tuple[str, dict[str, Any], str]:
    command_type, parameters = _action_command(action)
    if command_type == "water":
        seconds = int(parameters["duration_ms"]) / 1000
        summary = f"Water for {seconds:g} seconds"
    elif parameters["state"] == "off":
        summary = "Turn grow light off"
    else:
        minutes = int(parameters["duration_seconds"]) / 60
        if minutes >= 60 and minutes % 60 == 0:
            summary = f"Turn grow light on for {int(minutes // 60)} hour(s)"
        else:
            summary = f"Turn grow light on for {minutes:g} minutes"
    return command_type, parameters, summary


def simulate_automation_graph(
    db: sqlite3.Connection,
    *,
    graph: dict[str, Any],
    device_id: str,
    timezone: str,
    telemetry: dict[str, Any] | None,
    simulated_now: int,
    real_now: int,
    last_triggered_at: int | None,
    source: str,
    telemetry_received_at: int | None,
) -> dict[str, Any]:
    """
    Pure dry-run evaluator.

    This function never inserts into device_commands, never updates an
    automation, and never sends anything to FloraCore.
    """
    ordered = _ordered_nodes(graph)
    effective_cooldown = _automation_cooldown(ordered)

    steps: list[dict[str, Any]] = []
    flow_alive = True
    action_preview: dict[str, Any] | None = None

    for index, node in enumerate(ordered):
        node_type = str(node["type"])
        label = _node_label(node_type)

        if not flow_alive:
            steps.append(
                {
                    "node_id": node["id"],
                    "type": node_type,
                    "label": label,
                    "status": "not_reached",
                    "detail": "The flow stopped before this block.",
                }
            )
            continue

        if node_type in {
            "trigger_soil_below",
            "trigger_soil_above",
            "trigger_light_below",
            "trigger_light_above",
            "condition_soil_below",
            "condition_soil_above",
            "condition_light_below",
            "condition_light_above",
        }:
            passed, detail = _threshold_simulation(node, telemetry)

        elif node_type == "trigger_schedule":
            passed, detail = _schedule_simulation(
                node,
                now=simulated_now,
                timezone=timezone,
                last_triggered_at=last_triggered_at,
            )

        elif node_type == "trigger_telemetry":
            if source == "latest" and telemetry is None:
                passed, detail = False, "No authenticated telemetry sample is stored for this device."
            else:
                passed, detail = True, "A telemetry event is being simulated."

        elif node_type == "condition_time_between":
            passed = _time_between(
                simulated_now,
                timezone,
                str(node["config"]["start"]),
                str(node["config"]["end"]),
            )
            local_clock = _local_datetime(simulated_now, timezone).strftime("%H:%M")
            detail = (
                f"{local_clock} is inside "
                if passed
                else f"{local_clock} is outside "
            ) + f"{node['config']['start']}–{node['config']['end']}."

        elif node_type == "cooldown":
            passed, detail, _ = _cooldown_simulation(
                required_seconds=effective_cooldown,
                last_triggered_at=last_triggered_at,
                now=simulated_now,
            )

        elif node_type in ACTION_TYPES:
            command_type, parameters, summary = _action_preview(node)
            action_preview = {
                "type": command_type,
                "parameters": parameters,
                "summary": summary,
            }
            passed, detail = True, f"Would request: {summary}."

        else:
            passed, detail = False, "Unsupported block."

        status = "passed" if passed else "failed"
        steps.append(
            {
                "node_id": node["id"],
                "type": node_type,
                "label": label,
                "status": status,
                "detail": detail,
            }
        )
        if not passed:
            flow_alive = False

    logic_passed = bool(flow_alive and action_preview is not None)

    if logic_passed and action_preview is not None:
        delivery = _command_delivery_simulation(
            db,
            device_id=device_id,
            command_type=str(action_preview["type"]),
            now=real_now,
        )
    else:
        delivery = {
            "ready": None,
            "reason": "not_reached",
            "message": "Device delivery was not checked because the flow did not reach its action.",
        }

    if not logic_passed:
        outcome = "stopped"
    elif delivery["ready"]:
        outcome = "would_execute"
    else:
        outcome = "would_request_but_blocked"

    local = _local_datetime(simulated_now, timezone)
    soil = _sensor_value(telemetry, "soil_percent")
    light = _sensor_value(telemetry, "light_lux")

    return {
        "dry_run": True,
        "command_queued": False,
        "source": source,
        "timezone": timezone,
        "simulated_at": int(simulated_now),
        "simulated_local_time": local.strftime("%Y-%m-%d %H:%M:%S %Z"),
        "telemetry_received_at": telemetry_received_at,
        "inputs": {
            "soil_percent": soil,
            "light_lux": light,
        },
        "logic_passed": logic_passed,
        "outcome": outcome,
        "steps": steps,
        "action": action_preview,
        "delivery": delivery,
        "effective_cooldown_seconds": int(effective_cooldown),
    }


def _record_run(
    db: sqlite3.Connection,
    *,
    automation_id: str,
    user_id: int,
    device_id: str,
    trigger: dict[str, Any],
    now: int,
    status: str,
    command_id: str | None = None,
    error: str | None = None,
    result: dict[str, Any] | None = None,
) -> None:
    db.execute(
        """
        INSERT INTO automation_runs(
            run_id, automation_id, user_id, device_id,
            trigger_json, command_id, started_at, completed_at,
            status, result_json, error
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            _new_run_id(),
            automation_id,
            int(user_id),
            device_id,
            json.dumps(trigger, separators=(",", ":"), sort_keys=True),
            command_id,
            int(now),
            int(now) if status in {"skipped", "failed"} else None,
            status,
            (
                json.dumps(result, separators=(",", ":"), sort_keys=True)
                if result is not None
                else None
            ),
            error,
        ),
    )


def evaluate_automations_in_transaction(
    db: sqlite3.Connection,
    *,
    device_id: str,
    message_type: str,
    payload: dict[str, Any],
    now: int,
) -> list[str]:
    """
    Evaluate advanced-user automations after an authenticated FloraCore message.

    At most one automation command is queued per device response. The resulting
    command goes through the same device_commands queue as public API/manual
    control and is then delivered by the existing AES-GCM response path.
    """
    if message_type in {"claim", "ota_status", "command_result"}:
        return []
    if _setup_blocks_automation(payload):
        return []

    rows = db.execute(
        """
        SELECT
            a.automation_id,
            a.user_id,
            a.device_id,
            a.graph_json,
            a.timezone,
            a.last_triggered_at
        FROM automations AS a
        JOIN device_ownership AS o
          ON o.device_id = a.device_id
         AND o.user_id = a.user_id
        WHERE a.device_id = ?
          AND a.enabled = 1
          AND a.advanced_acknowledged_at IS NOT NULL
        ORDER BY a.id ASC
        """,
        (device_id,),
    ).fetchall()

    if not rows:
        return []

    telemetry = _telemetry_payload(
        db,
        device_id=device_id,
        message_type=message_type,
        payload=payload,
    )

    queued: list[str] = []

    for row in rows:
        try:
            graph_raw = json.loads(str(row["graph_json"]))
            graph = validate_graph(graph_raw)
        except (ValueError, TypeError, json.JSONDecodeError, AutomationValidationError):
            continue

        ordered = _ordered_nodes(graph)
        trigger = ordered[0]
        action = ordered[-1]

        matched, trigger_info = _trigger_matches(
            trigger,
            message_type=message_type,
            telemetry=telemetry,
            now=now,
            timezone=str(row["timezone"]),
            last_triggered_at=row["last_triggered_at"],
        )
        if not matched:
            continue

        cooldown = _automation_cooldown(ordered)
        last_triggered = row["last_triggered_at"]
        if last_triggered is not None and int(now) - int(last_triggered) < cooldown:
            continue

        conditions_ok = all(
            _condition_matches(
                node,
                telemetry=telemetry,
                now=now,
                timezone=str(row["timezone"]),
            )
            for node in ordered[1:-1]
            if node["type"] in CONDITION_TYPES
        )
        if not conditions_ok:
            continue

        db.execute(
            """
            UPDATE automations
            SET last_triggered_at = ?, last_evaluated_at = ?
            WHERE automation_id = ?
            """,
            (int(now), int(now), str(row["automation_id"])),
        )

        ready, reason = command_readiness(
            db,
            device_id=device_id,
            now=int(now),
            heartbeat_max_age_seconds=120,
        )
        if not ready:
            _record_run(
                db,
                automation_id=str(row["automation_id"]),
                user_id=int(row["user_id"]),
                device_id=device_id,
                trigger=trigger_info,
                now=now,
                status="skipped",
                error=reason or "control_unavailable",
            )
            break

        try:
            command_type, parameters = _action_command(action)
            command, _ = enqueue_command_in_transaction(
                db,
                user_id=int(row["user_id"]),
                device_id=device_id,
                command_type=command_type,
                parameters=parameters,
                idempotency_key=f"automation-{row['automation_id']}-{int(now)}",
                expires_in_seconds=COMMAND_DEFAULT_TTL_SECONDS,
                now=int(now),
            )
        except CommandValidationError as exc:
            _record_run(
                db,
                automation_id=str(row["automation_id"]),
                user_id=int(row["user_id"]),
                device_id=device_id,
                trigger=trigger_info,
                now=now,
                status="skipped",
                error=exc.code,
                result={"message": exc.message},
            )
            break

        command_id = str(command["command_id"])
        _record_run(
            db,
            automation_id=str(row["automation_id"]),
            user_id=int(row["user_id"]),
            device_id=device_id,
            trigger=trigger_info,
            now=now,
            status="queued",
            command_id=command_id,
        )
        queued.append(command_id)

        # One automation-generated physical action per authenticated device
        # response. Other matching automations remain eligible on later messages.
        break

    return queued


def _automation_to_dict(row: sqlite3.Row, *, include_graph: bool) -> dict[str, Any]:
    data: dict[str, Any] = {
        "automation_id": str(row["automation_id"]),
        "device_id": str(row["device_id"]),
        "name": str(row["name"]),
        "enabled": bool(row["enabled"]),
        "timezone": str(row["timezone"]),
        "created_at": int(row["created_at"]),
        "updated_at": int(row["updated_at"]),
        "last_triggered_at": row["last_triggered_at"],
        "advanced_acknowledged": row["advanced_acknowledged_at"] is not None,
    }
    if include_graph:
        try:
            data["graph"] = json.loads(str(row["graph_json"]))
        except (TypeError, ValueError, json.JSONDecodeError):
            data["graph"] = {"version": 1, "nodes": [], "edges": []}
    return data


def _find_automation(
    db: sqlite3.Connection,
    *,
    user_id: int,
    automation_id: str,
) -> sqlite3.Row | None:
    return db.execute(
        """
        SELECT *
        FROM automations
        WHERE user_id = ? AND automation_id = ?
        LIMIT 1
        """,
        (int(user_id), automation_id),
    ).fetchone()


@automation_api.get("/automations")
def automations_page():
    user_id = _session_user_id()
    if user_id is None:
        return redirect("/login?next=/automations")
    return render_template(
        "automations.html",
        user_email=session.get("email"),
        user_id=user_id,
        csrf_token=_ensure_csrf_token(),
    )


@automation_api.get("/api/automations")
def list_automations():
    user_id = _session_user_id()
    if user_id is None:
        return _api_error("not_authenticated", "Not authenticated.", 401)

    with closing(_connect_path(_db_path())) as db:
        rows = db.execute(
            """
            SELECT *
            FROM automations
            WHERE user_id = ?
            ORDER BY updated_at DESC, id DESC
            """,
            (user_id,),
        ).fetchall()
        devices = db.execute(
            """
            SELECT
                o.device_id,
                o.nickname,
                s.command_protocol,
                (
                    SELECT MAX(m.received_at)
                    FROM device_messages AS m
                    WHERE m.device_id = o.device_id
                      AND m.message_type = 'heartbeat'
                ) AS last_heartbeat_at
            FROM device_ownership AS o
            LEFT JOIN device_state AS s ON s.device_id = o.device_id
            WHERE o.user_id = ?
            ORDER BY o.claimed_at ASC
            """,
            (user_id,),
        ).fetchall()

    now = int(time.time())
    return jsonify(
        data=[_automation_to_dict(row, include_graph=False) for row in rows],
        devices=[
            {
                "device_id": str(row["device_id"]),
                "nickname": row["nickname"],
                "online": (
                    row["last_heartbeat_at"] is not None
                    and 0 <= now - int(row["last_heartbeat_at"]) <= 120
                ),
                "command_protocol": row["command_protocol"],
            }
            for row in devices
        ],
        meta={
            "max_automations": MAX_AUTOMATIONS_PER_USER,
            "engine_version": 1,
        },
    )


@automation_api.post("/api/automations")
def create_automation():
    user_id = _session_user_id()
    if user_id is None:
        return _api_error("not_authenticated", "Not authenticated.", 401)
    if not _csrf_valid():
        return _api_error("csrf_failed", "Invalid or expired security token.", 403)

    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return _api_error("invalid_request", "A JSON object is required.", 400)

    try:
        name = _clean_name(body.get("name"))
        device_id = _clean_device_id(body.get("device_id"))
        timezone = _clean_timezone(body.get("timezone"))
        graph = validate_graph(body.get("graph"))
    except AutomationValidationError as exc:
        return _api_error(exc.code, exc.message, 400)

    now = int(time.time())
    with closing(_connect_path(_db_path())) as db:
        if _owned_device(db, user_id=user_id, device_id=device_id) is None:
            return _api_error("device_not_found", "Device not found.", 404)

        count = db.execute(
            "SELECT COUNT(*) AS n FROM automations WHERE user_id = ?",
            (user_id,),
        ).fetchone()["n"]
        if int(count) >= MAX_AUTOMATIONS_PER_USER:
            return _api_error(
                "automation_limit",
                f"Maximum {MAX_AUTOMATIONS_PER_USER} automations per account.",
                409,
            )

        automation_id = _new_automation_id()
        db.execute(
            """
            INSERT INTO automations(
                automation_id, user_id, device_id, name, enabled,
                graph_json, timezone, created_at, updated_at
            ) VALUES (?, ?, ?, ?, 0, ?, ?, ?, ?)
            """,
            (
                automation_id,
                user_id,
                device_id,
                name,
                json.dumps(graph, separators=(",", ":"), sort_keys=True),
                timezone,
                now,
                now,
            ),
        )
        db.commit()
        row = _find_automation(db, user_id=user_id, automation_id=automation_id)
        assert row is not None

    return jsonify(data=_automation_to_dict(row, include_graph=True)), 201



@automation_api.post("/api/automations/simulate")
def simulate_automation():
    """
    Dry-run an unsaved or saved automation.

    This endpoint is session/CSRF protected and intentionally performs no
    command enqueue, no automation state update, and no hardware I/O.
    """
    user_id = _session_user_id()
    if user_id is None:
        return _api_error("not_authenticated", "Not authenticated.", 401)
    if not _csrf_valid():
        return _api_error("csrf_failed", "Invalid or expired security token.", 403)

    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return _api_error("invalid_request", "A JSON object is required.", 400)

    try:
        device_id = _clean_device_id(body.get("device_id"))
        timezone = _clean_timezone(body.get("timezone"))
        graph = validate_graph(body.get("graph"))
    except AutomationValidationError as exc:
        return _api_error(exc.code, exc.message, 400)

    source = body.get("source", "latest")
    if source not in {"latest", "custom"}:
        return _api_error(
            "invalid_simulation_source",
            "source must be 'latest' or 'custom'.",
            400,
        )

    raw_inputs = body.get("inputs", {})
    if not isinstance(raw_inputs, dict):
        return _api_error("invalid_simulation_inputs", "inputs must be an object.", 400)

    real_now = int(time.time())

    try:
        if source == "custom":
            telemetry: dict[str, Any] = {}
            if raw_inputs.get("soil_percent") is not None:
                telemetry["soil_percent"] = _number(
                    raw_inputs.get("soil_percent"),
                    name="soil percent",
                    minimum=0,
                    maximum=100,
                )
            if raw_inputs.get("light_lux") is not None:
                telemetry["light_lux"] = _number(
                    raw_inputs.get("light_lux"),
                    name="light lux",
                    minimum=0,
                    maximum=250_000,
                )

            local_time = raw_inputs.get("local_time")
            if local_time is not None and not isinstance(local_time, str):
                raise AutomationValidationError(
                    "invalid_simulation_inputs",
                    "local_time must use HH:MM format.",
                )
            simulated_now = _simulation_timestamp(
                timezone,
                local_time.strip() if isinstance(local_time, str) and local_time.strip() else None,
            )
            telemetry_received_at = None
        else:
            simulated_now = real_now
            telemetry = None
            telemetry_received_at = None
    except AutomationValidationError as exc:
        return _api_error(exc.code, exc.message, 400)

    automation_id = body.get("automation_id")
    last_triggered_at: int | None = None

    with closing(_connect_path(_db_path())) as db:
        if _owned_device(db, user_id=user_id, device_id=device_id) is None:
            return _api_error("device_not_found", "Device not found.", 404)

        if isinstance(automation_id, str) and automation_id.strip():
            saved = _find_automation(
                db,
                user_id=user_id,
                automation_id=automation_id.strip(),
            )
            if saved is None:
                return _api_error("automation_not_found", "Automation not found.", 404)
            if str(saved["device_id"]) == device_id:
                last_triggered_at = saved["last_triggered_at"]

        if source == "latest":
            telemetry, telemetry_received_at = _latest_telemetry_snapshot(
                db,
                device_id=device_id,
            )

        result = simulate_automation_graph(
            db,
            graph=graph,
            device_id=device_id,
            timezone=timezone,
            telemetry=telemetry,
            simulated_now=simulated_now,
            real_now=real_now,
            last_triggered_at=last_triggered_at,
            source=source,
            telemetry_received_at=telemetry_received_at,
        )

    return jsonify(data=result)


@automation_api.get("/api/automations/<automation_id>")
def get_automation(automation_id: str):
    user_id = _session_user_id()
    if user_id is None:
        return _api_error("not_authenticated", "Not authenticated.", 401)

    with closing(_connect_path(_db_path())) as db:
        row = _find_automation(db, user_id=user_id, automation_id=automation_id)
    if row is None:
        return _api_error("automation_not_found", "Automation not found.", 404)
    return jsonify(data=_automation_to_dict(row, include_graph=True))


@automation_api.put("/api/automations/<automation_id>")
def update_automation(automation_id: str):
    user_id = _session_user_id()
    if user_id is None:
        return _api_error("not_authenticated", "Not authenticated.", 401)
    if not _csrf_valid():
        return _api_error("csrf_failed", "Invalid or expired security token.", 403)

    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return _api_error("invalid_request", "A JSON object is required.", 400)

    try:
        name = _clean_name(body.get("name"))
        device_id = _clean_device_id(body.get("device_id"))
        timezone = _clean_timezone(body.get("timezone"))
        graph = validate_graph(body.get("graph"))
    except AutomationValidationError as exc:
        return _api_error(exc.code, exc.message, 400)

    now = int(time.time())
    with closing(_connect_path(_db_path())) as db:
        existing = _find_automation(db, user_id=user_id, automation_id=automation_id)
        if existing is None:
            return _api_error("automation_not_found", "Automation not found.", 404)
        if _owned_device(db, user_id=user_id, device_id=device_id) is None:
            return _api_error("device_not_found", "Device not found.", 404)

        # Editing an enabled automation disables it. Advanced users must
        # consciously review and re-enable the changed graph.
        db.execute(
            """
            UPDATE automations
            SET
                device_id = ?,
                name = ?,
                graph_json = ?,
                timezone = ?,
                enabled = 0,
                advanced_acknowledged_at = NULL,
                updated_at = ?
            WHERE user_id = ? AND automation_id = ?
            """,
            (
                device_id,
                name,
                json.dumps(graph, separators=(",", ":"), sort_keys=True),
                timezone,
                now,
                user_id,
                automation_id,
            ),
        )
        db.commit()
        row = _find_automation(db, user_id=user_id, automation_id=automation_id)
        assert row is not None

    return jsonify(data=_automation_to_dict(row, include_graph=True))


@automation_api.post("/api/automations/<automation_id>/enabled")
def set_automation_enabled(automation_id: str):
    user_id = _session_user_id()
    if user_id is None:
        return _api_error("not_authenticated", "Not authenticated.", 401)
    if not _csrf_valid():
        return _api_error("csrf_failed", "Invalid or expired security token.", 403)

    body = request.get_json(silent=True)
    if not isinstance(body, dict) or not isinstance(body.get("enabled"), bool):
        return _api_error("invalid_request", "enabled must be true or false.", 400)

    enabled = bool(body["enabled"])
    acknowledged = body.get("acknowledge_advanced_control") is True
    now = int(time.time())

    with closing(_connect_path(_db_path())) as db:
        row = _find_automation(db, user_id=user_id, automation_id=automation_id)
        if row is None:
            return _api_error("automation_not_found", "Automation not found.", 404)

        if enabled:
            if not acknowledged:
                return _api_error(
                    "advanced_acknowledgement_required",
                    "Confirm that this automation may activate physical hardware.",
                    409,
                )
            try:
                validate_graph(json.loads(str(row["graph_json"])))
            except (AutomationValidationError, ValueError, TypeError, json.JSONDecodeError):
                return _api_error("invalid_graph", "Automation graph is invalid.", 409)

            if _owned_device(
                db,
                user_id=user_id,
                device_id=str(row["device_id"]),
            ) is None:
                return _api_error("device_not_found", "Device not found.", 404)

        db.execute(
            """
            UPDATE automations
            SET
                enabled = ?,
                advanced_acknowledged_at = ?,
                updated_at = ?
            WHERE user_id = ? AND automation_id = ?
            """,
            (
                1 if enabled else 0,
                now if enabled else row["advanced_acknowledged_at"],
                now,
                user_id,
                automation_id,
            ),
        )
        db.commit()
        updated = _find_automation(db, user_id=user_id, automation_id=automation_id)
        assert updated is not None

    return jsonify(data=_automation_to_dict(updated, include_graph=False))


@automation_api.delete("/api/automations/<automation_id>")
def delete_automation(automation_id: str):
    user_id = _session_user_id()
    if user_id is None:
        return _api_error("not_authenticated", "Not authenticated.", 401)
    if not _csrf_valid():
        return _api_error("csrf_failed", "Invalid or expired security token.", 403)

    with closing(_connect_path(_db_path())) as db:
        row = _find_automation(db, user_id=user_id, automation_id=automation_id)
        if row is None:
            return _api_error("automation_not_found", "Automation not found.", 404)
        db.execute(
            "DELETE FROM automation_runs WHERE user_id = ? AND automation_id = ?",
            (user_id, automation_id),
        )
        db.execute(
            "DELETE FROM automations WHERE user_id = ? AND automation_id = ?",
            (user_id, automation_id),
        )
        db.commit()

    return jsonify(data={"deleted": True, "automation_id": automation_id})


@automation_api.get("/api/automations/<automation_id>/runs")
def automation_runs(automation_id: str):
    user_id = _session_user_id()
    if user_id is None:
        return _api_error("not_authenticated", "Not authenticated.", 401)

    raw_limit = request.args.get("limit", "20")
    try:
        limit = int(raw_limit)
    except ValueError:
        return _api_error("invalid_limit", "limit must be an integer.", 400)
    limit = max(1, min(limit, 50))

    with closing(_connect_path(_db_path())) as db:
        row = _find_automation(db, user_id=user_id, automation_id=automation_id)
        if row is None:
            return _api_error("automation_not_found", "Automation not found.", 404)

        rows = db.execute(
            """
            SELECT
                r.run_id,
                r.device_id,
                r.trigger_json,
                r.command_id,
                r.started_at,
                r.completed_at,
                r.status AS run_status,
                r.result_json AS run_result,
                r.error AS run_error,
                c.status AS command_status,
                c.acknowledged_at,
                c.completed_at AS command_completed_at,
                c.result_json AS command_result,
                c.error AS command_error
            FROM automation_runs AS r
            LEFT JOIN device_commands AS c ON c.command_id = r.command_id
            WHERE r.user_id = ? AND r.automation_id = ?
            ORDER BY r.id DESC
            LIMIT ?
            """,
            (user_id, automation_id, limit),
        ).fetchall()

    data = []
    for item in rows:
        status = item["command_status"] or item["run_status"]
        completed_at = item["command_completed_at"] or item["completed_at"]
        raw_result = item["command_result"] or item["run_result"]
        raw_trigger = item["trigger_json"]
        try:
            result = json.loads(str(raw_result)) if raw_result else None
        except (TypeError, ValueError, json.JSONDecodeError):
            result = None
        try:
            trigger = json.loads(str(raw_trigger)) if raw_trigger else None
        except (TypeError, ValueError, json.JSONDecodeError):
            trigger = None

        data.append(
            {
                "run_id": str(item["run_id"]),
                "device_id": str(item["device_id"]),
                "command_id": item["command_id"],
                "status": str(status),
                "started_at": int(item["started_at"]),
                "completed_at": completed_at,
                "acknowledged_at": item["acknowledged_at"],
                "trigger": trigger,
                "result": result,
                "error": item["command_error"] or item["run_error"],
            }
        )

    return jsonify(data=data, meta={"limit": limit})
