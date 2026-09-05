from __future__ import annotations

from collections import defaultdict, deque
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
import json
import math
import secrets
import sqlite3
import time

from floraos_commands import (
    COMMAND_DEFAULT_TTL_SECONDS,
    CommandValidationError,
    command_readiness,
    enqueue_command_in_transaction,
    validate_command,
)
from floraos_insights import calibrated_metric, connect, json_object, owned_device
from floraos_notifications import create_notification_in_transaction

MAX_NODES = 32
MAX_GRAPH_BYTES = 64 * 1024
BLOCKED_SETUP_STATES = {"SETUP_IDLE", "SETUP_CONNECTING", "SETUP_WIFI_CONNECTED", "SETUP_CLAIMING"}
TRIGGERS = {"trigger_telemetry", "trigger_soil_below", "trigger_soil_above", "trigger_light_below", "trigger_light_above", "trigger_schedule"}
CONDITIONS = {"condition_soil_below", "condition_soil_above", "condition_light_below", "condition_light_above", "condition_water_above", "condition_fertilizer_above", "condition_time_between", "condition_day_of_week"}
FLOW = {"logic_or", "delay"}
ACTIONS = {"action_water", "action_grow_light", "action_notify", "action_fertilize"}
ALL_TYPES = TRIGGERS | CONDITIONS | FLOW | ACTIONS


class AutomationV2Error(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def init_automation_v2_schema(db_path: str | Path) -> None:
    with closing(connect(db_path)) as db:
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS floraos_automations_v2 (
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
                last_evaluated_at INTEGER,
                advanced_acknowledged_at INTEGER,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_floraos_aut2_device
                ON floraos_automations_v2(device_id, enabled, id);
            CREATE INDEX IF NOT EXISTS idx_floraos_aut2_owner
                ON floraos_automations_v2(user_id, updated_at DESC);

            CREATE TABLE IF NOT EXISTS floraos_automation_v2_runs (
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
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_floraos_aut2_runs
                ON floraos_automation_v2_runs(user_id, device_id, started_at DESC);

            CREATE TABLE IF NOT EXISTS floraos_automation_v2_pending (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pending_id TEXT UNIQUE NOT NULL,
                automation_id TEXT NOT NULL,
                user_id INTEGER NOT NULL,
                device_id TEXT NOT NULL,
                node_id TEXT NOT NULL,
                due_at INTEGER NOT NULL,
                context_json TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                last_error TEXT,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_floraos_aut2_pending_due
                ON floraos_automation_v2_pending(device_id, due_at, id);
            """
        )
        db.commit()


def timezone_or_error(name: str) -> ZoneInfo:
    try:
        return ZoneInfo(name)
    except ZoneInfoNotFoundError as exc:
        raise AutomationV2Error("invalid_timezone", "Unknown timezone.") from exc


def _number(config: dict[str, Any], key: str, low: float, high: float) -> float:
    value = config.get(key)
    if isinstance(value, bool):
        raise AutomationV2Error("invalid_node_config", f"{key} must be numeric.")
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise AutomationV2Error("invalid_node_config", f"{key} must be numeric.") from exc
    if not math.isfinite(number) or not low <= number <= high:
        raise AutomationV2Error("invalid_node_config", f"{key} must be {low:g}–{high:g}.")
    return number


def _hhmm(value: Any, label: str) -> str:
    text = str(value or "")
    if len(text) != 5 or text[2] != ":":
        raise AutomationV2Error("invalid_node_config", f"{label} must be HH:MM.")
    try:
        hour, minute = map(int, text.split(":"))
    except ValueError as exc:
        raise AutomationV2Error("invalid_node_config", f"{label} must be HH:MM.") from exc
    if not (0 <= hour <= 23 and 0 <= minute <= 59):
        raise AutomationV2Error("invalid_node_config", f"{label} must be HH:MM.")
    return text


def validate_node(node: dict[str, Any]) -> None:
    t = node["type"]
    c = node["config"]
    if t in {"trigger_soil_below", "trigger_soil_above", "condition_soil_below", "condition_soil_above"}:
        _number(c, "percent", 0, 100)
    elif t in {"trigger_light_below", "trigger_light_above", "condition_light_below", "condition_light_above"}:
        _number(c, "lux", 0, 200000)
    elif t in {"condition_water_above", "condition_fertilizer_above"}:
        _number(c, "percent", 0, 100)
    elif t == "trigger_schedule":
        _hhmm(c.get("time"), "Schedule time")
    elif t == "condition_time_between":
        _hhmm(c.get("start"), "Start time")
        _hhmm(c.get("end"), "End time")
    elif t == "condition_day_of_week":
        days = c.get("days")
        allowed = {"mon", "tue", "wed", "thu", "fri", "sat", "sun"}
        if not isinstance(days, list) or not days or any(str(x).lower() not in allowed for x in days):
            raise AutomationV2Error("invalid_node_config", "Day condition needs valid weekday abbreviations.")
    elif t == "delay":
        c["seconds"] = int(_number(c, "seconds", 5, 86400))
    elif t == "action_water":
        duration = int(_number(c, "duration_ms", 500, 30000))
        validate_command("water", {"duration_ms": duration})
        c["duration_ms"] = duration
    elif t == "action_grow_light":
        state = str(c.get("state", "")).lower()
        if state == "off":
            validate_command("grow_light", {"state": "off"})
        elif state == "on":
            duration = int(_number(c, "duration_seconds", 60, 43200))
            validate_command("grow_light", {"state": "on", "duration_seconds": duration})
            c["duration_seconds"] = duration
        else:
            raise AutomationV2Error("invalid_node_config", "Grow-light state must be on or off.")
        c["state"] = state
    elif t == "action_notify":
        title = str(c.get("title", "")).strip()
        message = str(c.get("message", "")).strip()
        severity = str(c.get("severity", "info")).lower()
        if not title or len(title) > 160 or not message or len(message) > 1200:
            raise AutomationV2Error("invalid_node_config", "Notification title/message is invalid.")
        if severity not in {"info", "success", "warning", "critical"}:
            raise AutomationV2Error("invalid_node_config", "Notification severity is invalid.")
        c.update(title=title, message=message, severity=severity)
    elif t == "action_fertilize":
        c["volume_ml"] = _number(c, "volume_ml", .5, 50)


def validate_graph(graph: Any) -> dict[str, Any]:
    if not isinstance(graph, dict) or int(graph.get("version", 0)) != 2:
        raise AutomationV2Error("invalid_graph_version", "Automation Studio v2 requires graph version 2.")
    encoded = json.dumps(graph, separators=(",", ":"), sort_keys=True)
    if len(encoded.encode()) > MAX_GRAPH_BYTES:
        raise AutomationV2Error("graph_too_large", "Automation graph exceeds 64 KiB.")
    nodes_raw, edges_raw = graph.get("nodes"), graph.get("edges")
    if not isinstance(nodes_raw, list) or not isinstance(edges_raw, list) or not 1 <= len(nodes_raw) <= MAX_NODES:
        raise AutomationV2Error("invalid_graph", f"Use 1–{MAX_NODES} nodes and an edges array.")

    nodes: dict[str, dict[str, Any]] = {}
    for raw in nodes_raw:
        if not isinstance(raw, dict):
            raise AutomationV2Error("invalid_node", "Every node must be an object.")
        node_id = str(raw.get("id", "")).strip()
        node_type = str(raw.get("type", "")).strip()
        config = raw.get("config", {})
        if not node_id or len(node_id) > 48 or not all(ch.isalnum() or ch in "_-" for ch in node_id):
            raise AutomationV2Error("invalid_node", "Node ids use letters, numbers, _ or - and max 48 chars.")
        if node_id in nodes:
            raise AutomationV2Error("duplicate_node", f"Duplicate node {node_id}.")
        if node_type not in ALL_TYPES or not isinstance(config, dict):
            raise AutomationV2Error("unsupported_node", f"Unsupported or invalid node {node_id}.")
        node = {"id": node_id, "type": node_type, "config": dict(config)}
        validate_node(node)
        nodes[node_id] = node

    if not any(x["type"] in TRIGGERS for x in nodes.values()):
        raise AutomationV2Error("trigger_required", "At least one trigger is required.")
    if not any(x["type"] in ACTIONS for x in nodes.values()):
        raise AutomationV2Error("action_required", "At least one action is required.")

    indegree = {node_id: 0 for node_id in nodes}
    outgoing: dict[str, list[dict[str, str]]] = defaultdict(list)
    edges = []
    for raw in edges_raw:
        if not isinstance(raw, dict):
            raise AutomationV2Error("invalid_edge", "Every edge must be an object.")
        source, target = str(raw.get("from", "")).strip(), str(raw.get("to", "")).strip()
        when = str(raw.get("when", "always")).lower()
        if source not in nodes or target not in nodes or source == target or when not in {"always", "true", "false"}:
            raise AutomationV2Error("invalid_edge", "Invalid graph edge.")
        edge = {"from": source, "to": target, "when": when}
        edges.append(edge)
        outgoing[source].append(edge)
        indegree[target] += 1

    # DAG requirement.
    degrees = dict(indegree)
    q = deque([node_id for node_id, degree in degrees.items() if degree == 0])
    seen = 0
    while q:
        node_id = q.popleft()
        seen += 1
        for edge in outgoing.get(node_id, []):
            degrees[edge["to"]] -= 1
            if degrees[edge["to"]] == 0:
                q.append(edge["to"])
    if seen != len(nodes):
        raise AutomationV2Error("graph_cycle", "Automation Studio v2 graphs cannot contain cycles.")
    return {"version": 2, "nodes": list(nodes.values()), "edges": edges}


def maps(graph: dict[str, Any]):
    nodes = {x["id"]: x for x in graph["nodes"]}
    outgoing: dict[str, list[dict[str, str]]] = defaultdict(list)
    for edge in graph["edges"]:
        outgoing[edge["from"]].append(edge)
    return nodes, outgoing


def local_dt(now: int, timezone_name: str) -> datetime:
    return datetime.fromtimestamp(int(now), tz=timezone.utc).astimezone(timezone_or_error(timezone_name))


def trigger_matches(db: sqlite3.Connection, node: dict[str, Any], user_id: int, device_id: str, message_type: str, payload: dict[str, Any], now: int, timezone_name: str, last_evaluated: int | None) -> bool:
    t, c = node["type"], node["config"]
    if t == "trigger_telemetry":
        return message_type == "telemetry"
    if t.startswith("trigger_soil_"):
        value = calibrated_metric(db, user_id, device_id, "soil", payload)
        if message_type != "telemetry" or value is None:
            return False
        return value < float(c["percent"]) if t.endswith("below") else value > float(c["percent"])
    if t.startswith("trigger_light_"):
        value = calibrated_metric(db, user_id, device_id, "light", payload)
        if message_type != "telemetry" or value is None:
            return False
        return value < float(c["lux"]) if t.endswith("below") else value > float(c["lux"])
    if t == "trigger_schedule":
        local = local_dt(now, timezone_name)
        if local.strftime("%H:%M") != str(c["time"]):
            return False
        if last_evaluated is None:
            return True
        return local_dt(last_evaluated, timezone_name).strftime("%Y-%m-%d %H:%M") != local.strftime("%Y-%m-%d %H:%M")
    return False


def condition_matches(db: sqlite3.Connection, node: dict[str, Any], user_id: int, device_id: str, payload: dict[str, Any], now: int, timezone_name: str) -> bool:
    t, c = node["type"], node["config"]
    if t.startswith("condition_soil_"):
        value = calibrated_metric(db, user_id, device_id, "soil", payload)
        if value is None:
            return False
        return value < float(c["percent"]) if t.endswith("below") else value > float(c["percent"])
    if t.startswith("condition_light_"):
        value = calibrated_metric(db, user_id, device_id, "light", payload)
        if value is None:
            return False
        return value < float(c["lux"]) if t.endswith("below") else value > float(c["lux"])
    if t == "condition_water_above":
        value = calibrated_metric(db, user_id, device_id, "water", payload)
        return value is not None and value > float(c["percent"])
    if t == "condition_fertilizer_above":
        value = calibrated_metric(db, user_id, device_id, "fertilizer", payload)
        return value is not None and value > float(c["percent"])
    if t == "condition_time_between":
        current = local_dt(now, timezone_name).strftime("%H:%M")
        start, end = str(c["start"]), str(c["end"])
        return start <= current <= end if start <= end else current >= start or current <= end
    if t == "condition_day_of_week":
        day = local_dt(now, timezone_name).strftime("%a").lower()[:3]
        return day in {str(x).lower() for x in c["days"]}
    return True


def active_physical_command(db: sqlite3.Connection, device_id: str) -> bool:
    return db.execute(
        "SELECT 1 FROM device_commands WHERE device_id=? AND status IN ('queued','delivered','acknowledged') AND completed_at IS NULL LIMIT 1",
        (device_id,),
    ).fetchone() is not None


def record_run(db: sqlite3.Connection, *, automation_id: str, user_id: int, device_id: str, now: int, status: str, trigger: dict[str, Any] | None = None, command_id: str | None = None, result: dict[str, Any] | None = None, error: str | None = None) -> str:
    run_id = "run2_" + secrets.token_urlsafe(14)
    db.execute(
        """INSERT INTO floraos_automation_v2_runs(run_id,automation_id,user_id,device_id,trigger_json,command_id,started_at,completed_at,status,result_json,error)
           VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
        (
            run_id, automation_id, int(user_id), device_id,
            json.dumps(trigger, separators=(",", ":"), sort_keys=True) if trigger else None,
            command_id, int(now), int(now) if status in {"completed","skipped","failed","notified","delayed"} else None,
            status, json.dumps(result, separators=(",", ":"), sort_keys=True) if result else None, error,
        ),
    )
    return run_id


def schedule_pending(db: sqlite3.Connection, *, automation_id: str, user_id: int, device_id: str, node_id: str, due_at: int, context: dict[str, Any], now: int) -> None:
    db.execute(
        """INSERT INTO floraos_automation_v2_pending(pending_id,automation_id,user_id,device_id,node_id,due_at,context_json,created_at)
           VALUES(?,?,?,?,?,?,?,?)""",
        ("pend_" + secrets.token_urlsafe(14), automation_id, int(user_id), device_id, node_id, int(due_at), json.dumps(context, separators=(",", ":"), sort_keys=True), int(now)),
    )


def queue_physical(db: sqlite3.Connection, *, automation_id: str, user_id: int, device_id: str, node: dict[str, Any], now: int) -> str:
    ready, reason = command_readiness(db, device_id=device_id, now=now, heartbeat_max_age_seconds=120)
    if not ready:
        raise AutomationV2Error(reason or "control_unavailable", "Device control is unavailable.")
    if active_physical_command(db, device_id):
        raise AutomationV2Error("command_in_progress", "Another physical command is active.")

    t, c = node["type"], node["config"]
    if t == "action_water":
        command_type, params = validate_command("water", {"duration_ms": int(c["duration_ms"])})
    elif t == "action_grow_light":
        params_raw = {"state": c["state"]}
        if c["state"] == "on":
            params_raw["duration_seconds"] = int(c["duration_seconds"])
        command_type, params = validate_command("grow_light", params_raw)
    elif t == "action_fertilize":
        # Local import avoids a module cycle. The web phase validates an
        # authenticated capability plus pump-flow calibration and daily limits.
        from floraos_web_phase20 import fertilizer_parameters
        command_type = "fertilize"
        params = fertilizer_parameters(db, user_id=user_id, device_id=device_id, volume_ml=c["volume_ml"], now=now)
    else:
        raise AutomationV2Error("unsupported_action", "Unsupported physical action.")

    command, _ = enqueue_command_in_transaction(
        db, user_id=user_id, device_id=device_id, command_type=command_type,
        parameters=params, idempotency_key=f"aut2-{automation_id}-{node['id']}-{now}",
        expires_in_seconds=COMMAND_DEFAULT_TTL_SECONDS, now=now,
    )
    return str(command["command_id"])


def execute_from(db: sqlite3.Connection, *, automation_id: str, user_id: int, device_id: str, graph: dict[str, Any], start_nodes: list[str], payload: dict[str, Any], now: int, timezone_name: str, trigger_context: dict[str, Any]) -> bool:
    nodes, outgoing = maps(graph)
    queue = deque(start_nodes)
    reached: set[str] = set()
    physical_queued = False
    while queue:
        node_id = queue.popleft()
        if node_id in reached:
            continue
        reached.add(node_id)
        node = nodes[node_id]
        t = node["type"]

        if t in CONDITIONS:
            passed = condition_matches(db, node, user_id, device_id, payload, now, timezone_name)
            for edge in outgoing.get(node_id, []):
                if edge["when"] == "always" or edge["when"] == ("true" if passed else "false"):
                    queue.append(edge["to"])
            continue
        if t == "logic_or":
            for edge in outgoing.get(node_id, []):
                if edge["when"] in {"always", "true"}:
                    queue.append(edge["to"])
            continue
        if t == "delay":
            for edge in outgoing.get(node_id, []):
                schedule_pending(db, automation_id=automation_id, user_id=user_id, device_id=device_id, node_id=edge["to"], due_at=now+int(node["config"]["seconds"]), context=trigger_context, now=now)
            record_run(db, automation_id=automation_id, user_id=user_id, device_id=device_id, now=now, status="delayed", trigger=trigger_context, result={"seconds": int(node["config"]["seconds"])})
            continue
        if t == "action_notify":
            c = node["config"]
            note = create_notification_in_transaction(
                db, user_id=user_id, device_id=device_id, category="automation", severity=c["severity"],
                title=c["title"], message=c["message"], dedup_key=f"aut2:{automation_id}:{node_id}:{now//60}", now=now,
            )
            record_run(db, automation_id=automation_id, user_id=user_id, device_id=device_id, now=now, status="notified", trigger=trigger_context, result={"notification_id": note})
        elif t in {"action_water", "action_grow_light", "action_fertilize"}:
            if physical_queued:
                schedule_pending(db, automation_id=automation_id, user_id=user_id, device_id=device_id, node_id=node_id, due_at=now+60, context=trigger_context, now=now)
                continue
            try:
                command_id = queue_physical(db, automation_id=automation_id, user_id=user_id, device_id=device_id, node=node, now=now)
                physical_queued = True
                record_run(db, automation_id=automation_id, user_id=user_id, device_id=device_id, now=now, status="queued", trigger=trigger_context, command_id=command_id)
            except (AutomationV2Error, CommandValidationError) as exc:
                code = getattr(exc, "code", "command_blocked")
                record_run(db, automation_id=automation_id, user_id=user_id, device_id=device_id, now=now, status="skipped", trigger=trigger_context, error=code, result={"message": str(exc)})
                schedule_pending(db, automation_id=automation_id, user_id=user_id, device_id=device_id, node_id=node_id, due_at=now+60, context=trigger_context, now=now)
                continue
        for edge in outgoing.get(node_id, []):
            if edge["when"] in {"always", "true"}:
                queue.append(edge["to"])
    return physical_queued


def process_pending(db: sqlite3.Connection, device_id: str, payload: dict[str, Any], now: int) -> bool:
    if active_physical_command(db, device_id):
        return False
    row = db.execute(
        """SELECT p.*,a.graph_json,a.timezone,a.enabled FROM floraos_automation_v2_pending p
           JOIN floraos_automations_v2 a ON a.automation_id=p.automation_id
           WHERE p.device_id=? AND p.due_at<=? AND a.enabled=1 ORDER BY p.due_at ASC,p.id ASC LIMIT 1""",
        (device_id, now),
    ).fetchone()
    if not row:
        return False
    try:
        graph = validate_graph(json_object(row["graph_json"]))
        queued = execute_from(
            db, automation_id=str(row["automation_id"]), user_id=int(row["user_id"]), device_id=device_id,
            graph=graph, start_nodes=[str(row["node_id"])], payload=payload, now=now,
            timezone_name=str(row["timezone"]), trigger_context=json_object(row["context_json"]),
        )
        db.execute("DELETE FROM floraos_automation_v2_pending WHERE id=?", (int(row["id"]),))
        return queued
    except Exception as exc:
        db.execute("UPDATE floraos_automation_v2_pending SET attempts=attempts+1,due_at=?,last_error=? WHERE id=?", (now+60, f"{type(exc).__name__}: {exc}"[:500], int(row["id"])))
        return False


def evaluate_in_transaction(db: sqlite3.Connection, *, device_id: str, message_type: str, payload: dict[str, Any], now: int) -> None:
    if message_type in {"claim", "ota_status", "command_result"}:
        return
    if any(isinstance(payload.get(k), str) and str(payload[k]).upper() in BLOCKED_SETUP_STATES for k in ("mode", "state", "setup_state")):
        return
    if process_pending(db, device_id, payload, now):
        return

    rows = db.execute(
        """SELECT a.* FROM floraos_automations_v2 a
           JOIN device_ownership o ON o.user_id=a.user_id AND o.device_id=a.device_id
           WHERE a.device_id=? AND a.enabled=1 AND a.advanced_acknowledged_at IS NOT NULL ORDER BY a.id ASC""",
        (device_id,),
    ).fetchall()
    for row in rows:
        try:
            graph = validate_graph(json_object(row["graph_json"]))
            nodes, outgoing = maps(graph)
            starts: list[str] = []
            matched: list[str] = []
            for node in nodes.values():
                if node["type"] in TRIGGERS and trigger_matches(db, node, int(row["user_id"]), device_id, message_type, payload, now, str(row["timezone"]), row["last_evaluated_at"]):
                    matched.append(node["id"])
                    starts.extend(edge["to"] for edge in outgoing.get(node["id"], []))
            db.execute("UPDATE floraos_automations_v2 SET last_evaluated_at=? WHERE id=?", (now, int(row["id"])))
            if not starts:
                continue
            physical = execute_from(
                db, automation_id=str(row["automation_id"]), user_id=int(row["user_id"]), device_id=device_id,
                graph=graph, start_nodes=starts, payload=payload, now=now, timezone_name=str(row["timezone"]),
                trigger_context={"message_type": message_type, "matched_triggers": matched, "evaluated_at": now},
            )
            if physical:
                break
        except Exception as exc:
            record_run(db, automation_id=str(row["automation_id"]), user_id=int(row["user_id"]), device_id=device_id, now=now, status="failed", error=f"{type(exc).__name__}: {exc}"[:500])


def reconcile_command_result(db: sqlite3.Connection, device_id: str, payload: dict[str, Any], now: int) -> None:
    command_id = payload.get("command_id", payload.get("id"))
    if not isinstance(command_id, str):
        return
    row = db.execute("SELECT status,result_json,error,completed_at FROM device_commands WHERE command_id=? AND device_id=? LIMIT 1", (command_id, device_id)).fetchone()
    if not row:
        return
    db.execute(
        """UPDATE floraos_automation_v2_runs SET status=?,completed_at=COALESCE(?,completed_at),
           result_json=COALESCE(?,result_json),error=COALESCE(?,error) WHERE command_id=? AND device_id=?""",
        (str(row["status"]), row["completed_at"] or now, row["result_json"], row["error"], command_id, device_id),
    )


def recommendation_graphs(profile: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not profile:
        return []
    soil = max(0.0, float(profile["soil_min"]) - 5)
    water_guard = max(25.0, float(profile["water_low"]) + 10)
    light = float(profile["light_min"])
    return [
        {
            "slug": "keep-soil-in-range", "name": f"Keep {profile['plant_name']} soil in range",
            "summary": f"Water for 5 seconds below {soil:g}% only when the water reservoir is above {water_guard:g}%.",
            "graph": {"version": 2, "nodes": [
                {"id":"dry","type":"trigger_soil_below","config":{"percent":soil}},
                {"id":"water_ok","type":"condition_water_above","config":{"percent":water_guard}},
                {"id":"water","type":"action_water","config":{"duration_ms":5000}},
            ], "edges": [
                {"from":"dry","to":"water_ok","when":"always"}, {"from":"water_ok","to":"water","when":"true"},
            ]},
        },
        {
            "slug": "support-low-light", "name": f"Support {profile['plant_name']} in low light",
            "summary": f"Run grow light for 30 minutes during daytime when light is below {light:g} lux.",
            "graph": {"version": 2, "nodes": [
                {"id":"low","type":"trigger_light_below","config":{"lux":light}},
                {"id":"day","type":"condition_time_between","config":{"start":"07:00","end":"19:00"}},
                {"id":"light","type":"action_grow_light","config":{"state":"on","duration_seconds":1800}},
            ], "edges": [
                {"from":"low","to":"day","when":"always"}, {"from":"day","to":"light","when":"true"},
            ]},
        },
    ]
