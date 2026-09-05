from __future__ import annotations

from contextlib import closing
from pathlib import Path
from typing import Any
import hmac
import json
import math
import secrets
import sqlite3
import time

from flask import Blueprint, current_app, jsonify, redirect, render_template, request, session

from floraos_commands import (
    COMMAND_DEFAULT_TTL_SECONDS,
    CommandValidationError,
    cancel_command_in_transaction,
    command_readiness,
    command_row_to_dict,
    enqueue_command_in_transaction,
    validate_command,
    validate_idempotency_key,
    validate_ttl,
)
from floraos_insights import (
    MAX_HISTORY_SECONDS,
    METRICS,
    RANGES,
    calibrated_metric,
    care_score_v2,
    connect,
    downsample,
    history_samples,
    init_insights_schema,
    json_object,
    latest_telemetry,
    metric_summary,
    online_status,
    owned_device,
    plant_profile,
    reservoir_summary,
    runtime_profile,
    save_runtime_from_authenticated_payload,
    target_for,
    trend_analysis,
)
from floraos_notifications import (
    CATEGORIES,
    DEFAULTS,
    SEVERITY_RANK,
    create_notification_in_transaction,
    dispatch_pending_emails,
    init_notification_schema,
    preference,
    process_notification_message_in_transaction,
    sweep_offline,
)
from floraos_automation_v2 import (
    AutomationV2Error,
    evaluate_in_transaction as evaluate_automation_v2,
    init_automation_v2_schema,
    recommendation_graphs,
    reconcile_command_result,
    timezone_or_error,
    validate_graph as validate_automation_v2_graph,
)

phase20 = Blueprint("floraos_phase20", __name__)

ONLINE_SECONDS = 120
FERTILIZER_MIN_ML = .5
FERTILIZER_MAX_SINGLE_ML = 50.0
FERTILIZER_MAX_DAILY_ML = 100.0
FERTILIZER_MAX_RUNTIME_MS = 30000


def init_phase20(app, db_path: str | Path) -> None:
    resolved = Path(db_path)
    app.config["FLORAOS_PHASE20_DB_PATH"] = str(resolved)
    app.config["FLORAOS_DB_PATH"] = str(resolved)
    init_insights_schema(resolved)
    init_notification_schema(resolved)
    init_automation_v2_schema(resolved)
    app.register_blueprint(phase20)


def _db_path() -> Path:
    value = current_app.config.get("FLORAOS_PHASE20_DB_PATH") or current_app.config.get("FLORAOS_DB_PATH")
    if not value:
        raise RuntimeError("FloraOS DB path not configured")
    return Path(value)


def _user_id() -> int | None:
    raw = session.get("user_id")
    try:
        return int(raw) if raw is not None else None
    except (TypeError, ValueError):
        return None


def _csrf() -> str:
    token = session.get("csrf_token")
    if not isinstance(token, str) or not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


def _csrf_valid() -> bool:
    supplied = request.headers.get("X-CSRF-Token", "")
    expected = session.get("csrf_token", "")
    return bool(isinstance(expected, str) and supplied and expected and hmac.compare_digest(supplied, expected))


def _error(code: str, message: str, status: int):
    return jsonify(error={"code": code, "message": message}), status


def _require_user():
    user_id = _user_id()
    if user_id is None:
        return None, _error("not_authenticated", "Not authenticated.", 401)
    return user_id, None


def _require_csrf():
    return None if _csrf_valid() else _error("csrf_failed", "Invalid or expired security token.", 403)


def capability_true(capabilities: dict[str, Any], *paths: tuple[str, ...]) -> bool:
    for path in paths:
        current: Any = capabilities
        found = True
        for key in path:
            if not isinstance(current, dict) or key not in current:
                found = False
                break
            current = current[key]
        if found and (current is True or (isinstance(current, int) and not isinstance(current, bool) and current >= 1)):
            return True
    return False


def fertilizer_parameters(db: sqlite3.Connection, *, user_id: int, device_id: str, volume_ml: Any, now: int) -> dict[str, Any]:
    runtime = runtime_profile(db, device_id)
    cap = runtime["capabilities"]
    if not capability_true(cap, ("actuators", "fertilizer_pump"), ("commands", "fertilize"), ("fertilizer_pump",), ("fertilize",)):
        raise AutomationV2Error("fertilizer_capability_unavailable", "Authenticated firmware has not reported fertilizer-pump command support.")

    row = db.execute(
        "SELECT calibration_type,config_json FROM floraos_device_calibrations WHERE user_id=? AND device_id=? AND sensor_key='fertilizer_pump' LIMIT 1",
        (int(user_id), device_id),
    ).fetchone()
    if not row or str(row["calibration_type"]) != "pump_flow":
        raise AutomationV2Error("fertilizer_calibration_required", "Fertilizer control is locked until pump-flow calibration is saved.")
    cfg = json_object(row["config_json"])
    try:
        mlps = float(cfg["ml_per_second"])
        max_single = min(float(cfg.get("max_single_ml", 20)), FERTILIZER_MAX_SINGLE_ML)
        max_daily = min(float(cfg.get("max_daily_ml", 50)), FERTILIZER_MAX_DAILY_ML)
        volume = float(volume_ml)
    except (KeyError, TypeError, ValueError) as exc:
        raise AutomationV2Error("invalid_fertilizer_calibration", "Fertilizer calibration is invalid.") from exc
    if not (0.05 <= mlps <= 100):
        raise AutomationV2Error("invalid_fertilizer_calibration", "Fertilizer flow calibration is outside accepted limits.")
    if not math.isfinite(volume) or not FERTILIZER_MIN_ML <= volume <= max_single:
        raise AutomationV2Error("unsafe_fertilizer_volume", f"Dose must be {FERTILIZER_MIN_ML:g}–{max_single:g} mL.")

    used = 0.0
    rows = db.execute(
        """SELECT parameters_json FROM device_commands WHERE user_id=? AND device_id=? AND command_type='fertilize'
           AND created_at>=? AND status NOT IN ('failed','cancelled','expired')""",
        (int(user_id), device_id, int(now)-86400),
    ).fetchall()
    for command in rows:
        try:
            used += float(json_object(command["parameters_json"]).get("volume_ml", 0))
        except (TypeError, ValueError):
            pass
    if used + volume > max_daily:
        raise AutomationV2Error("fertilizer_daily_limit", f"This dose would exceed the {max_daily:g} mL rolling 24-hour limit.")
    duration_ms = round(volume / mlps * 1000)
    if not 100 <= duration_ms <= FERTILIZER_MAX_RUNTIME_MS:
        raise AutomationV2Error("unsafe_fertilizer_runtime", "Calculated dosing runtime is outside the safe web envelope.")
    return {"volume_ml": round(volume, 3), "duration_ms": int(duration_ms), "calibration_ml_per_second": mlps}


def process_phase20_message_in_transaction(db: sqlite3.Connection, *, device_id: str, message_type: str, payload: dict[str, Any], now: int) -> None:
    """Post-authentication web intelligence hook. Never breaks the device plane."""
    db.execute("SAVEPOINT floraos_phase20")
    try:
        save_runtime_from_authenticated_payload(db, device_id, payload, now)
        process_notification_message_in_transaction(db, device_id=device_id, message_type=message_type, payload=payload, now=now)
        if message_type == "command_result":
            reconcile_command_result(db, device_id, payload, now)
        evaluate_automation_v2(db, device_id=device_id, message_type=message_type, payload=payload, now=now)
        db.execute("RELEASE SAVEPOINT floraos_phase20")
    except Exception:
        db.execute("ROLLBACK TO SAVEPOINT floraos_phase20")
        db.execute("RELEASE SAVEPOINT floraos_phase20")
        # Deliberately swallow: browser intelligence may not break E2EE device processing.


def _history_window() -> tuple[int, int, str]:
    now = int(time.time())
    label = request.args.get("range", "24h").strip().lower()
    if label in RANGES:
        return now - RANGES[label], now, label
    try:
        start = int(request.args.get("from", "0"))
        end = int(request.args.get("to", str(now)))
    except ValueError as exc:
        raise ValueError("from/to must be Unix timestamps") from exc
    end = min(end, now)
    if start <= 0 or end <= start or end-start > MAX_HISTORY_SECONDS:
        raise ValueError("Custom history must be positive, ordered, and <= 90 days")
    return start, end, "custom"


def _command_history(db: sqlite3.Connection, user_id: int, device_id: str, limit: int = 30) -> list[dict[str, Any]]:
    rows = db.execute("SELECT * FROM device_commands WHERE user_id=? AND device_id=? ORDER BY id DESC LIMIT ?", (int(user_id), device_id, max(1, min(limit,100)))).fetchall()
    return [command_row_to_dict(row) for row in rows]


def _device_overview(db: sqlite3.Connection, user_id: int, device_id: str, now: int) -> dict[str, Any]:
    own = owned_device(db, user_id, device_id)
    if not own:
        raise LookupError
    online, heartbeat_age = online_status(db, device_id, now)
    payload, telemetry_at = latest_telemetry(db, device_id)
    state = {}
    if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='device_state'").fetchone():
        row = db.execute("SELECT * FROM device_state WHERE device_id=? LIMIT 1", (device_id,)).fetchone()
        if row:
            state = {k: row[k] for k in row.keys()}
    return {
        "device_id": device_id, "nickname": own["nickname"], "claimed_at": own["claimed_at"],
        "online": online, "heartbeat_age_seconds": heartbeat_age,
        "telemetry_received_at": telemetry_at, "telemetry_age_seconds": max(0, now-telemetry_at) if telemetry_at else None,
        "latest_telemetry": payload, "state": state, "runtime": runtime_profile(db, device_id),
        "plant": plant_profile(db, user_id, device_id),
    }


@phase20.after_request
def no_store(response):
    if request.path.startswith(("/api/intelligence", "/api/notifications", "/api/automations/v2")):
        response.headers["Cache-Control"] = "no-store, max-age=0"
        response.headers["Pragma"] = "no-cache"
    return response


@phase20.get("/health/live")
def live():
    return jsonify(ok=True, service="FloraCore", check="live")


@phase20.get("/health/ready")
def ready():
    details = {"database": False, "device_tables": False, "phase20": False}
    try:
        with closing(connect(_db_path())) as db:
            db.execute("SELECT 1").fetchone(); details["database"] = True
            details["device_tables"] = all(db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (x,)).fetchone() for x in ("device_messages","device_telemetry","device_ownership"))
            details["phase20"] = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='floraos_device_runtime'").fetchone() is not None
    except Exception as exc:
        details["error"] = type(exc).__name__
    ok = all(details.get(x) for x in ("database","device_tables","phase20"))
    return jsonify(ok=ok, service="FloraCore", check="ready", details=details), 200 if ok else 503


@phase20.get("/notifications")
def notifications_page():
    if _user_id() is None:
        return redirect("/login")
    return render_template("notifications.html", user_id=_user_id(), user_email=session.get("email", ""), csrf_token=_csrf())


@phase20.get("/devices/<device_id>")
def device_page(device_id: str):
    user_id = _user_id()
    if user_id is None:
        return redirect("/login")
    with closing(connect(_db_path())) as db:
        if not owned_device(db, user_id, device_id):
            return "Not found", 404
    return render_template("device_detail.html", user_id=user_id, user_email=session.get("email", ""), device_id=device_id, csrf_token=_csrf())


@phase20.get("/automations/v2")
def automation_v2_page():
    if _user_id() is None:
        return redirect("/login")
    return render_template("automations_v2.html", user_id=_user_id(), user_email=session.get("email", ""), csrf_token=_csrf())


@phase20.get("/api/intelligence/devices")
def devices_api():
    user_id, error = _require_user()
    if error: return error
    now = int(time.time())
    with closing(connect(_db_path())) as db:
        rows = db.execute("SELECT device_id FROM device_ownership WHERE user_id=? ORDER BY claimed_at DESC", (int(user_id),)).fetchall()
        data = [_device_overview(db, user_id, str(row["device_id"]), now) for row in rows]
    return jsonify(data=data)


@phase20.get("/api/intelligence/devices/<device_id>")
def device_api(device_id: str):
    user_id, error = _require_user()
    if error: return error
    now = int(time.time())
    with closing(connect(_db_path())) as db:
        if not owned_device(db, user_id, device_id): return _error("device_not_found", "Device not found.", 404)
        data = _device_overview(db, user_id, device_id, now)
        data["care_v2"] = care_score_v2(db, user_id, device_id, now)
        data["reservoirs"] = reservoir_summary(db, user_id, device_id, now)
        data["commands"] = _command_history(db, user_id, device_id, 20)
        data["calibrations"] = [{"sensor_key":str(r["sensor_key"]),"type":str(r["calibration_type"]),"config":json_object(r["config_json"]),"updated_at":int(r["updated_at"])} for r in db.execute("SELECT * FROM floraos_device_calibrations WHERE user_id=? AND device_id=? ORDER BY sensor_key", (int(user_id),device_id)).fetchall()]
    return jsonify(data=data)


@phase20.get("/api/intelligence/devices/<device_id>/history")
def history_api(device_id: str):
    user_id, error = _require_user()
    if error: return error
    try: start, end, label = _history_window()
    except ValueError as exc: return _error("invalid_range", str(exc), 400)
    with closing(connect(_db_path())) as db:
        if not owned_device(db, user_id, device_id): return _error("device_not_found", "Device not found.", 404)
        samples = history_samples(db, user_id, device_id, start, end)
        profile = plant_profile(db, user_id, device_id)
        summaries = {key: metric_summary(samples, key, target_for(profile,key)) for key in METRICS}
        events = []
        rows = db.execute("SELECT command_id,command_type,parameters_json,created_at,completed_at,status FROM device_commands WHERE user_id=? AND device_id=? AND created_at BETWEEN ? AND ? ORDER BY created_at ASC LIMIT 500", (int(user_id),device_id,start,end)).fetchall()
        for row in rows:
            events.append({"command_id":str(row["command_id"]),"type":str(row["command_type"]),"parameters":json_object(row["parameters_json"]),"created_at":int(row["created_at"]),"completed_at":row["completed_at"],"status":str(row["status"])})
    return jsonify(data={"device_id":device_id,"range":label,"from":start,"to":end,"raw_sample_count":len(samples),"points":downsample(samples,start,end),"summary":summaries,"events":events,"targets":{key:target_for(profile,key) for key in ("soil","light","temperature","humidity")} if profile else {}})


@phase20.get("/api/intelligence/devices/<device_id>/trends")
def trends_api(device_id: str):
    user_id, error = _require_user()
    if error: return error
    try: start, end, label = _history_window()
    except ValueError as exc: return _error("invalid_range", str(exc), 400)
    with closing(connect(_db_path())) as db:
        if not owned_device(db,user_id,device_id): return _error("device_not_found","Device not found.",404)
        samples = history_samples(db,user_id,device_id,start,end)
        data = trend_analysis(samples, plant_profile(db,user_id,device_id))
    return jsonify(data={"device_id":device_id,"range":label,**data})


@phase20.get("/api/intelligence/devices/<device_id>/care-v2")
def care_api(device_id: str):
    user_id, error = _require_user()
    if error: return error
    with closing(connect(_db_path())) as db:
        if not owned_device(db,user_id,device_id): return _error("device_not_found","Device not found.",404)
        data = care_score_v2(db,user_id,device_id)
    return jsonify(data=data)


@phase20.put("/api/intelligence/devices/<device_id>/plant-details")
def plant_details_api(device_id: str):
    user_id, error = _require_user()
    if error: return error
    csrf = _require_csrf()
    if csrf: return csrf
    body = request.get_json(silent=True)
    if not isinstance(body,dict): return _error("invalid_body","JSON object required.",400)
    scientific = str(body.get("scientific_name","")).strip()[:120] or None
    notes = str(body.get("notes","")).strip()
    if len(notes)>4000: return _error("notes_too_long","Notes limited to 4000 characters.",400)
    avatar = str(body.get("avatar","🌱")).strip()
    if not avatar or len(avatar)>16: avatar="🌱"
    planted = body.get("planted_at")
    try: planted_at = int(planted) if planted not in (None,"") else None
    except (TypeError,ValueError): return _error("invalid_planted_at","planted_at must be Unix time.",400)
    now=int(time.time())
    with closing(connect(_db_path())) as db:
        if not owned_device(db,user_id,device_id): return _error("device_not_found","Device not found.",404)
        db.execute("""INSERT INTO floraos_plant_details(user_id,device_id,scientific_name,planted_at,notes,avatar,updated_at) VALUES(?,?,?,?,?,?,?)
            ON CONFLICT(user_id,device_id) DO UPDATE SET scientific_name=excluded.scientific_name,planted_at=excluded.planted_at,notes=excluded.notes,avatar=excluded.avatar,updated_at=excluded.updated_at""",
            (int(user_id),device_id,scientific,planted_at,notes,avatar,now)); db.commit()
        data=plant_profile(db,user_id,device_id)
    return jsonify(data=data)


@phase20.put("/api/intelligence/devices/<device_id>/calibrations/<sensor_key>")
def calibration_api(device_id: str, sensor_key: str):
    user_id,error=_require_user()
    if error:return error
    csrf=_require_csrf()
    if csrf:return csrf
    body=request.get_json(silent=True)
    if not isinstance(body,dict) or sensor_key not in set(METRICS)|{"fertilizer_pump"}: return _error("invalid_calibration","Unsupported calibration.",400)
    kind=str(body.get("type","")).strip(); cfg=body.get("config")
    if not isinstance(cfg,dict): return _error("invalid_calibration","config must be an object.",400)
    try:
        if sensor_key=="fertilizer_pump":
            if kind!="pump_flow": raise ValueError("fertilizer_pump uses pump_flow")
            mlps=float(cfg["ml_per_second"]); single=float(cfg.get("max_single_ml",20)); daily=float(cfg.get("max_daily_ml",50))
            if not .05<=mlps<=100 or not .5<=single<=50 or not single<=daily<=100: raise ValueError("pump limits outside safe web bounds")
            cfg={"ml_per_second":mlps,"max_single_ml":single,"max_daily_ml":daily}
        elif kind=="two_point_percent":
            zero=float(cfg["raw_zero"]); full=float(cfg["raw_full"])
            if not math.isfinite(zero) or not math.isfinite(full) or zero==full: raise ValueError("raw endpoints must be finite and distinct")
            cfg={"raw_zero":zero,"raw_full":full}
        elif kind=="linear":
            scale=float(cfg.get("scale",1)); offset=float(cfg.get("offset",0))
            if not math.isfinite(scale) or not math.isfinite(offset) or scale==0: raise ValueError("invalid scale/offset")
            cfg={"scale":scale,"offset":offset}
        else: raise ValueError("use two_point_percent, linear, or pump_flow")
    except (KeyError,TypeError,ValueError) as exc: return _error("invalid_calibration",str(exc),400)
    now=int(time.time())
    with closing(connect(_db_path())) as db:
        if not owned_device(db,user_id,device_id):return _error("device_not_found","Device not found.",404)
        db.execute("""INSERT INTO floraos_device_calibrations(user_id,device_id,sensor_key,calibration_type,config_json,updated_at) VALUES(?,?,?,?,?,?)
            ON CONFLICT(user_id,device_id,sensor_key) DO UPDATE SET calibration_type=excluded.calibration_type,config_json=excluded.config_json,updated_at=excluded.updated_at""",
            (int(user_id),device_id,sensor_key,kind,json.dumps(cfg,separators=(",",":"),sort_keys=True),now));db.commit()
    return jsonify(data={"sensor_key":sensor_key,"type":kind,"config":cfg,"updated_at":now})


@phase20.get("/api/intelligence/devices/<device_id>/commands")
def commands_api(device_id:str):
    user_id,error=_require_user()
    if error:return error
    with closing(connect(_db_path())) as db:
        if not owned_device(db,user_id,device_id):return _error("device_not_found","Device not found.",404)
        data=_command_history(db,user_id,device_id,int(request.args.get("limit","30")))
    return jsonify(data=data)


@phase20.post("/api/intelligence/devices/<device_id>/commands")
def manual_command_api(device_id:str):
    user_id,error=_require_user()
    if error:return error
    csrf=_require_csrf()
    if csrf:return csrf
    body=request.get_json(silent=True)
    if not isinstance(body,dict):return _error("invalid_body","JSON object required.",400)
    command_type=str(body.get("type","")).strip().lower(); params_in=body.get("parameters")
    try:
        idem=validate_idempotency_key(body.get("idempotency_key") or request.headers.get("Idempotency-Key")); ttl=validate_ttl(body.get("expires_in_seconds"))
    except CommandValidationError as exc:return _error(exc.code,exc.message,400)
    now=int(time.time())
    with closing(connect(_db_path())) as db:
        db.execute("BEGIN IMMEDIATE")
        if not owned_device(db,user_id,device_id):db.rollback();return _error("device_not_found","Device not found.",404)
        ready,reason=command_readiness(db,device_id=device_id,now=now,heartbeat_max_age_seconds=120)
        if not ready:db.rollback();return _error(reason or "control_unavailable","Device control is unavailable.",409)
        try:
            if command_type in {"water","grow_light"}: validated,params=validate_command(command_type,params_in)
            elif command_type=="fertilize": validated="fertilize";params=fertilizer_parameters(db,user_id=user_id,device_id=device_id,volume_ml=params_in.get("volume_ml") if isinstance(params_in,dict) else None,now=now)
            else:db.rollback();return _error("unsupported_command","Only water, grow_light, and gated fertilize are supported here.",400)
            command,created=enqueue_command_in_transaction(db,user_id=user_id,device_id=device_id,command_type=validated,parameters=params,idempotency_key=idem,expires_in_seconds=ttl,now=now);db.commit()
        except CommandValidationError as exc:db.rollback();return _error(exc.code,exc.message,429 if exc.code=="command_cooldown" else 409)
        except AutomationV2Error as exc:db.rollback();return _error(exc.code,exc.message,409)
    return jsonify(data={"command":command,"created":created})


@phase20.post("/api/intelligence/devices/<device_id>/commands/<command_id>/cancel")
def cancel_api(device_id:str,command_id:str):
    user_id,error=_require_user()
    if error:return error
    csrf=_require_csrf()
    if csrf:return csrf
    with closing(connect(_db_path())) as db:
        db.execute("BEGIN IMMEDIATE")
        if not owned_device(db,user_id,device_id):db.rollback();return _error("device_not_found","Device not found.",404)
        command,reason=cancel_command_in_transaction(db,user_id=user_id,device_id=device_id,command_id=command_id,now=int(time.time()));db.commit()
    if command is None:return _error("command_not_found","Command not found.",404)
    if reason:return _error(reason,"This command can no longer be cancelled.",409)
    return jsonify(data=command)


@phase20.get("/api/intelligence/devices/<device_id>/reservoirs")
def reservoirs_api(device_id:str):
    user_id,error=_require_user()
    if error:return error
    with closing(connect(_db_path())) as db:
        if not owned_device(db,user_id,device_id):return _error("device_not_found","Device not found.",404)
        data=reservoir_summary(db,user_id,device_id)
    return jsonify(data=data)


@phase20.post("/api/intelligence/devices/<device_id>/reservoirs/<reservoir>/refill")
def refill_api(device_id:str,reservoir:str):
    user_id,error=_require_user()
    if error:return error
    csrf=_require_csrf()
    if csrf:return csrf
    if reservoir not in {"water","fertilizer"}:return _error("invalid_reservoir","Reservoir must be water or fertilizer.",400)
    body=request.get_json(silent=True) or {}
    try:
        amount=float(body["amount_ml"]) if body.get("amount_ml") not in (None,"") else None
        level=float(body["level_percent"]) if body.get("level_percent") not in (None,"") else None
    except (TypeError,ValueError):return _error("invalid_refill","Refill values must be numeric.",400)
    if amount is None and level is None:return _error("invalid_refill","Provide amount_ml or level_percent.",400)
    if amount is not None and not 0<amount<=10000:return _error("invalid_refill","amount_ml outside range.",400)
    if level is not None and not 0<=level<=100:return _error("invalid_refill","level_percent must be 0–100.",400)
    now=int(time.time());refill="refill_"+secrets.token_urlsafe(12)
    with closing(connect(_db_path())) as db:
        if not owned_device(db,user_id,device_id):return _error("device_not_found","Device not found.",404)
        db.execute("INSERT INTO floraos_reservoir_refills(refill_id,user_id,device_id,reservoir,amount_ml,level_percent,notes,created_at) VALUES(?,?,?,?,?,?,?,?)",(refill,int(user_id),device_id,reservoir,amount,level,str(body.get("notes","")).strip()[:500] or None,now));db.commit()
    return jsonify(data={"refill_id":refill,"created_at":now})


@phase20.get("/api/intelligence/devices/<device_id>/recommendations")
def recs_api(device_id:str):
    user_id,error=_require_user()
    if error:return error
    with closing(connect(_db_path())) as db:
        if not owned_device(db,user_id,device_id):return _error("device_not_found","Device not found.",404)
        data=recommendation_graphs(plant_profile(db,user_id,device_id))
    return jsonify(data=data)


@phase20.post("/api/intelligence/devices/<device_id>/recommendations/<slug>/install")
def rec_install_api(device_id:str,slug:str):
    user_id,error=_require_user()
    if error:return error
    csrf=_require_csrf()
    if csrf:return csrf
    body=request.get_json(silent=True) or {};tz=str(body.get("timezone","UTC"))
    try:timezone_or_error(tz)
    except AutomationV2Error as exc:return _error(exc.code,exc.message,400)
    now=int(time.time())
    with closing(connect(_db_path())) as db:
        if not owned_device(db,user_id,device_id):return _error("device_not_found","Device not found.",404)
        item=next((x for x in recommendation_graphs(plant_profile(db,user_id,device_id)) if x["slug"]==slug),None)
        if not item:return _error("recommendation_not_found","Recommendation not found.",404)
        graph=validate_automation_v2_graph(item["graph"]);aid="aut2_"+secrets.token_urlsafe(14)
        db.execute("INSERT INTO floraos_automations_v2(automation_id,user_id,device_id,name,enabled,graph_json,timezone,created_at,updated_at) VALUES(?,?,?,?,0,?,?,?,?)",(aid,int(user_id),device_id,item["name"],json.dumps(graph,separators=(",",":"),sort_keys=True),tz,now,now));db.commit()
    return jsonify(data={"automation_id":aid,"enabled":False,"message":"Added in disabled review mode."})


@phase20.get("/api/notifications")
def notifications_api():
    user_id,error=_require_user()
    if error:return error
    sweep_offline(_db_path())
    try:limit=max(1,min(int(request.args.get("limit","50")),100))
    except ValueError:return _error("invalid_limit","limit must be integer.",400)
    unread_only=request.args.get("unread","0") in {"1","true","yes"}
    with closing(connect(_db_path())) as db:
        where="WHERE user_id=?"+(" AND read_at IS NULL" if unread_only else "")
        rows=db.execute(f"SELECT * FROM floraos_notifications {where} ORDER BY created_at DESC,id DESC LIMIT ?",(int(user_id),limit)).fetchall()
        unread=int(db.execute("SELECT COUNT(*) AS n FROM floraos_notifications WHERE user_id=? AND read_at IS NULL",(int(user_id),)).fetchone()["n"])
    data=[{"notification_id":str(r["notification_id"]),"device_id":r["device_id"],"category":str(r["category"]),"severity":str(r["severity"]),"title":str(r["title"]),"message":str(r["message"]),"created_at":int(r["created_at"]),"read_at":r["read_at"],"email_state":str(r["email_state"])} for r in rows]
    return jsonify(data=data,meta={"unread":unread})


@phase20.post("/api/notifications/<notification_id>/read")
def note_read_api(notification_id:str):
    user_id,error=_require_user()
    if error:return error
    csrf=_require_csrf()
    if csrf:return csrf
    now=int(time.time())
    with closing(connect(_db_path())) as db:
        cur=db.execute("UPDATE floraos_notifications SET read_at=COALESCE(read_at,?) WHERE user_id=? AND notification_id=?",(now,int(user_id),notification_id));db.commit()
    if not cur.rowcount:return _error("notification_not_found","Notification not found.",404)
    return jsonify(data={"read_at":now})


@phase20.post("/api/notifications/read-all")
def read_all_api():
    user_id,error=_require_user()
    if error:return error
    csrf=_require_csrf()
    if csrf:return csrf
    now=int(time.time())
    with closing(connect(_db_path())) as db:
        cur=db.execute("UPDATE floraos_notifications SET read_at=? WHERE user_id=? AND read_at IS NULL",(now,int(user_id)));db.commit()
    return jsonify(data={"updated":int(cur.rowcount or 0)})


@phase20.get("/api/notifications/preferences")
def prefs_api():
    user_id,error=_require_user()
    if error:return error
    with closing(connect(_db_path())) as db:data={c:preference(db,user_id,c) for c in sorted(CATEGORIES)}
    return jsonify(data=data)


@phase20.put("/api/notifications/preferences/<category>")
def pref_update_api(category:str):
    user_id,error=_require_user()
    if error:return error
    csrf=_require_csrf()
    if csrf:return csrf
    if category not in CATEGORIES:return _error("invalid_category","Unknown category.",400)
    body=request.get_json(silent=True)
    if not isinstance(body,dict):return _error("invalid_body","JSON object required.",400)
    try:cooldown=max(60,min(int(body.get("cooldown_seconds",DEFAULTS[category][2])),7*86400))
    except (TypeError,ValueError):return _error("invalid_cooldown","Invalid cooldown.",400)
    severity=str(body.get("min_severity",DEFAULTS[category][3])).lower()
    if severity not in SEVERITY_RANK:return _error("invalid_severity","Invalid severity.",400)
    qs=str(body.get("quiet_start","")).strip() or None;qe=str(body.get("quiet_end","")).strip() or None
    for v in (qs,qe):
        if v is not None and (len(v)!=5 or v[2] != ":"):return _error("invalid_quiet_hours","Use HH:MM.",400)
    timezone_name=str(body.get("timezone","Asia/Kuala_Lumpur")).strip() or "Asia/Kuala_Lumpur"
    try: timezone_or_error(timezone_name)
    except AutomationV2Error as exc: return _error(exc.code,exc.message,400)
    now=int(time.time())
    with closing(connect(_db_path())) as db:
        db.execute("""INSERT INTO floraos_notification_preferences(user_id,category,web_enabled,email_enabled,cooldown_seconds,min_severity,quiet_start,quiet_end,timezone,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(user_id,category) DO UPDATE SET web_enabled=excluded.web_enabled,email_enabled=excluded.email_enabled,cooldown_seconds=excluded.cooldown_seconds,min_severity=excluded.min_severity,quiet_start=excluded.quiet_start,quiet_end=excluded.quiet_end,timezone=excluded.timezone,updated_at=excluded.updated_at""",
            (int(user_id),category,1 if body.get("web_enabled",True) else 0,1 if body.get("email_enabled",False) else 0,cooldown,severity,qs,qe,timezone_name,now));db.commit();data=preference(db,user_id,category)
    return jsonify(data=data)


def _aut_dict(row:sqlite3.Row,graph:bool=True)->dict[str,Any]:
    data={"automation_id":str(row["automation_id"]),"device_id":str(row["device_id"]),"name":str(row["name"]),"enabled":bool(row["enabled"]),"timezone":str(row["timezone"]),"created_at":int(row["created_at"]),"updated_at":int(row["updated_at"]),"last_evaluated_at":row["last_evaluated_at"],"advanced_acknowledged":row["advanced_acknowledged_at"] is not None}
    if graph:data["graph"]=json_object(row["graph_json"])
    return data


@phase20.get("/api/automations/v2")
def aut_list_api():
    user_id,error=_require_user()
    if error:return error
    with closing(connect(_db_path())) as db:rows=db.execute("SELECT * FROM floraos_automations_v2 WHERE user_id=? ORDER BY updated_at DESC,id DESC",(int(user_id),)).fetchall()
    return jsonify(data=[_aut_dict(r,False) for r in rows])


@phase20.post("/api/automations/v2")
def aut_create_api():
    user_id,error=_require_user()
    if error:return error
    csrf=_require_csrf()
    if csrf:return csrf
    body=request.get_json(silent=True)
    if not isinstance(body,dict):return _error("invalid_body","JSON object required.",400)
    name=str(body.get("name","")).strip();device_id=str(body.get("device_id","")).strip();tz=str(body.get("timezone","UTC"))
    try:timezone_or_error(tz);graph=validate_automation_v2_graph(body.get("graph"))
    except AutomationV2Error as exc:return _error(exc.code,exc.message,400)
    if not name or len(name)>100:return _error("invalid_name","Name must be 1–100 characters.",400)
    now=int(time.time());aid="aut2_"+secrets.token_urlsafe(14)
    with closing(connect(_db_path())) as db:
        if not owned_device(db,user_id,device_id):return _error("device_not_found","Device not found.",404)
        if int(db.execute("SELECT COUNT(*) AS n FROM floraos_automations_v2 WHERE user_id=?",(int(user_id),)).fetchone()["n"])>=32:return _error("automation_limit","Maximum 32 v2 flows.",409)
        db.execute("INSERT INTO floraos_automations_v2(automation_id,user_id,device_id,name,enabled,graph_json,timezone,created_at,updated_at) VALUES(?,?,?,?,0,?,?,?,?)",(aid,int(user_id),device_id,name,json.dumps(graph,separators=(",",":"),sort_keys=True),tz,now,now));db.commit();row=db.execute("SELECT * FROM floraos_automations_v2 WHERE automation_id=?",(aid,)).fetchone()
    return jsonify(data=_aut_dict(row)),201


@phase20.get("/api/automations/v2/<automation_id>")
def aut_get_api(automation_id:str):
    user_id,error=_require_user()
    if error:return error
    with closing(connect(_db_path())) as db:row=db.execute("SELECT * FROM floraos_automations_v2 WHERE user_id=? AND automation_id=? LIMIT 1",(int(user_id),automation_id)).fetchone()
    return jsonify(data=_aut_dict(row)) if row else _error("automation_not_found","Automation not found.",404)


@phase20.put("/api/automations/v2/<automation_id>")
def aut_update_api(automation_id:str):
    user_id,error=_require_user()
    if error:return error
    csrf=_require_csrf()
    if csrf:return csrf
    body=request.get_json(silent=True)
    if not isinstance(body,dict):return _error("invalid_body","JSON object required.",400)
    with closing(connect(_db_path())) as db:
        row=db.execute("SELECT * FROM floraos_automations_v2 WHERE user_id=? AND automation_id=? LIMIT 1",(int(user_id),automation_id)).fetchone()
        if not row:return _error("automation_not_found","Automation not found.",404)
        name=str(body.get("name",row["name"])).strip();device_id=str(body.get("device_id",row["device_id"]));tz=str(body.get("timezone",row["timezone"]))
        try:timezone_or_error(tz);graph=validate_automation_v2_graph(body.get("graph",json_object(row["graph_json"])))
        except AutomationV2Error as exc:return _error(exc.code,exc.message,400)
        if not owned_device(db,user_id,device_id):return _error("device_not_found","Device not found.",404)
        now=int(time.time());db.execute("UPDATE floraos_automations_v2 SET name=?,device_id=?,graph_json=?,timezone=?,enabled=0,advanced_acknowledged_at=NULL,updated_at=? WHERE user_id=? AND automation_id=?",(name,device_id,json.dumps(graph,separators=(",",":"),sort_keys=True),tz,now,int(user_id),automation_id));db.execute("DELETE FROM floraos_automation_v2_pending WHERE user_id=? AND automation_id=?",(int(user_id),automation_id));db.commit();row=db.execute("SELECT * FROM floraos_automations_v2 WHERE user_id=? AND automation_id=?",(int(user_id),automation_id)).fetchone()
    return jsonify(data=_aut_dict(row))


@phase20.post("/api/automations/v2/<automation_id>/enabled")
def aut_enable_api(automation_id:str):
    user_id,error=_require_user()
    if error:return error
    csrf=_require_csrf()
    if csrf:return csrf
    body=request.get_json(silent=True) or {};enabled=bool(body.get("enabled",False));ack=bool(body.get("acknowledge_advanced_control",False))
    with closing(connect(_db_path())) as db:
        row=db.execute("SELECT * FROM floraos_automations_v2 WHERE user_id=? AND automation_id=? LIMIT 1",(int(user_id),automation_id)).fetchone()
        if not row:return _error("automation_not_found","Automation not found.",404)
        if enabled and not (ack or row["advanced_acknowledged_at"] is not None):return _error("advanced_acknowledgement_required","Review and explicitly acknowledge advanced physical control.",409)
        now=int(time.time());db.execute("UPDATE floraos_automations_v2 SET enabled=?,advanced_acknowledged_at=?,updated_at=? WHERE user_id=? AND automation_id=?",(1 if enabled else 0,now if enabled else row["advanced_acknowledged_at"],now,int(user_id),automation_id));
        if not enabled:db.execute("DELETE FROM floraos_automation_v2_pending WHERE user_id=? AND automation_id=?",(int(user_id),automation_id))
        db.commit();row=db.execute("SELECT * FROM floraos_automations_v2 WHERE user_id=? AND automation_id=?",(int(user_id),automation_id)).fetchone()
    return jsonify(data=_aut_dict(row,False))


@phase20.delete("/api/automations/v2/<automation_id>")
def aut_delete_api(automation_id:str):
    user_id,error=_require_user()
    if error:return error
    csrf=_require_csrf()
    if csrf:return csrf
    with closing(connect(_db_path())) as db:
        if not db.execute("SELECT 1 FROM floraos_automations_v2 WHERE user_id=? AND automation_id=?",(int(user_id),automation_id)).fetchone():return _error("automation_not_found","Automation not found.",404)
        for table in ("floraos_automation_v2_pending","floraos_automation_v2_runs","floraos_automations_v2"):db.execute(f"DELETE FROM {table} WHERE user_id=? AND automation_id=?",(int(user_id),automation_id))
        db.commit()
    return jsonify(data={"deleted":True})


@phase20.get("/api/automations/v2/<automation_id>/runs")
def aut_runs_api(automation_id:str):
    user_id,error=_require_user()
    if error:return error
    with closing(connect(_db_path())) as db:
        if not db.execute("SELECT 1 FROM floraos_automations_v2 WHERE user_id=? AND automation_id=?",(int(user_id),automation_id)).fetchone():return _error("automation_not_found","Automation not found.",404)
        rows=db.execute("""SELECT r.*,c.status AS command_status,c.acknowledged_at,c.completed_at AS command_completed_at,c.result_json AS command_result,c.error AS command_error FROM floraos_automation_v2_runs r LEFT JOIN device_commands c ON c.command_id=r.command_id WHERE r.user_id=? AND r.automation_id=? ORDER BY r.id DESC LIMIT 100""",(int(user_id),automation_id)).fetchall()
    return jsonify(data=[{"run_id":str(r["run_id"]),"device_id":str(r["device_id"]),"command_id":r["command_id"],"status":str(r["command_status"] or r["status"]),"started_at":int(r["started_at"]),"completed_at":r["command_completed_at"] or r["completed_at"],"acknowledged_at":r["acknowledged_at"],"trigger":json_object(r["trigger_json"]),"result":json_object(r["command_result"] or r["result_json"]),"error":r["command_error"] or r["error"]} for r in rows])


@phase20.get("/api/automations/v2/templates")
def templates_api():
    user_id,error=_require_user()
    if error:return error
    device_id=request.args.get("device_id","").strip();data=[]
    with closing(connect(_db_path())) as db:
        if device_id:
            if not owned_device(db,user_id,device_id):return _error("device_not_found","Device not found.",404)
            data.extend(recommendation_graphs(plant_profile(db,user_id,device_id)))
    data.append({"slug":"notify-telemetry","name":"Telemetry received","summary":"Notification-only starter flow; it never controls hardware.","graph":{"version":2,"nodes":[{"id":"t","type":"trigger_telemetry","config":{}},{"id":"n","type":"action_notify","config":{"severity":"info","title":"FloraCore telemetry","message":"Authenticated telemetry was received."}}],"edges":[{"from":"t","to":"n","when":"always"}]}})
    return jsonify(data=data)


@phase20.get("/api/automations/v2/execution")
def execution_api():
    user_id,error=_require_user()
    if error:return error
    with closing(connect(_db_path())) as db:
        runs=db.execute("""SELECT r.*,a.name,c.status AS command_status,c.acknowledged_at,c.completed_at AS command_completed_at,c.error AS command_error FROM floraos_automation_v2_runs r LEFT JOIN floraos_automations_v2 a ON a.automation_id=r.automation_id LEFT JOIN device_commands c ON c.command_id=r.command_id WHERE r.user_id=? ORDER BY r.id DESC LIMIT 100""",(int(user_id),)).fetchall()
        pending=db.execute("""SELECT p.*,a.name FROM floraos_automation_v2_pending p LEFT JOIN floraos_automations_v2 a ON a.automation_id=p.automation_id WHERE p.user_id=? ORDER BY p.due_at ASC LIMIT 100""",(int(user_id),)).fetchall()
    return jsonify(data={"runs":[{"run_id":str(r["run_id"]),"automation_id":str(r["automation_id"]),"automation_name":r["name"],"device_id":str(r["device_id"]),"command_id":r["command_id"],"status":str(r["command_status"] or r["status"]),"started_at":int(r["started_at"]),"completed_at":r["command_completed_at"] or r["completed_at"],"acknowledged_at":r["acknowledged_at"],"error":r["command_error"] or r["error"]} for r in runs],"pending":[{"pending_id":str(p["pending_id"]),"automation_id":str(p["automation_id"]),"automation_name":p["name"],"device_id":str(p["device_id"]),"node_id":str(p["node_id"]),"due_at":int(p["due_at"]),"attempts":int(p["attempts"]),"last_error":p["last_error"]} for p in pending]})


__all__=["dispatch_pending_emails","fertilizer_parameters","init_phase20","process_phase20_message_in_transaction","sweep_offline"]
