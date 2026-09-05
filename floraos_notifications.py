from __future__ import annotations

from contextlib import closing
from email.message import EmailMessage
from email.utils import formataddr
from datetime import datetime
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
from pathlib import Path
from typing import Any
import os
import smtplib
import sqlite3
import ssl
import time
import secrets

from floraos_insights import (
    METRICS,
    ONLINE_SECONDS,
    calibrated_metric,
    connect,
    latest_telemetry,
    online_status,
    owner_for_device,
    plant_profile,
)

SEVERITY_RANK = {"info": 0, "success": 1, "warning": 2, "critical": 3}
CATEGORIES = {
    "plant_warning", "device_offline", "device_online", "reservoir",
    "automation", "command", "firmware", "care_trend",
}
DEFAULTS = {
    "plant_warning": (1, 1, 1800, "warning"),
    "device_offline": (1, 1, 1800, "warning"),
    "device_online": (1, 0, 1800, "info"),
    "reservoir": (1, 1, 3600, "warning"),
    "automation": (1, 0, 300, "info"),
    "command": (1, 0, 300, "info"),
    "firmware": (1, 0, 3600, "info"),
    "care_trend": (1, 1, 21600, "warning"),
}


def init_notification_schema(db_path: str | Path) -> None:
    with closing(connect(db_path)) as db:
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS floraos_notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                notification_id TEXT UNIQUE NOT NULL,
                user_id INTEGER NOT NULL,
                device_id TEXT,
                category TEXT NOT NULL,
                severity TEXT NOT NULL,
                title TEXT NOT NULL,
                message TEXT NOT NULL,
                dedup_key TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                read_at INTEGER,
                email_state TEXT NOT NULL DEFAULT 'none',
                email_attempts INTEGER NOT NULL DEFAULT 0,
                email_last_error TEXT,
                email_sent_at INTEGER,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_floraos_notifications_inbox
                ON floraos_notifications(user_id, read_at, created_at DESC, id DESC);

            CREATE TABLE IF NOT EXISTS floraos_notification_preferences (
                user_id INTEGER NOT NULL,
                category TEXT NOT NULL,
                web_enabled INTEGER NOT NULL DEFAULT 1,
                email_enabled INTEGER NOT NULL DEFAULT 0,
                cooldown_seconds INTEGER NOT NULL DEFAULT 1800,
                min_severity TEXT NOT NULL DEFAULT 'info',
                quiet_start TEXT,
                quiet_end TEXT,
                timezone TEXT NOT NULL DEFAULT 'Asia/Kuala_Lumpur',
                updated_at INTEGER NOT NULL,
                PRIMARY KEY(user_id, category),
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS floraos_notification_dedup (
                user_id INTEGER NOT NULL,
                dedup_key TEXT NOT NULL,
                last_created_at INTEGER NOT NULL,
                PRIMARY KEY(user_id, dedup_key),
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            """
        )
        db.commit()


def preference(db: sqlite3.Connection, user_id: int, category: str) -> dict[str, Any]:
    default = DEFAULTS.get(category, (1, 0, 1800, "info"))
    row = db.execute(
        "SELECT * FROM floraos_notification_preferences WHERE user_id=? AND category=? LIMIT 1",
        (int(user_id), category),
    ).fetchone()
    if not row:
        return {
            "web_enabled": bool(default[0]), "email_enabled": bool(default[1]),
            "cooldown_seconds": int(default[2]), "min_severity": str(default[3]),
            "quiet_start": None, "quiet_end": None, "timezone": "Asia/Kuala_Lumpur",
        }
    return {
        "web_enabled": bool(row["web_enabled"]), "email_enabled": bool(row["email_enabled"]),
        "cooldown_seconds": int(row["cooldown_seconds"]), "min_severity": str(row["min_severity"]),
        "quiet_start": row["quiet_start"], "quiet_end": row["quiet_end"], "timezone": row["timezone"] if "timezone" in row.keys() else "Asia/Kuala_Lumpur",
    }


def create_notification_in_transaction(
    db: sqlite3.Connection, *, user_id: int, device_id: str | None,
    category: str, severity: str, title: str, message: str,
    dedup_key: str, now: int,
) -> str | None:
    if category not in CATEGORIES:
        category = "plant_warning"
    if severity not in SEVERITY_RANK:
        severity = "info"
    pref = preference(db, user_id, category)
    if SEVERITY_RANK[severity] < SEVERITY_RANK.get(pref["min_severity"], 0):
        return None
    if not pref["web_enabled"] and not pref["email_enabled"]:
        return None

    row = db.execute(
        "SELECT last_created_at FROM floraos_notification_dedup WHERE user_id=? AND dedup_key=? LIMIT 1",
        (int(user_id), dedup_key),
    ).fetchone()
    if row and int(now) - int(row["last_created_at"]) < int(pref["cooldown_seconds"]):
        return None

    notification_id = "note_" + secrets.token_urlsafe(14)
    db.execute(
        """
        INSERT INTO floraos_notifications(notification_id,user_id,device_id,category,severity,title,message,dedup_key,created_at,email_state)
        VALUES(?,?,?,?,?,?,?,?,?,?)
        """,
        (
            notification_id, int(user_id), device_id, category, severity,
            title[:160], message[:1200], dedup_key[:220], int(now),
            "pending" if pref["email_enabled"] else "none",
        ),
    )
    db.execute(
        """
        INSERT INTO floraos_notification_dedup(user_id,dedup_key,last_created_at)
        VALUES(?,?,?)
        ON CONFLICT(user_id,dedup_key) DO UPDATE SET last_created_at=excluded.last_created_at
        """,
        (int(user_id), dedup_key[:220], int(now)),
    )
    return notification_id


def _last_heartbeat(db: sqlite3.Connection, device_id: str, offset: int = 0) -> int | None:
    rows = db.execute(
        "SELECT received_at FROM device_messages WHERE device_id=? AND message_type='heartbeat' ORDER BY received_at DESC LIMIT 1 OFFSET ?",
        (device_id, int(offset)),
    ).fetchall()
    return int(rows[0]["received_at"]) if rows else None


def process_notification_message_in_transaction(
    db: sqlite3.Connection, *, device_id: str, message_type: str,
    payload: dict[str, Any], now: int,
) -> None:
    user_id = owner_for_device(db, device_id)
    if user_id is None:
        return
    own = db.execute("SELECT nickname FROM device_ownership WHERE device_id=? LIMIT 1", (device_id,)).fetchone()
    name = str(own["nickname"] or device_id) if own else device_id

    if message_type == "heartbeat":
        previous = _last_heartbeat(db, device_id, 1)
        if previous is not None and now - previous > ONLINE_SECONDS:
            create_notification_in_transaction(
                db, user_id=user_id, device_id=device_id, category="device_online",
                severity="success", title=f"{name} is back online",
                message=f"Authenticated heartbeats resumed after a {now-previous}-second gap.",
                dedup_key=f"online:{device_id}", now=now,
            )

    if message_type == "telemetry":
        profile = plant_profile(db, user_id, device_id)
        if profile:
            for metric, low_key, high_key in (
                ("soil", "soil_min", "soil_max"), ("light", "light_min", "light_max"),
                ("temperature", "temperature_min", "temperature_max"), ("humidity", "humidity_min", "humidity_max"),
            ):
                value = calibrated_metric(db, user_id, device_id, metric, payload)
                if value is None:
                    continue
                low, high = float(profile[low_key]), float(profile[high_key])
                if value < low:
                    create_notification_in_transaction(
                        db, user_id=user_id, device_id=device_id, category="plant_warning", severity="warning",
                        title=f"{METRICS[metric]['label']} is below target",
                        message=f"{profile['plant_name']} is at {value:.1f}{METRICS[metric]['unit']}; configured minimum is {low:g}{METRICS[metric]['unit']}.",
                        dedup_key=f"metric-low:{device_id}:{metric}", now=now,
                    )
                elif value > high:
                    create_notification_in_transaction(
                        db, user_id=user_id, device_id=device_id, category="plant_warning", severity="warning",
                        title=f"{METRICS[metric]['label']} is above target",
                        message=f"{profile['plant_name']} is at {value:.1f}{METRICS[metric]['unit']}; configured maximum is {high:g}{METRICS[metric]['unit']}.",
                        dedup_key=f"metric-high:{device_id}:{metric}", now=now,
                    )
            for metric, threshold in (("water", profile["water_low"]), ("fertilizer", profile["fertilizer_low"])):
                value = calibrated_metric(db, user_id, device_id, metric, payload)
                if value is not None and value < float(threshold):
                    create_notification_in_transaction(
                        db, user_id=user_id, device_id=device_id, category="reservoir", severity="warning",
                        title=f"{METRICS[metric]['label']} is low",
                        message=f"{name} reports {value:.1f}% remaining; warning threshold is {float(threshold):g}%.",
                        dedup_key=f"reservoir:{device_id}:{metric}", now=now,
                    )

    if message_type == "command_result" and db.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='device_commands'"
    ).fetchone():
        command_id = payload.get("command_id", payload.get("id"))
        if isinstance(command_id, str):
            row = db.execute(
                "SELECT command_type,status,error FROM device_commands WHERE command_id=? AND device_id=? LIMIT 1",
                (command_id, device_id),
            ).fetchone()
            if row and str(row["status"]) in {"completed", "failed"}:
                status = str(row["status"])
                create_notification_in_transaction(
                    db, user_id=user_id, device_id=device_id, category="command",
                    severity="success" if status == "completed" else "warning",
                    title=f"{str(row['command_type']).replace('_',' ').title()} {status}",
                    message=f"Command {command_id} {status} on {name}." + (f" Error: {row['error']}" if row["error"] else ""),
                    dedup_key=f"command:{command_id}:{status}", now=now,
                )

    if message_type == "ota_status":
        status = str(payload.get("status", "")).strip().lower()
        if status:
            severity = "warning" if status in {"failed", "rollback"} else "success" if status in {"confirmed", "completed"} else "info"
            create_notification_in_transaction(
                db, user_id=user_id, device_id=device_id, category="firmware", severity=severity,
                title=f"Firmware update: {status}", message=f"{name} reported OTA status {status}.",
                dedup_key=f"ota:{device_id}:{status}", now=now,
            )


def sweep_offline(db_path: str | Path, now: int | None = None) -> int:
    current = int(time.time()) if now is None else int(now)
    created = 0
    with closing(connect(db_path)) as db:
        rows = db.execute(
            """
            SELECT o.user_id,o.device_id,o.nickname,MAX(m.received_at) AS last_heartbeat
            FROM device_ownership o
            LEFT JOIN device_messages m ON m.device_id=o.device_id AND m.message_type='heartbeat'
            GROUP BY o.user_id,o.device_id,o.nickname
            """
        ).fetchall()
        for row in rows:
            last = row["last_heartbeat"]
            if last is not None and current - int(last) <= ONLINE_SECONDS:
                continue
            name = str(row["nickname"] or row["device_id"])
            detail = "No authenticated heartbeat has ever been recorded." if last is None else f"The last authenticated heartbeat was {current-int(last)} seconds ago."
            note = create_notification_in_transaction(
                db, user_id=int(row["user_id"]), device_id=str(row["device_id"]),
                category="device_offline", severity="critical", title=f"{name} is offline",
                message=detail, dedup_key=f"offline:{row['device_id']}", now=current,
            )
            if note:
                created += 1
        db.commit()
    return created


def in_quiet_hours(pref: dict[str, Any], now: int | None = None) -> bool:
    start = pref.get("quiet_start")
    end = pref.get("quiet_end")
    if not start or not end:
        return False
    try:
        zone = ZoneInfo(str(pref.get("timezone") or "Asia/Kuala_Lumpur"))
    except ZoneInfoNotFoundError:
        zone = ZoneInfo("UTC")
    local = datetime.fromtimestamp(int(time.time()) if now is None else int(now), tz=zone)
    current = local.strftime("%H:%M")
    return start <= current < end if start < end else current >= start or current < end


def _smtp_send(to_email: str, subject: str, body: str) -> None:
    host = os.environ.get("SMTP_HOST", "").strip()
    sender = os.environ.get("SMTP_FROM_EMAIL", "").strip()
    if not host or not sender:
        raise RuntimeError("SMTP is not configured")
    username = os.environ.get("SMTP_USERNAME", "").strip()
    password = os.environ.get("SMTP_PASSWORD", "")
    sender_name = os.environ.get("SMTP_FROM_NAME", "FloraCore").strip() or "FloraCore"
    port = int(os.environ.get("SMTP_PORT", "587"))
    timeout = float(os.environ.get("SMTP_TIMEOUT", "12"))
    use_ssl = os.environ.get("SMTP_USE_SSL", "0").lower() in {"1","true","yes","on"}
    use_tls = os.environ.get("SMTP_USE_TLS", "1" if not use_ssl else "0").lower() in {"1","true","yes","on"}
    if use_ssl and use_tls:
        raise RuntimeError("SMTP_USE_SSL and SMTP_USE_TLS cannot both be enabled")
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = formataddr((sender_name, sender))
    msg["To"] = to_email
    msg["Auto-Submitted"] = "auto-generated"
    msg.set_content(body)
    context = ssl.create_default_context()
    if use_ssl:
        with smtplib.SMTP_SSL(host, port, timeout=timeout, context=context) as smtp:
            if username:
                smtp.login(username, password)
            smtp.send_message(msg)
    else:
        with smtplib.SMTP(host, port, timeout=timeout) as smtp:
            smtp.ehlo()
            if use_tls:
                smtp.starttls(context=context)
                smtp.ehlo()
            if username:
                smtp.login(username, password)
            smtp.send_message(msg)


def dispatch_pending_emails(db_path: str | Path, limit: int = 25) -> dict[str, int]:
    sent = failed = 0
    now = int(time.time())
    with closing(connect(db_path)) as db:
        rows = db.execute(
            """
            SELECT n.*,u.email FROM floraos_notifications n JOIN users u ON u.id=n.user_id
            WHERE n.email_state='pending' ORDER BY n.id ASC LIMIT ?
            """,
            (max(1, min(int(limit), 100)),),
        ).fetchall()
        for row in rows:
            pref = preference(db, int(row["user_id"]), str(row["category"]))
            if in_quiet_hours(pref, now):
                continue
            try:
                _smtp_send(
                    str(row["email"]), f"FloraCore: {row['title']}",
                    f"{row['title']}\n\n{row['message']}\n\nOpen FloraCore to review the latest state.",
                )
                db.execute("UPDATE floraos_notifications SET email_state='sent',email_sent_at=?,email_last_error=NULL WHERE id=?", (now, int(row["id"])))
                sent += 1
            except Exception as exc:
                attempts = int(row["email_attempts"] or 0) + 1
                db.execute(
                    "UPDATE floraos_notifications SET email_state=?,email_attempts=?,email_last_error=? WHERE id=?",
                    ("failed" if attempts >= 5 else "pending", attempts, f"{type(exc).__name__}: {exc}"[:500], int(row["id"])),
                )
                failed += 1
        db.commit()
    return {"sent": sent, "failed": failed}
