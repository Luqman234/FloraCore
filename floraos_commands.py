from __future__ import annotations

from contextlib import closing
from pathlib import Path
from typing import Any
import json
import secrets
import sqlite3
import time


COMMAND_PROTOCOL_VERSION = 1
COMMAND_ID_PREFIX = "cmd_"
COMMAND_ID_BYTES = 18
COMMAND_DEFAULT_TTL_SECONDS = 90
COMMAND_MIN_TTL_SECONDS = 10
COMMAND_MAX_TTL_SECONDS = 120
COMMAND_MAX_PENDING_PER_DEVICE = 8
COMMAND_RETRY_AFTER_SECONDS = 5
MAX_COMMANDS_PER_RESPONSE = 1

WATER_MIN_DURATION_MS = 500
WATER_MAX_DURATION_MS = 30_000
WATER_COMMAND_COOLDOWN_SECONDS = 60
GROW_LIGHT_MIN_DURATION_SECONDS = 60
GROW_LIGHT_MAX_DURATION_SECONDS = 43_200

COMMAND_TYPES = frozenset({"water", "grow_light"})
COMMAND_ACTIVE_STATUSES = frozenset({"queued", "delivered", "acknowledged"})
COMMAND_TERMINAL_STATUSES = frozenset({"completed", "failed", "expired", "cancelled"})
COMMAND_RESULT_STATUSES = frozenset({"acknowledged", "completed", "failed"})

BLOCKED_SETUP_STATES = {
    "SETUP_IDLE",
    "SETUP_CONNECTING",
    "SETUP_WIFI_CONNECTED",
    "SETUP_CLAIMING",
}


class CommandValidationError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def _connect_path(path: str | Path) -> sqlite3.Connection:
    db = sqlite3.connect(Path(path), timeout=5)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    db.execute("PRAGMA busy_timeout = 5000")
    return db


def _table_exists(db: sqlite3.Connection, name: str) -> bool:
    return db.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name = ? LIMIT 1",
        (name,),
    ).fetchone() is not None


def _table_columns(db: sqlite3.Connection, table: str) -> set[str]:
    return {
        str(row["name"])
        for row in db.execute(f"PRAGMA table_info({table})").fetchall()
    }


def init_command_schema(db_path: str | Path) -> None:
    """Add the v1 command queue without replacing any existing device tables."""
    with closing(_connect_path(db_path)) as db:
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS device_state (
                device_id TEXT PRIMARY KEY,
                last_seen INTEGER NOT NULL,
                last_message_type TEXT NOT NULL,
                last_message_id TEXT NOT NULL
            )
            """
        )

        columns = _table_columns(db, "device_state")
        if "command_protocol" not in columns:
            db.execute("ALTER TABLE device_state ADD COLUMN command_protocol INTEGER")
        if "command_protocol_reported_at" not in columns:
            db.execute(
                "ALTER TABLE device_state ADD COLUMN command_protocol_reported_at INTEGER"
            )

        db.execute(
            """
            CREATE TABLE IF NOT EXISTS device_commands (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                command_id TEXT UNIQUE NOT NULL,
                device_id TEXT NOT NULL,
                user_id INTEGER NOT NULL,
                idempotency_key TEXT NOT NULL,
                command_type TEXT NOT NULL,
                parameters_json TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                delivered_at INTEGER,
                last_delivered_at INTEGER,
                delivery_count INTEGER NOT NULL DEFAULT 0,
                acknowledged_at INTEGER,
                completed_at INTEGER,
                status TEXT NOT NULL,
                result_json TEXT,
                error TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                UNIQUE(user_id, device_id, idempotency_key)
            )
            """
        )
        db.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_device_commands_delivery
            ON device_commands(device_id, status, expires_at, created_at)
            """
        )
        db.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_device_commands_owner
            ON device_commands(user_id, device_id, id DESC)
            """
        )
        db.commit()


def _clean_protocol(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        protocol = int(value)
    except (TypeError, ValueError):
        return None
    if not 0 <= protocol <= 100:
        return None
    return protocol


def update_command_capability_in_transaction(
    db: sqlite3.Connection,
    *,
    device_id: str,
    message_type: str,
    payload: dict[str, Any],
    now: int,
) -> None:
    """Persist command protocol only when reported by an authenticated device."""
    if message_type == "claim" or not isinstance(payload, dict):
        return

    protocol = _clean_protocol(payload.get("command_protocol"))
    if protocol is None:
        capabilities = payload.get("capabilities")
        if isinstance(capabilities, dict):
            protocol = _clean_protocol(
                capabilities.get("command_protocol", capabilities.get("commands"))
            )

    if protocol is None:
        # Command support is fail-closed. A normal authenticated heartbeat that
        # does not advertise command protocol v1 clears any stale capability
        # left by an older/newer firmware image. Other message types do not.
        if message_type != "heartbeat":
            return
        protocol = 0

    db.execute(
        """
        UPDATE device_state
        SET command_protocol = ?, command_protocol_reported_at = ?
        WHERE device_id = ?
        """,
        (protocol, int(now), device_id),
    )


def command_protocol_for_device(
    db: sqlite3.Connection,
    device_id: str,
) -> int | None:
    row = db.execute(
        "SELECT command_protocol FROM device_state WHERE device_id = ?",
        (device_id,),
    ).fetchone()
    if row is None:
        return None
    return _clean_protocol(row["command_protocol"])


def _setup_blocks_commands(payload: dict[str, Any]) -> bool:
    if not isinstance(payload, dict):
        return False
    for key in ("setup_state", "state", "mode"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip().upper() in BLOCKED_SETUP_STATES:
            return True
    return False


def _device_is_owned(db: sqlite3.Connection, device_id: str) -> bool:
    return db.execute(
        "SELECT 1 FROM device_ownership WHERE device_id = ? LIMIT 1",
        (device_id,),
    ).fetchone() is not None


def _ota_in_progress(db: sqlite3.Connection, device_id: str) -> bool:
    if not _table_exists(db, "device_ota_history"):
        return False
    row = db.execute(
        """
        SELECT status
        FROM device_ota_history
        WHERE device_id = ?
        ORDER BY updated_at DESC, id DESC
        LIMIT 1
        """,
        (device_id,),
    ).fetchone()
    if row is None:
        return False
    return str(row["status"]) in {"downloading", "installed"}


def validate_command(
    command_type: Any,
    parameters: Any,
) -> tuple[str, dict[str, Any]]:
    if not isinstance(command_type, str):
        raise CommandValidationError(
            "invalid_command",
            "Command type must be a string.",
        )

    command_type = command_type.strip().lower()
    if command_type not in COMMAND_TYPES:
        raise CommandValidationError(
            "unsupported_command",
            "This command type is not supported by FloraOS API v1.2.",
        )

    if not isinstance(parameters, dict):
        raise CommandValidationError(
            "invalid_parameters",
            "parameters must be a JSON object.",
        )

    if command_type == "water":
        if set(parameters) != {"duration_ms"}:
            raise CommandValidationError(
                "invalid_parameters",
                "water requires only duration_ms.",
            )
        duration = parameters.get("duration_ms")
        if isinstance(duration, bool) or not isinstance(duration, int):
            raise CommandValidationError(
                "invalid_parameters",
                "duration_ms must be an integer.",
            )
        if not WATER_MIN_DURATION_MS <= duration <= WATER_MAX_DURATION_MS:
            raise CommandValidationError(
                "unsafe_command",
                f"duration_ms must be between {WATER_MIN_DURATION_MS} and "
                f"{WATER_MAX_DURATION_MS}.",
            )
        return command_type, {"duration_ms": duration}

    # grow_light
    allowed = {"state", "duration_seconds"}
    if set(parameters) - allowed:
        raise CommandValidationError(
            "invalid_parameters",
            "grow_light accepts only state and duration_seconds.",
        )

    state = parameters.get("state")
    if state not in {"on", "off"}:
        raise CommandValidationError(
            "invalid_parameters",
            "grow_light state must be 'on' or 'off'.",
        )

    if state == "off":
        if "duration_seconds" in parameters:
            raise CommandValidationError(
                "invalid_parameters",
                "duration_seconds is not used when grow_light state is off.",
            )
        return command_type, {"state": "off"}

    duration = parameters.get("duration_seconds")
    if isinstance(duration, bool) or not isinstance(duration, int):
        raise CommandValidationError(
            "invalid_parameters",
            "duration_seconds is required when grow_light state is on.",
        )
    if not GROW_LIGHT_MIN_DURATION_SECONDS <= duration <= GROW_LIGHT_MAX_DURATION_SECONDS:
        raise CommandValidationError(
            "unsafe_command",
            f"duration_seconds must be between {GROW_LIGHT_MIN_DURATION_SECONDS} "
            f"and {GROW_LIGHT_MAX_DURATION_SECONDS}.",
        )

    return command_type, {"state": "on", "duration_seconds": duration}


def validate_ttl(value: Any) -> int:
    if value is None:
        return COMMAND_DEFAULT_TTL_SECONDS
    if isinstance(value, bool):
        raise CommandValidationError("invalid_expiration", "Command expiration is invalid.")
    try:
        ttl = int(value)
    except (TypeError, ValueError) as exc:
        raise CommandValidationError(
            "invalid_expiration",
            "expires_in_seconds must be an integer.",
        ) from exc
    if not COMMAND_MIN_TTL_SECONDS <= ttl <= COMMAND_MAX_TTL_SECONDS:
        raise CommandValidationError(
            "invalid_expiration",
            f"expires_in_seconds must be between {COMMAND_MIN_TTL_SECONDS} and "
            f"{COMMAND_MAX_TTL_SECONDS}.",
        )
    return ttl


def validate_idempotency_key(value: Any) -> str:
    if not isinstance(value, str):
        raise CommandValidationError(
            "idempotency_key_required",
            "Idempotency-Key header is required for physical commands.",
        )
    key = value.strip()
    if not 8 <= len(key) <= 128:
        raise CommandValidationError(
            "invalid_idempotency_key",
            "Idempotency-Key must be between 8 and 128 characters.",
        )
    if any(ord(ch) < 33 or ord(ch) > 126 for ch in key):
        raise CommandValidationError(
            "invalid_idempotency_key",
            "Idempotency-Key must contain printable ASCII without spaces.",
        )
    return key


def _new_command_id() -> str:
    return COMMAND_ID_PREFIX + secrets.token_urlsafe(COMMAND_ID_BYTES)


def _decode_json_object(raw: Any) -> dict[str, Any] | None:
    if raw is None:
        return None
    try:
        value = json.loads(str(raw))
    except (json.JSONDecodeError, TypeError, ValueError):
        return None
    return value if isinstance(value, dict) else None


def command_row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "command_id": str(row["command_id"]),
        "device_id": str(row["device_id"]),
        "type": str(row["command_type"]),
        "parameters": _decode_json_object(row["parameters_json"]) or {},
        "created_at": int(row["created_at"]),
        "expires_at": int(row["expires_at"]),
        "delivered_at": row["delivered_at"],
        "delivery_count": int(row["delivery_count"] or 0),
        "acknowledged_at": row["acknowledged_at"],
        "completed_at": row["completed_at"],
        "status": str(row["status"]),
        "result": _decode_json_object(row["result_json"]),
        "error": row["error"],
    }


def _select_command_row(
    db: sqlite3.Connection,
    *,
    user_id: int,
    device_id: str,
    command_id: str,
) -> sqlite3.Row | None:
    return db.execute(
        """
        SELECT *
        FROM device_commands
        WHERE user_id = ? AND device_id = ? AND command_id = ?
        LIMIT 1
        """,
        (int(user_id), device_id, command_id),
    ).fetchone()


def command_readiness(
    db: sqlite3.Connection,
    *,
    device_id: str,
    now: int,
    heartbeat_max_age_seconds: int = 120,
) -> tuple[bool, str | None]:
    heartbeat = db.execute(
        """
        SELECT MAX(received_at) AS last_heartbeat
        FROM device_messages
        WHERE device_id = ? AND message_type = 'heartbeat'
        """,
        (device_id,),
    ).fetchone()
    last_heartbeat = heartbeat["last_heartbeat"] if heartbeat else None
    if last_heartbeat is None:
        return False, "device_offline"
    age = int(now) - int(last_heartbeat)
    if age < 0 or age > int(heartbeat_max_age_seconds):
        return False, "device_offline"

    protocol = command_protocol_for_device(db, device_id)
    if protocol is None or protocol < COMMAND_PROTOCOL_VERSION:
        return False, "command_protocol_unavailable"

    if _ota_in_progress(db, device_id):
        return False, "ota_in_progress"

    return True, None


def enqueue_command_in_transaction(
    db: sqlite3.Connection,
    *,
    user_id: int,
    device_id: str,
    command_type: str,
    parameters: dict[str, Any],
    idempotency_key: str,
    expires_in_seconds: int,
    now: int,
) -> tuple[dict[str, Any], bool]:
    existing = db.execute(
        """
        SELECT * FROM device_commands
        WHERE user_id = ? AND device_id = ? AND idempotency_key = ?
        LIMIT 1
        """,
        (int(user_id), device_id, idempotency_key),
    ).fetchone()
    if existing is not None:
        existing_parameters = _decode_json_object(existing["parameters_json"]) or {}
        existing_ttl = int(existing["expires_at"]) - int(existing["created_at"])
        if (
            str(existing["command_type"]) != command_type
            or existing_parameters != parameters
            or existing_ttl != int(expires_in_seconds)
        ):
            raise CommandValidationError(
                "idempotency_conflict",
                "This Idempotency-Key was already used for a different command request.",
            )
        return command_row_to_dict(existing), False

    pending_count = db.execute(
        """
        SELECT COUNT(*) AS n
        FROM device_commands
        WHERE device_id = ? AND status IN ('queued', 'delivered') AND expires_at >= ?
        """,
        (device_id, int(now)),
    ).fetchone()["n"]
    if int(pending_count) >= COMMAND_MAX_PENDING_PER_DEVICE:
        raise CommandValidationError(
            "command_queue_full",
            "This device already has too many pending commands.",
        )

    # Water must never stack while a previous watering command is still in-flight,
    # and a short server-side cooldown reduces accidental repeated watering from
    # buggy integrations. Firmware must still enforce its own local limits.
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
        if (
            recent_water is not None
            and int(now) - int(recent_water["created_at"]) < WATER_COMMAND_COOLDOWN_SECONDS
        ):
            raise CommandValidationError(
                "command_cooldown",
                f"Watering commands have a {WATER_COMMAND_COOLDOWN_SECONDS}-second safety cooldown.",
            )

        water = db.execute(
            """
            SELECT 1
            FROM device_commands
            WHERE device_id = ?
              AND command_type = 'water'
              AND status IN ('queued', 'delivered', 'acknowledged')
              AND (completed_at IS NULL)
            LIMIT 1
            """,
            (device_id,),
        ).fetchone()
        if water is not None:
            raise CommandValidationError(
                "command_in_progress",
                "A watering command is already in progress for this device.",
            )

    command_id = _new_command_id()
    expires_at = int(now) + int(expires_in_seconds)
    db.execute(
        """
        INSERT INTO device_commands(
            command_id, device_id, user_id, idempotency_key,
            command_type, parameters_json, created_at, expires_at,
            status
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'queued')
        """,
        (
            command_id,
            device_id,
            int(user_id),
            idempotency_key,
            command_type,
            json.dumps(parameters, separators=(",", ":"), sort_keys=True),
            int(now),
            expires_at,
        ),
    )
    row = _select_command_row(
        db,
        user_id=user_id,
        device_id=device_id,
        command_id=command_id,
    )
    assert row is not None
    return command_row_to_dict(row), True


def cancel_command_in_transaction(
    db: sqlite3.Connection,
    *,
    user_id: int,
    device_id: str,
    command_id: str,
    now: int,
) -> tuple[dict[str, Any] | None, str | None]:
    row = _select_command_row(
        db,
        user_id=user_id,
        device_id=device_id,
        command_id=command_id,
    )
    if row is None:
        return None, "command_not_found"

    status = str(row["status"])
    if status == "queued":
        db.execute(
            """
            UPDATE device_commands
            SET status = 'cancelled', completed_at = ?, error = NULL
            WHERE id = ? AND status = 'queued'
            """,
            (int(now), int(row["id"])),
        )
        row = _select_command_row(
            db,
            user_id=user_id,
            device_id=device_id,
            command_id=command_id,
        )
        return command_row_to_dict(row), None  # type: ignore[arg-type]

    if status in {"delivered", "acknowledged"}:
        return command_row_to_dict(row), "command_already_delivered"

    return command_row_to_dict(row), "command_not_cancellable"


def _expire_pending_commands(db: sqlite3.Connection, device_id: str, now: int) -> None:
    db.execute(
        """
        UPDATE device_commands
        SET status = 'expired', completed_at = ?, error = 'command_expired'
        WHERE device_id = ?
          AND status IN ('queued', 'delivered')
          AND expires_at < ?
        """,
        (int(now), device_id, int(now)),
    )


def build_device_commands_in_transaction(
    db: sqlite3.Connection,
    *,
    device_id: str,
    message_type: str,
    payload: dict[str, Any],
    now: int,
) -> list[dict[str, Any]]:
    """At-least-once command delivery over the existing encrypted response."""
    if message_type in {"claim", "ota_status"}:
        return []
    if _setup_blocks_commands(payload):
        return []
    if not _device_is_owned(db, device_id):
        return []

    protocol = command_protocol_for_device(db, device_id)
    if protocol is None or protocol < COMMAND_PROTOCOL_VERSION:
        return []
    if _ota_in_progress(db, device_id):
        return []

    _expire_pending_commands(db, device_id, now)

    rows = db.execute(
        """
        SELECT *
        FROM device_commands
        WHERE device_id = ?
          AND status IN ('queued', 'delivered')
          AND expires_at >= ?
          AND (
              last_delivered_at IS NULL
              OR last_delivered_at <= ?
          )
        ORDER BY created_at ASC, id ASC
        LIMIT ?
        """,
        (
            device_id,
            int(now),
            int(now) - COMMAND_RETRY_AFTER_SECONDS,
            MAX_COMMANDS_PER_RESPONSE,
        ),
    ).fetchall()

    commands: list[dict[str, Any]] = []
    for row in rows:
        db.execute(
            """
            UPDATE device_commands
            SET
                status = 'delivered',
                delivered_at = COALESCE(delivered_at, ?),
                last_delivered_at = ?,
                delivery_count = delivery_count + 1
            WHERE id = ?
            """,
            (int(now), int(now), int(row["id"])),
        )
        parameters = _decode_json_object(row["parameters_json"]) or {}
        commands.append(
            {
                "id": str(row["command_id"]),
                "type": str(row["command_type"]),
                "parameters": parameters,
                "expires_at": int(row["expires_at"]),
            }
        )

    return commands


def record_command_result_in_transaction(
    db: sqlite3.Connection,
    *,
    device_id: str,
    payload: dict[str, Any],
    now: int,
) -> bool:
    """Record an authenticated acknowledgement/completion from FloraCore."""
    if not isinstance(payload, dict):
        return False

    command_id = payload.get("command_id", payload.get("id"))
    status = payload.get("status")
    if not isinstance(command_id, str) or not command_id.startswith(COMMAND_ID_PREFIX):
        return False
    if not isinstance(status, str):
        return False

    status = status.strip().lower()
    if status == "accepted":
        status = "acknowledged"
    if status not in COMMAND_RESULT_STATUSES:
        return False

    row = db.execute(
        """
        SELECT * FROM device_commands
        WHERE command_id = ? AND device_id = ?
        LIMIT 1
        """,
        (command_id, device_id),
    ).fetchone()
    if row is None:
        return False

    raw_result = payload.get("result")
    if raw_result is None:
        result_json = None
    elif isinstance(raw_result, dict):
        result_json = json.dumps(
            raw_result,
            separators=(",", ":"),
            sort_keys=True,
        )[:4000]
    else:
        result_json = json.dumps({"value": raw_result}, separators=(",", ":"))[:4000]

    raw_error = payload.get("error")
    error = str(raw_error).strip()[:512] if raw_error is not None else None
    if error == "":
        error = None

    if status == "acknowledged":
        db.execute(
            """
            UPDATE device_commands
            SET
                status = CASE
                    WHEN status IN ('completed', 'failed') THEN status
                    ELSE 'acknowledged'
                END,
                acknowledged_at = COALESCE(acknowledged_at, ?),
                result_json = COALESCE(?, result_json),
                error = COALESCE(?, error)
            WHERE id = ?
            """,
            (int(now), result_json, error, int(row["id"])),
        )
        return True

    db.execute(
        """
        UPDATE device_commands
        SET
            status = ?,
            acknowledged_at = COALESCE(acknowledged_at, ?),
            completed_at = ?,
            result_json = ?,
            error = ?
        WHERE id = ?
        """,
        (
            status,
            int(now),
            int(now),
            result_json,
            error,
            int(row["id"]),
        ),
    )
    return True
