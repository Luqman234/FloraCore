from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import sqlite3
import time
from contextlib import contextmanager, closing
from functools import wraps
from pathlib import Path
from typing import Any, Callable, TypeVar

from flask import Blueprint, current_app, g, jsonify, request, session

from floraos_commands import (
    COMMAND_MAX_TTL_SECONDS,
    COMMAND_MIN_TTL_SECONDS,
    COMMAND_TYPES,
    CommandValidationError,
    cancel_command_in_transaction,
    command_readiness,
    command_row_to_dict,
    enqueue_command_in_transaction,
    init_command_schema,
    validate_command,
    validate_idempotency_key,
    validate_ttl,
)
from floraos_ota import compare_versions, init_ota_schema


API_VERSION = "1.2"
API_PREFIX = "/api/v1"
ONLINE_HEARTBEAT_MAX_AGE_SECONDS = 120

TOKEN_PREFIX = "flora_pat_"
TOKEN_BYTES = 32
TOKEN_NAME_MAX_LEN = 64
TOKEN_DEFAULT_LIFETIME_DAYS = 90
TOKEN_MAX_LIFETIME_DAYS = 365
MAX_ACTIVE_TOKENS_PER_USER = 20

TELEMETRY_DEFAULT_LIMIT = 50
TELEMETRY_MAX_LIMIT = 100

DEVICE_NICKNAME_MAX_LEN = 80
PLANT_NAME_MAX_LEN = 80
PLANT_SPECIES_MAX_LEN = 160
PLANT_NOTES_MAX_LEN = 2000

COMMAND_DEFAULT_LIMIT = 25
COMMAND_MAX_LIMIT = 100
FIRMWARE_HISTORY_DEFAULT_LIMIT = 25
FIRMWARE_HISTORY_MAX_LIMIT = 100

VALID_SCOPES = frozenset({
    "devices:read",
    "devices:write",
    "devices:control",
    "telemetry:read",
    "plants:read",
    "plants:write",
    "firmware:read",
})
DEFAULT_SCOPES = ("devices:read", "telemetry:read")

SCOPE_LABELS = {
    "devices:read": "Read devices",
    "devices:write": "Edit device metadata",
    "devices:control": "Control devices",
    "telemetry:read": "Read telemetry",
    "plants:read": "Read plant profiles",
    "plants:write": "Edit plant profiles",
    "firmware:read": "Read firmware status",
}

public_api = Blueprint("floraos_public_api_v1", __name__)
F = TypeVar("F", bound=Callable[..., Any])


def _db_path() -> Path:
    configured = current_app.config.get("FLORAOS_DB_PATH")
    if not configured:
        raise RuntimeError("FLORAOS_DB_PATH is not configured")
    return Path(configured)


@contextmanager
def _connect():
    db = sqlite3.connect(_db_path(), timeout=5)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    db.execute("PRAGMA busy_timeout = 5000")
    try:
        yield db
    finally:
        db.close()


def _table_exists(db: sqlite3.Connection, name: str) -> bool:
    return db.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name = ? LIMIT 1",
        (name,),
    ).fetchone() is not None


def init_api_tables(db_path: str | Path) -> None:
    """Add Public API v1.2 storage without altering the ESP32 device plane."""
    path = Path(db_path)

    with closing(sqlite3.connect(path, timeout=5)) as db:
        db.execute("PRAGMA foreign_keys = ON")
        db.execute("PRAGMA busy_timeout = 5000")

        db.execute(
            """
            CREATE TABLE IF NOT EXISTS api_tokens (
                token_id TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                token_hash BLOB UNIQUE NOT NULL,
                token_prefix TEXT NOT NULL,
                name TEXT NOT NULL,
                scopes TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                last_used_at INTEGER,
                revoked_at INTEGER,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            """
        )
        db.execute(
            "CREATE INDEX IF NOT EXISTS idx_api_tokens_user "
            "ON api_tokens(user_id, created_at DESC)"
        )
        db.execute(
            "CREATE INDEX IF NOT EXISTS idx_api_tokens_hash "
            "ON api_tokens(token_hash)"
        )

        # Plant profiles are account-facing metadata attached to an owned
        # FloraCore. Deleting a profile never unclaims the device; the FK only
        # removes an orphaned profile if ownership itself is deliberately removed.
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS plant_profiles (
                device_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                species TEXT,
                notes TEXT,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                FOREIGN KEY (device_id)
                    REFERENCES device_ownership(device_id)
                    ON DELETE CASCADE
            )
            """
        )

        if _table_exists(db, "device_messages"):
            db.execute(
                "CREATE INDEX IF NOT EXISTS idx_device_messages_heartbeat "
                "ON device_messages(device_id, message_type, received_at DESC)"
            )
        if _table_exists(db, "device_telemetry"):
            db.execute(
                "CREATE INDEX IF NOT EXISTS idx_device_telemetry_device_id "
                "ON device_telemetry(device_id, id DESC)"
            )

        db.commit()

    init_ota_schema(path)
    init_command_schema(path)


def init_public_api(app, db_path: str | Path) -> None:
    """Register the PAT-authenticated user API beside the private device API."""
    resolved = Path(db_path)
    app.config["FLORAOS_DB_PATH"] = str(resolved)
    init_api_tables(resolved)

    if public_api.name not in app.blueprints:
        app.register_blueprint(public_api)


def _token_digest(token: str) -> bytes:
    return hashlib.sha256(token.encode("utf-8")).digest()


def _new_raw_token() -> str:
    return TOKEN_PREFIX + secrets.token_urlsafe(TOKEN_BYTES)


def _new_token_id() -> str:
    return secrets.token_urlsafe(18)


def _normalize_scopes(value: Any) -> tuple[str, ...] | None:
    if value is None:
        return DEFAULT_SCOPES
    if not isinstance(value, list):
        return None

    normalized: list[str] = []
    for raw in value:
        scope = str(raw).strip()
        if scope not in VALID_SCOPES:
            return None
        if scope not in normalized:
            normalized.append(scope)

    return tuple(sorted(normalized)) if normalized else None


def create_personal_access_token(
    db_path: str | Path,
    *,
    user_id: int,
    name: str,
    scopes: tuple[str, ...] = DEFAULT_SCOPES,
    lifetime_days: int = TOKEN_DEFAULT_LIFETIME_DAYS,
    now: int | None = None,
) -> dict[str, Any]:
    """Create a PAT and persist only SHA-256(raw token), never the secret."""
    name = str(name).strip()
    scopes = tuple(sorted(set(scopes)))

    if not name or len(name) > TOKEN_NAME_MAX_LEN:
        raise ValueError("invalid token name")
    if not scopes or any(scope not in VALID_SCOPES for scope in scopes):
        raise ValueError("invalid token scopes")
    if not isinstance(lifetime_days, int) or not (
        1 <= lifetime_days <= TOKEN_MAX_LIFETIME_DAYS
    ):
        raise ValueError("invalid token lifetime")

    timestamp = int(time.time()) if now is None else int(now)
    expires_at = timestamp + lifetime_days * 86400

    raw_token = _new_raw_token()
    token_id = _new_token_id()
    digest = _token_digest(raw_token)
    display_prefix = raw_token[:18]

    db = sqlite3.connect(Path(db_path), timeout=5)
    try:
        db.execute("PRAGMA foreign_keys = ON")
        db.execute("PRAGMA busy_timeout = 5000")

        active_count = db.execute(
            """
            SELECT COUNT(*)
            FROM api_tokens
            WHERE user_id = ?
              AND revoked_at IS NULL
              AND expires_at > ?
            """,
            (int(user_id), timestamp),
        ).fetchone()[0]

        if int(active_count) >= MAX_ACTIVE_TOKENS_PER_USER:
            raise ValueError("too many active API tokens")

        db.execute(
            """
            INSERT INTO api_tokens(
                token_id, user_id, token_hash, token_prefix, name, scopes,
                created_at, expires_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                token_id,
                int(user_id),
                digest,
                display_prefix,
                name,
                " ".join(scopes),
                timestamp,
                expires_at,
            ),
        )
        db.commit()
    finally:
        db.close()

    return {
        "token_id": token_id,
        "token": raw_token,
        "token_prefix": display_prefix,
        "name": name,
        "scopes": list(scopes),
        "created_at": timestamp,
        "expires_at": expires_at,
    }


def _session_user_id() -> int | None:
    raw = session.get("user_id")
    try:
        return int(raw) if raw is not None else None
    except (TypeError, ValueError):
        return None


def _csrf_valid() -> bool:
    supplied = request.headers.get("X-CSRF-Token", "")
    expected = session.get("csrf_token", "")
    return bool(
        supplied
        and expected
        and hmac.compare_digest(str(supplied), str(expected))
    )


def _response(payload: dict[str, Any], status: int):
    response = jsonify(payload)
    response.status_code = status
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-FloraOS-API-Version"] = API_VERSION
    return response


def _success(data: Any, status: int = 200, *, meta: dict[str, Any] | None = None):
    payload: dict[str, Any] = {"data": data}
    if meta is not None:
        payload["meta"] = meta
    return _response(payload, status)


def _error(
    code: str,
    message: str,
    status: int,
    *,
    headers: dict[str, str] | None = None,
):
    response = _response(
        {"error": {"code": code, "message": message}},
        status,
    )
    if headers:
        for key, value in headers.items():
            response.headers[key] = value
    return response


def _bearer_token() -> str | None:
    header = request.headers.get("Authorization", "")
    scheme, separator, value = header.partition(" ")

    if not separator or scheme.lower() != "bearer":
        return None

    token = value.strip()
    if (
        not token.startswith(TOKEN_PREFIX)
        or len(token) < len(TOKEN_PREFIX) + 32
        or len(token) > 160
    ):
        return None

    return token


def _authenticate_bearer() -> dict[str, Any] | None:
    token = _bearer_token()
    if token is None:
        return None

    digest = _token_digest(token)
    now = int(time.time())

    with _connect() as db:
        row = db.execute(
            """
            SELECT
                t.token_id, t.user_id, t.name, t.scopes, t.created_at,
                t.expires_at, t.last_used_at, t.revoked_at, u.email
            FROM api_tokens AS t
            JOIN users AS u ON u.id = t.user_id
            WHERE t.token_hash = ?
            LIMIT 1
            """,
            (digest,),
        ).fetchone()

        if row is None or row["revoked_at"] is not None:
            return None
        if int(row["expires_at"]) <= now:
            return None

        # Avoid a write on every read-heavy API request.
        last_used = row["last_used_at"]
        if last_used is None or now - int(last_used) >= 60:
            db.execute(
                "UPDATE api_tokens SET last_used_at = ? "
                "WHERE token_id = ? AND revoked_at IS NULL",
                (now, row["token_id"]),
            )
            db.commit()

    return {
        "token_id": str(row["token_id"]),
        "user_id": int(row["user_id"]),
        "email": str(row["email"]),
        "name": str(row["name"]),
        "scopes": frozenset(str(row["scopes"]).split()),
        "created_at": int(row["created_at"]),
        "expires_at": int(row["expires_at"]),
    }


def require_api_token(*required_scopes: str):
    for scope in required_scopes:
        if scope not in VALID_SCOPES:
            raise ValueError(f"unknown FloraOS API scope: {scope}")

    def decorator(func: F) -> F:
        @wraps(func)
        def wrapped(*args, **kwargs):
            principal = _authenticate_bearer()
            if principal is None:
                return _error(
                    "invalid_token",
                    "A valid FloraOS API bearer token is required.",
                    401,
                    headers={
                        "WWW-Authenticate":
                            'Bearer realm="FloraOS API", error="invalid_token"'
                    },
                )

            missing = [
                scope for scope in required_scopes
                if scope not in principal["scopes"]
            ]
            if missing:
                return _error(
                    "insufficient_scope",
                    "This API token does not have the required scope.",
                    403,
                    headers={
                        "WWW-Authenticate":
                            'Bearer realm="FloraOS API", '
                            'error="insufficient_scope", '
                            f'scope="{" ".join(required_scopes)}"'
                    },
                )

            g.floraos_api_principal = principal
            return func(*args, **kwargs)

        return wrapped  # type: ignore[return-value]

    return decorator


def _principal() -> dict[str, Any]:
    return g.floraos_api_principal


def _heartbeat_age(last_heartbeat_at: Any, now: int) -> int | None:
    if last_heartbeat_at is None:
        return None
    try:
        age = now - int(last_heartbeat_at)
    except (TypeError, ValueError):
        return None
    return age if age >= 0 else None


def _owned_device_row(
    db: sqlite3.Connection,
    user_id: int,
    device_id: str,
) -> sqlite3.Row | None:
    return db.execute(
        """
        SELECT
            o.device_id,
            o.claimed_at,
            o.nickname,
            s.last_seen,
            s.last_message_type,
            s.last_message_id,
            s.firmware_product,
            s.firmware_target,
            s.firmware_version,
            s.firmware_channel,
            s.firmware_reported_at,
            s.command_protocol,
            s.command_protocol_reported_at,
            (
                SELECT MAX(m.received_at)
                FROM device_messages AS m
                WHERE m.device_id = o.device_id
                  AND m.message_type = 'heartbeat'
            ) AS last_heartbeat_at
        FROM device_ownership AS o
        LEFT JOIN device_state AS s ON s.device_id = o.device_id
        WHERE o.user_id = ? AND o.device_id = ?
        LIMIT 1
        """,
        (int(user_id), device_id),
    ).fetchone()


def _device_dict(row: sqlite3.Row, *, now: int) -> dict[str, Any]:
    age = _heartbeat_age(row["last_heartbeat_at"], now)
    return {
        "device_id": row["device_id"],
        "nickname": row["nickname"],
        "claimed_at": row["claimed_at"],
        "online": age is not None and age <= ONLINE_HEARTBEAT_MAX_AGE_SECONDS,
        "last_heartbeat_at": row["last_heartbeat_at"],
        "heartbeat_age_seconds": age,
        "last_seen": row["last_seen"],
        "last_message_type": row["last_message_type"],
        "last_message_id": row["last_message_id"],
        "firmware": {
            "product": row["firmware_product"],
            "target": row["firmware_target"],
            "version": row["firmware_version"],
            "channel": row["firmware_channel"],
            "reported_at": row["firmware_reported_at"],
        },
        "command_protocol": row["command_protocol"],
        "command_capable": (
            row["command_protocol"] is not None
            and int(row["command_protocol"]) >= 1
        ),
    }


def _decode_payload(raw: Any) -> dict[str, Any] | None:
    try:
        payload = json.loads(str(raw))
    except (json.JSONDecodeError, TypeError, ValueError):
        return None
    return payload if isinstance(payload, dict) else None


def _validate_device_id(device_id: str):
    if not device_id or len(device_id) > 64:
        return _error("invalid_device_id", "Invalid device id.", 400)
    return None


def _ownership_or_404(db: sqlite3.Connection, user_id: int, device_id: str):
    row = _owned_device_row(db, user_id, device_id)
    if row is None:
        return None, _error("device_not_found", "Device not found.", 404)
    return row, None


def _validate_optional_text(
    value: Any,
    *,
    field: str,
    maximum: int,
    allow_null: bool = True,
) -> tuple[str | None, Any | None]:
    if value is None and allow_null:
        return None, None
    if not isinstance(value, str):
        return None, _error("invalid_request", f"{field} must be a string.", 400)
    text = value.strip()
    if len(text) > maximum:
        return None, _error(
            "invalid_request",
            f"{field} must be at most {maximum} characters.",
            400,
        )
    return text or None, None


# -------------------------------------------------------------------------
# Public API discovery/authenticated endpoints
# -------------------------------------------------------------------------

@public_api.get(API_PREFIX)
def api_discovery():
    return _success({
        "name": "FloraOS Public API",
        "version": API_VERSION,
        "namespace": API_PREFIX,
        "authentication": "Bearer Personal Access Token",
        "token_prefix": TOKEN_PREFIX,
        "online_heartbeat_max_age_seconds": ONLINE_HEARTBEAT_MAX_AGE_SECONDS,
        "physical_device_control": True,
        "command_protocol": 1,
        "command_types": sorted(COMMAND_TYPES),
        "command_ttl_seconds": {
            "min": COMMAND_MIN_TTL_SECONDS,
            "max": COMMAND_MAX_TTL_SECONDS,
        },
        "ota_control": False,
        "scopes": [
            {"scope": scope, "label": SCOPE_LABELS[scope]}
            for scope in sorted(VALID_SCOPES)
        ],
    })


@public_api.get(f"{API_PREFIX}/me")
@require_api_token()
def api_me():
    principal = _principal()
    # Per product decision, the existing sequential users.id is the official
    # public FloraCore User ID. It identifies the account but does not authorize it.
    return _success({
        "user_id": principal["user_id"],
        "email": principal["email"],
        "token": {
            "name": principal["name"],
            "scopes": sorted(principal["scopes"]),
            "created_at": principal["created_at"],
            "expires_at": principal["expires_at"],
        },
    })


@public_api.get(f"{API_PREFIX}/devices")
@require_api_token("devices:read")
def api_devices():
    principal = _principal()
    now = int(time.time())

    with _connect() as db:
        rows = db.execute(
            """
            SELECT
                o.device_id,
                o.claimed_at,
                o.nickname,
                s.last_seen,
                s.last_message_type,
                s.last_message_id,
                s.firmware_product,
                s.firmware_target,
                s.firmware_version,
                s.firmware_channel,
                s.firmware_reported_at,
                s.command_protocol,
                s.command_protocol_reported_at,
                (
                    SELECT MAX(m.received_at)
                    FROM device_messages AS m
                    WHERE m.device_id = o.device_id
                      AND m.message_type = 'heartbeat'
                ) AS last_heartbeat_at
            FROM device_ownership AS o
            LEFT JOIN device_state AS s ON s.device_id = o.device_id
            WHERE o.user_id = ?
            ORDER BY o.claimed_at DESC
            """,
            (principal["user_id"],),
        ).fetchall()

    return _success(
        [_device_dict(row, now=now) for row in rows],
        meta={
            "count": len(rows),
            "online_threshold_seconds": ONLINE_HEARTBEAT_MAX_AGE_SECONDS,
        },
    )


@public_api.get(f"{API_PREFIX}/devices/<device_id>")
@require_api_token("devices:read")
def api_device(device_id: str):
    invalid = _validate_device_id(device_id)
    if invalid:
        return invalid

    principal = _principal()
    now = int(time.time())

    with _connect() as db:
        row, error = _ownership_or_404(db, principal["user_id"], device_id)
    if error:
        return error

    return _success(_device_dict(row, now=now))


@public_api.patch(f"{API_PREFIX}/devices/<device_id>")
@require_api_token("devices:write")
def api_patch_device(device_id: str):
    invalid = _validate_device_id(device_id)
    if invalid:
        return invalid

    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return _error("invalid_request", "A JSON object is required.", 400)

    extra = set(body) - {"nickname"}
    if extra:
        return _error(
            "invalid_request",
            "Only owner-controlled device metadata can be changed.",
            400,
        )
    if "nickname" not in body:
        return _error("invalid_request", "nickname is required.", 400)

    nickname, error = _validate_optional_text(
        body.get("nickname"), field="nickname", maximum=DEVICE_NICKNAME_MAX_LEN
    )
    if error:
        return error

    principal = _principal()
    now = int(time.time())
    with _connect() as db:
        row, ownership_error = _ownership_or_404(
            db, principal["user_id"], device_id
        )
        if ownership_error:
            return ownership_error

        db.execute(
            "UPDATE device_ownership SET nickname = ? "
            "WHERE user_id = ? AND device_id = ?",
            (nickname, principal["user_id"], device_id),
        )
        db.commit()
        row = _owned_device_row(db, principal["user_id"], device_id)

    return _success(_device_dict(row, now=now))


@public_api.get(f"{API_PREFIX}/devices/<device_id>/state")
@require_api_token("devices:read", "telemetry:read")
def api_device_state(device_id: str):
    invalid = _validate_device_id(device_id)
    if invalid:
        return invalid

    principal = _principal()
    now = int(time.time())

    with _connect() as db:
        row, error = _ownership_or_404(db, principal["user_id"], device_id)
        if error:
            return error

        telemetry = db.execute(
            """
            SELECT message_id, received_at, payload_json
            FROM device_telemetry
            WHERE device_id = ?
            ORDER BY id DESC
            LIMIT 1
            """,
            (device_id,),
        ).fetchone()

    result = _device_dict(row, now=now)
    result["telemetry"] = None
    if telemetry is not None:
        result["telemetry"] = {
            "message_id": telemetry["message_id"],
            "received_at": telemetry["received_at"],
            "payload": _decode_payload(telemetry["payload_json"]),
        }

    return _success(result)


@public_api.get(f"{API_PREFIX}/devices/<device_id>/telemetry/latest")
@require_api_token("telemetry:read")
def api_latest_telemetry(device_id: str):
    invalid = _validate_device_id(device_id)
    if invalid:
        return invalid

    principal = _principal()

    with _connect() as db:
        _, error = _ownership_or_404(db, principal["user_id"], device_id)
        if error:
            return error

        telemetry = db.execute(
            """
            SELECT message_id, received_at, payload_json
            FROM device_telemetry
            WHERE device_id = ?
            ORDER BY id DESC
            LIMIT 1
            """,
            (device_id,),
        ).fetchone()

    if telemetry is None:
        return _success(None)

    return _success({
        "device_id": device_id,
        "message_id": telemetry["message_id"],
        "received_at": telemetry["received_at"],
        "payload": _decode_payload(telemetry["payload_json"]),
    })


@public_api.get(f"{API_PREFIX}/devices/<device_id>/telemetry")
@require_api_token("telemetry:read")
def api_telemetry_history(device_id: str):
    invalid = _validate_device_id(device_id)
    if invalid:
        return invalid

    raw_limit = request.args.get("limit", str(TELEMETRY_DEFAULT_LIMIT))
    raw_cursor = request.args.get("cursor", "")

    try:
        limit = int(raw_limit)
    except (TypeError, ValueError):
        return _error("invalid_limit", "limit must be an integer.", 400)

    if not 1 <= limit <= TELEMETRY_MAX_LIMIT:
        return _error(
            "invalid_limit",
            f"limit must be between 1 and {TELEMETRY_MAX_LIMIT}.",
            400,
        )

    cursor: int | None = None
    if raw_cursor:
        try:
            cursor = int(raw_cursor)
        except ValueError:
            return _error("invalid_cursor", "cursor is invalid.", 400)
        if cursor <= 0:
            return _error("invalid_cursor", "cursor is invalid.", 400)

    principal = _principal()

    with _connect() as db:
        _, error = _ownership_or_404(db, principal["user_id"], device_id)
        if error:
            return error

        if cursor is None:
            rows = db.execute(
                """
                SELECT id, message_id, received_at, payload_json
                FROM device_telemetry
                WHERE device_id = ?
                ORDER BY id DESC
                LIMIT ?
                """,
                (device_id, limit + 1),
            ).fetchall()
        else:
            rows = db.execute(
                """
                SELECT id, message_id, received_at, payload_json
                FROM device_telemetry
                WHERE device_id = ? AND id < ?
                ORDER BY id DESC
                LIMIT ?
                """,
                (device_id, cursor, limit + 1),
            ).fetchall()

    has_more = len(rows) > limit
    page = rows[:limit]
    next_cursor = str(page[-1]["id"]) if has_more and page else None

    return _success(
        [
            {
                "device_id": device_id,
                "message_id": row["message_id"],
                "received_at": row["received_at"],
                "payload": _decode_payload(row["payload_json"]),
            }
            for row in page
        ],
        meta={
            "limit": limit,
            "next_cursor": next_cursor,
            "has_more": has_more,
        },
    )


# -------------------------------------------------------------------------
# Plant profile API v1.1 (retained in v1.2)
# -------------------------------------------------------------------------

@public_api.get(f"{API_PREFIX}/devices/<device_id>/plant")
@require_api_token("plants:read")
def api_get_plant(device_id: str):
    invalid = _validate_device_id(device_id)
    if invalid:
        return invalid

    principal = _principal()
    with _connect() as db:
        _, error = _ownership_or_404(db, principal["user_id"], device_id)
        if error:
            return error

        row = db.execute(
            """
            SELECT name, species, notes, created_at, updated_at
            FROM plant_profiles
            WHERE device_id = ?
            """,
            (device_id,),
        ).fetchone()

    if row is None:
        return _success(None)

    return _success({
        "device_id": device_id,
        "name": row["name"],
        "species": row["species"],
        "notes": row["notes"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    })


@public_api.put(f"{API_PREFIX}/devices/<device_id>/plant")
@require_api_token("plants:write")
def api_put_plant(device_id: str):
    invalid = _validate_device_id(device_id)
    if invalid:
        return invalid

    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return _error("invalid_request", "A JSON object is required.", 400)

    extra = set(body) - {"name", "species", "notes"}
    if extra:
        return _error("invalid_request", "Unknown plant-profile field.", 400)

    name_raw = body.get("name")
    if not isinstance(name_raw, str) or not name_raw.strip():
        return _error("invalid_request", "name is required.", 400)
    name = name_raw.strip()
    if len(name) > PLANT_NAME_MAX_LEN:
        return _error(
            "invalid_request",
            f"name must be at most {PLANT_NAME_MAX_LEN} characters.",
            400,
        )

    species, error = _validate_optional_text(
        body.get("species"), field="species", maximum=PLANT_SPECIES_MAX_LEN
    )
    if error:
        return error
    notes, error = _validate_optional_text(
        body.get("notes"), field="notes", maximum=PLANT_NOTES_MAX_LEN
    )
    if error:
        return error

    principal = _principal()
    now = int(time.time())

    with _connect() as db:
        _, ownership_error = _ownership_or_404(
            db, principal["user_id"], device_id
        )
        if ownership_error:
            return ownership_error

        existing = db.execute(
            "SELECT created_at FROM plant_profiles WHERE device_id = ?",
            (device_id,),
        ).fetchone()

        if existing is None:
            db.execute(
                """
                INSERT INTO plant_profiles(
                    device_id, name, species, notes, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (device_id, name, species, notes, now, now),
            )
            status = 201
            created_at = now
        else:
            created_at = int(existing["created_at"])
            db.execute(
                """
                UPDATE plant_profiles
                SET name = ?, species = ?, notes = ?, updated_at = ?
                WHERE device_id = ?
                """,
                (name, species, notes, now, device_id),
            )
            status = 200

        db.commit()

    return _success({
        "device_id": device_id,
        "name": name,
        "species": species,
        "notes": notes,
        "created_at": created_at,
        "updated_at": now,
    }, status)


@public_api.delete(f"{API_PREFIX}/devices/<device_id>/plant")
@require_api_token("plants:write")
def api_delete_plant(device_id: str):
    invalid = _validate_device_id(device_id)
    if invalid:
        return invalid

    principal = _principal()
    with _connect() as db:
        _, error = _ownership_or_404(db, principal["user_id"], device_id)
        if error:
            return error

        cursor = db.execute(
            "DELETE FROM plant_profiles WHERE device_id = ?",
            (device_id,),
        )
        db.commit()

    return _success({
        "device_id": device_id,
        "deleted": cursor.rowcount > 0,
    })



# -------------------------------------------------------------------------
# Public API v1.2 — firmware visibility + safe physical command queue
# -------------------------------------------------------------------------

def _bounded_limit(
    *,
    default: int,
    maximum: int,
) -> tuple[int | None, Any | None]:
    raw = request.args.get("limit", str(default))
    try:
        limit = int(raw)
    except (TypeError, ValueError):
        return None, _error("invalid_limit", "limit must be an integer.", 400)
    if not 1 <= limit <= maximum:
        return None, _error(
            "invalid_limit",
            f"limit must be between 1 and {maximum}.",
            400,
        )
    return limit, None


def _integer_cursor() -> tuple[int | None, Any | None]:
    raw = request.args.get("cursor", "").strip()
    if not raw:
        return None, None
    try:
        cursor = int(raw)
    except ValueError:
        return None, _error("invalid_cursor", "cursor is invalid.", 400)
    if cursor <= 0:
        return None, _error("invalid_cursor", "cursor is invalid.", 400)
    return cursor, None


def _firmware_release_for_device(
    db: sqlite3.Connection,
    device_id: str,
) -> sqlite3.Row | None:
    state = db.execute(
        """
        SELECT firmware_product, firmware_target, firmware_version, firmware_channel
        FROM device_state
        WHERE device_id = ?
        """,
        (device_id,),
    ).fetchone()
    if state is None:
        return None

    product = state["firmware_product"]
    target = state["firmware_target"]
    installed = state["firmware_version"]
    channel = state["firmware_channel"]
    if not all((product, target, installed, channel)):
        return None

    rows = db.execute(
        """
        SELECT id, version, channel, byte_size, sha256, binary_url,
               released_at, release_notes
        FROM firmware_releases
        WHERE product = ? AND target = ? AND channel = ? AND enabled = 1
        """,
        (product, target, channel),
    ).fetchall()

    best = None
    for row in rows:
        try:
            newer = compare_versions(str(row["version"]), str(installed)) > 0
        except ValueError:
            continue
        if not newer:
            continue

        attempt = db.execute(
            """
            SELECT status
            FROM device_ota_history
            WHERE device_id = ? AND release_id = ?
            ORDER BY id DESC LIMIT 1
            """,
            (device_id, int(row["id"])),
        ).fetchone()
        if attempt is not None and str(attempt["status"]) in {
            "validated", "failed", "rolled_back"
        }:
            continue

        if best is None:
            best = row
            continue
        try:
            if compare_versions(str(row["version"]), str(best["version"])) > 0:
                best = row
        except ValueError:
            pass
    return best


@public_api.get(f"{API_PREFIX}/devices/<device_id>/firmware")
@require_api_token("firmware:read")
def api_device_firmware(device_id: str):
    invalid = _validate_device_id(device_id)
    if invalid:
        return invalid

    principal = _principal()
    with _connect() as db:
        _, error = _ownership_or_404(db, principal["user_id"], device_id)
        if error:
            return error

        state = db.execute(
            """
            SELECT firmware_product, firmware_target, firmware_version,
                   firmware_channel, firmware_reported_at
            FROM device_state
            WHERE device_id = ?
            """,
            (device_id,),
        ).fetchone()
        release = _firmware_release_for_device(db, device_id)
        latest = db.execute(
            """
            SELECT from_version, target_version, started_at, completed_at,
                   status, error, result, updated_at
            FROM device_ota_history
            WHERE device_id = ?
            ORDER BY updated_at DESC, id DESC
            LIMIT 1
            """,
            (device_id,),
        ).fetchone()

    installed = state["firmware_version"] if state else None
    available = str(release["version"]) if release is not None else None

    if latest is not None and str(latest["status"]) == "rolled_back":
        status = "rolled_back"
    elif latest is not None and str(latest["status"]) == "failed":
        status = "failed"
    elif latest is not None and str(latest["status"]) in {"downloading", "installed"}:
        status = str(latest["status"])
    elif available is not None:
        status = "update_available"
    elif installed is None:
        status = "unknown"
    else:
        status = "up_to_date"

    return _success({
        "device_id": device_id,
        "product": state["firmware_product"] if state else None,
        "target": state["firmware_target"] if state else None,
        "installed": installed,
        "channel": state["firmware_channel"] if state else None,
        "reported_at": state["firmware_reported_at"] if state else None,
        "available": available,
        "status": status,
        "release": (
            {
                "version": str(release["version"]),
                "channel": str(release["channel"]),
                "size": int(release["byte_size"]),
                "sha256": str(release["sha256"]),
                "url": str(release["binary_url"]),
                "released_at": int(release["released_at"]),
                "release_notes": release["release_notes"],
            }
            if release is not None
            else None
        ),
        "last_update": (
            {
                "from_version": latest["from_version"],
                "target_version": latest["target_version"],
                "started_at": latest["started_at"],
                "completed_at": latest["completed_at"],
                "status": latest["status"],
                "error": latest["error"],
                "result": latest["result"],
                "updated_at": latest["updated_at"],
            }
            if latest is not None
            else None
        ),
    })


@public_api.get(f"{API_PREFIX}/devices/<device_id>/firmware/history")
@require_api_token("firmware:read")
def api_device_firmware_history(device_id: str):
    invalid = _validate_device_id(device_id)
    if invalid:
        return invalid

    limit, error = _bounded_limit(
        default=FIRMWARE_HISTORY_DEFAULT_LIMIT,
        maximum=FIRMWARE_HISTORY_MAX_LIMIT,
    )
    if error:
        return error
    cursor, error = _integer_cursor()
    if error:
        return error
    assert limit is not None

    principal = _principal()
    with _connect() as db:
        _, ownership_error = _ownership_or_404(
            db, principal["user_id"], device_id
        )
        if ownership_error:
            return ownership_error

        if cursor is None:
            rows = db.execute(
                """
                SELECT id, from_version, target_version, started_at,
                       completed_at, status, error, result, updated_at
                FROM device_ota_history
                WHERE device_id = ?
                ORDER BY id DESC
                LIMIT ?
                """,
                (device_id, limit + 1),
            ).fetchall()
        else:
            rows = db.execute(
                """
                SELECT id, from_version, target_version, started_at,
                       completed_at, status, error, result, updated_at
                FROM device_ota_history
                WHERE device_id = ? AND id < ?
                ORDER BY id DESC
                LIMIT ?
                """,
                (device_id, cursor, limit + 1),
            ).fetchall()

    has_more = len(rows) > limit
    page = rows[:limit]
    next_cursor = str(page[-1]["id"]) if has_more and page else None
    return _success(
        [
            {
                "from_version": row["from_version"],
                "target_version": row["target_version"],
                "started_at": row["started_at"],
                "completed_at": row["completed_at"],
                "status": row["status"],
                "error": row["error"],
                "result": row["result"],
                "updated_at": row["updated_at"],
            }
            for row in page
        ],
        meta={
            "limit": limit,
            "next_cursor": next_cursor,
            "has_more": has_more,
        },
    )


@public_api.post(f"{API_PREFIX}/devices/<device_id>/commands")
@require_api_token("devices:control")
def api_create_command(device_id: str):
    invalid = _validate_device_id(device_id)
    if invalid:
        return invalid

    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return _error("invalid_request", "A JSON object is required.", 400)

    extra = set(body) - {"type", "parameters", "expires_in_seconds"}
    if extra:
        return _error(
            "invalid_request",
            "Unknown command field. user_id and arbitrary command data are not accepted.",
            400,
        )

    try:
        command_type, parameters = validate_command(
            body.get("type"), body.get("parameters")
        )
        ttl = validate_ttl(body.get("expires_in_seconds"))
        idempotency_key = validate_idempotency_key(
            request.headers.get("Idempotency-Key")
        )
    except CommandValidationError as exc:
        return _error(exc.code, exc.message, 400)

    # OTA is never a command type in this API. The allow-list above admits only
    # safe, typed operations with bounded parameters.
    principal = _principal()
    now = int(time.time())

    with _connect() as db:
        try:
            db.execute("BEGIN IMMEDIATE")

            _, ownership_error = _ownership_or_404(
                db, principal["user_id"], device_id
            )
            if ownership_error:
                db.rollback()
                return ownership_error

            ready, reason = command_readiness(
                db,
                device_id=device_id,
                now=now,
                heartbeat_max_age_seconds=ONLINE_HEARTBEAT_MAX_AGE_SECONDS,
            )
            if not ready:
                db.rollback()
                messages = {
                    "device_offline": "Device is offline; physical commands are not queued.",
                    "command_protocol_unavailable": (
                        "This FloraCore has not reported support for command protocol v1."
                    ),
                    "ota_in_progress": "A firmware update is in progress for this device.",
                }
                return _error(
                    reason or "control_unavailable",
                    messages.get(reason, "Device control is unavailable."),
                    409,
                )

            command, created = enqueue_command_in_transaction(
                db,
                user_id=principal["user_id"],
                device_id=device_id,
                command_type=command_type,
                parameters=parameters,
                idempotency_key=idempotency_key,
                expires_in_seconds=ttl,
                now=now,
            )
            db.commit()
        except CommandValidationError as exc:
            db.rollback()
            if exc.code == "command_cooldown":
                status = 429
            elif exc.code in {"command_queue_full", "command_in_progress", "idempotency_conflict"}:
                status = 409
            else:
                status = 400
            return _error(exc.code, exc.message, status)
        except sqlite3.IntegrityError:
            db.rollback()
            # A concurrent retry with the same Idempotency-Key should resolve
            # to the already-created command rather than creating a second action.
            row = db.execute(
                """
                SELECT * FROM device_commands
                WHERE user_id = ? AND device_id = ? AND idempotency_key = ?
                LIMIT 1
                """,
                (principal["user_id"], device_id, idempotency_key),
            ).fetchone()
            if row is None:
                return _error("command_conflict", "Command could not be queued.", 409)
            command = command_row_to_dict(row)
            created = False

    return _success(
        command,
        201 if created else 200,
        meta={"idempotent_replay": not created},
    )


@public_api.get(f"{API_PREFIX}/devices/<device_id>/commands")
@require_api_token("devices:control")
def api_commands(device_id: str):
    invalid = _validate_device_id(device_id)
    if invalid:
        return invalid

    limit, error = _bounded_limit(
        default=COMMAND_DEFAULT_LIMIT,
        maximum=COMMAND_MAX_LIMIT,
    )
    if error:
        return error
    cursor, error = _integer_cursor()
    if error:
        return error
    assert limit is not None

    principal = _principal()
    with _connect() as db:
        _, ownership_error = _ownership_or_404(
            db, principal["user_id"], device_id
        )
        if ownership_error:
            return ownership_error

        if cursor is None:
            rows = db.execute(
                """
                SELECT * FROM device_commands
                WHERE user_id = ? AND device_id = ?
                ORDER BY id DESC LIMIT ?
                """,
                (principal["user_id"], device_id, limit + 1),
            ).fetchall()
        else:
            rows = db.execute(
                """
                SELECT * FROM device_commands
                WHERE user_id = ? AND device_id = ? AND id < ?
                ORDER BY id DESC LIMIT ?
                """,
                (principal["user_id"], device_id, cursor, limit + 1),
            ).fetchall()

    has_more = len(rows) > limit
    page = rows[:limit]
    next_cursor = str(page[-1]["id"]) if has_more and page else None
    return _success(
        [command_row_to_dict(row) for row in page],
        meta={
            "limit": limit,
            "next_cursor": next_cursor,
            "has_more": has_more,
        },
    )


@public_api.get(f"{API_PREFIX}/devices/<device_id>/commands/<command_id>")
@require_api_token("devices:control")
def api_command(device_id: str, command_id: str):
    invalid = _validate_device_id(device_id)
    if invalid:
        return invalid
    if not command_id.startswith("cmd_") or len(command_id) > 128:
        return _error("command_not_found", "Command not found.", 404)

    principal = _principal()
    with _connect() as db:
        _, ownership_error = _ownership_or_404(
            db, principal["user_id"], device_id
        )
        if ownership_error:
            return ownership_error

        row = db.execute(
            """
            SELECT * FROM device_commands
            WHERE user_id = ? AND device_id = ? AND command_id = ?
            LIMIT 1
            """,
            (principal["user_id"], device_id, command_id),
        ).fetchone()

    if row is None:
        return _error("command_not_found", "Command not found.", 404)
    return _success(command_row_to_dict(row))


@public_api.delete(f"{API_PREFIX}/devices/<device_id>/commands/<command_id>")
@require_api_token("devices:control")
def api_cancel_command(device_id: str, command_id: str):
    invalid = _validate_device_id(device_id)
    if invalid:
        return invalid
    if not command_id.startswith("cmd_") or len(command_id) > 128:
        return _error("command_not_found", "Command not found.", 404)

    principal = _principal()
    now = int(time.time())
    with _connect() as db:
        _, ownership_error = _ownership_or_404(
            db, principal["user_id"], device_id
        )
        if ownership_error:
            return ownership_error

        command, reason = cancel_command_in_transaction(
            db,
            user_id=principal["user_id"],
            device_id=device_id,
            command_id=command_id,
            now=now,
        )
        if command is None:
            return _error("command_not_found", "Command not found.", 404)
        if reason == "command_already_delivered":
            return _error(
                "command_already_delivered",
                "This command was already delivered and can no longer be safely cancelled.",
                409,
            )
        if reason == "command_not_cancellable":
            return _error(
                "command_not_cancellable",
                "This command is already in a terminal state.",
                409,
            )
        db.commit()

    return _success(command)

# -------------------------------------------------------------------------
# Website-session token-management API (NOT bearer-token routes)
# -------------------------------------------------------------------------

@public_api.get("/api/developer/tokens")
def developer_tokens_list():
    user_id = _session_user_id()
    if user_id is None:
        return _error("not_authenticated", "Not authenticated.", 401)

    now = int(time.time())
    with _connect() as db:
        rows = db.execute(
            """
            SELECT
                token_id, token_prefix, name, scopes, created_at,
                expires_at, last_used_at, revoked_at
            FROM api_tokens
            WHERE user_id = ?
            ORDER BY created_at DESC
            """,
            (user_id,),
        ).fetchall()

    tokens = []
    for row in rows:
        if row["revoked_at"] is not None:
            status = "revoked"
        elif int(row["expires_at"]) <= now:
            status = "expired"
        else:
            status = "active"

        tokens.append({
            "token_id": row["token_id"],
            "token_prefix": row["token_prefix"],
            "name": row["name"],
            "scopes": str(row["scopes"]).split(),
            "created_at": row["created_at"],
            "expires_at": row["expires_at"],
            "last_used_at": row["last_used_at"],
            "revoked_at": row["revoked_at"],
            "status": status,
        })

    return _success(tokens, meta={"count": len(tokens)})


@public_api.post("/api/developer/tokens")
def developer_tokens_create():
    user_id = _session_user_id()
    if user_id is None:
        return _error("not_authenticated", "Not authenticated.", 401)
    if not _csrf_valid():
        return _error(
            "invalid_csrf",
            "Invalid or expired security token. Refresh and try again.",
            403,
        )

    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return _error("invalid_request", "A JSON object is required.", 400)

    name = str(body.get("name", "")).strip()
    scopes = _normalize_scopes(body.get("scopes"))

    try:
        lifetime_days = int(body.get("expires_in_days", TOKEN_DEFAULT_LIFETIME_DAYS))
    except (TypeError, ValueError):
        return _error("invalid_expiration", "Expiration is invalid.", 400)

    if not name or len(name) > TOKEN_NAME_MAX_LEN:
        return _error(
            "invalid_name",
            f"Token name must be between 1 and {TOKEN_NAME_MAX_LEN} characters.",
            400,
        )
    if scopes is None:
        return _error("invalid_scope", "One or more token scopes are invalid.", 400)
    if not 1 <= lifetime_days <= TOKEN_MAX_LIFETIME_DAYS:
        return _error(
            "invalid_expiration",
            f"Expiration must be between 1 and {TOKEN_MAX_LIFETIME_DAYS} days.",
            400,
        )

    try:
        token = create_personal_access_token(
            _db_path(),
            user_id=user_id,
            name=name,
            scopes=scopes,
            lifetime_days=lifetime_days,
        )
    except ValueError as exc:
        if str(exc) == "too many active API tokens":
            return _error(
                "token_limit_reached",
                f"You can have at most {MAX_ACTIVE_TOKENS_PER_USER} active API tokens.",
                409,
            )
        return _error("invalid_request", "Token could not be created.", 400)

    # Raw token is intentionally returned exactly once in this creation response.
    return _success(token, 201)


@public_api.delete("/api/developer/tokens/<token_id>")
def developer_tokens_revoke(token_id: str):
    user_id = _session_user_id()
    if user_id is None:
        return _error("not_authenticated", "Not authenticated.", 401)
    if not _csrf_valid():
        return _error(
            "invalid_csrf",
            "Invalid or expired security token. Refresh and try again.",
            403,
        )

    if not token_id or len(token_id) > 128:
        return _error("token_not_found", "Token not found.", 404)

    now = int(time.time())
    with _connect() as db:
        row = db.execute(
            "SELECT revoked_at FROM api_tokens WHERE token_id = ? AND user_id = ?",
            (token_id, user_id),
        ).fetchone()
        if row is None:
            return _error("token_not_found", "Token not found.", 404)

        if row["revoked_at"] is None:
            db.execute(
                "UPDATE api_tokens SET revoked_at = ? "
                "WHERE token_id = ? AND user_id = ?",
                (now, token_id, user_id),
            )
            db.commit()

    return _success({"token_id": token_id, "revoked": True})
