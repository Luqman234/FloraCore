from __future__ import annotations

import hashlib
import hmac
import secrets
import sqlite3
import time
from pathlib import Path
from typing import Any

from flask import Blueprint, current_app, jsonify, request, session


CLAIM_TTL_SECONDS = 10 * 60
CLAIM_TOKEN_BYTES = 32  # 256 bits of entropy before URL-safe encoding.
CLAIM_TOKEN_MIN_LEN = 32
CLAIM_TOKEN_MAX_LEN = 128
CLAIM_ID_BYTES = 18

enrollment_api = Blueprint("device_enrollment", __name__)


def _db_path() -> Path:
    configured = current_app.config.get("FLORAOS_DB_PATH")
    if not configured:
        raise RuntimeError("FLORAOS_DB_PATH is not configured")
    return Path(configured)


def _connect() -> sqlite3.Connection:
    db = sqlite3.connect(_db_path(), timeout=5)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    db.execute("PRAGMA busy_timeout = 5000")
    return db


def _token_hash(token: str) -> bytes:
    return hashlib.sha256(token.encode("utf-8")).digest()


def _valid_token(token: str) -> bool:
    if not isinstance(token, str):
        return False
    if not (CLAIM_TOKEN_MIN_LEN <= len(token) <= CLAIM_TOKEN_MAX_LEN):
        return False
    return all(ch.isalnum() or ch in "-_" for ch in token)


def _session_user_id() -> int | None:
    raw = session.get("user_id")
    try:
        return int(raw) if raw is not None else None
    except (TypeError, ValueError):
        return None


def _csrf_valid() -> bool:
    supplied = request.headers.get("X-CSRF-Token", "")
    expected = session.get("csrf_token", "")
    return bool(supplied and expected and hmac.compare_digest(supplied, expected))


def _require_login_json():
    if _session_user_id() is None:
        return jsonify(error="Not authenticated."), 401
    return None


def _require_csrf_json():
    if not _csrf_valid():
        return jsonify(error="Invalid or expired security token. Refresh the page and try again."), 403
    return None


def _init_tables(db_path: Path) -> None:
    with sqlite3.connect(db_path, timeout=5) as db:
        db.execute("PRAGMA foreign_keys = ON")
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS device_ownership (
                device_id TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                claimed_at INTEGER NOT NULL,
                nickname TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            """
        )
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS device_claims (
                claim_id TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                token_hash BLOB UNIQUE NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                consumed_at INTEGER,
                cancelled_at INTEGER,
                device_id TEXT,
                rejection_reason TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            """
        )
        # Additive compatibility with the earlier FloraOS enrollment handoff.
        # Never drop/recreate the table: a deployed database may already use
        # claim_id as the primary key and device_id as the consumed-device field.
        claim_columns = {
            row[1] for row in db.execute("PRAGMA table_info(device_claims)").fetchall()
        }
        if "device_id" not in claim_columns:
            db.execute("ALTER TABLE device_claims ADD COLUMN device_id TEXT")
            claim_columns.add("device_id")
        if "rejection_reason" not in claim_columns:
            db.execute("ALTER TABLE device_claims ADD COLUMN rejection_reason TEXT")

        db.execute(
            "CREATE INDEX IF NOT EXISTS idx_device_ownership_user "
            "ON device_ownership(user_id, claimed_at DESC)"
        )
        db.execute(
            "CREATE INDEX IF NOT EXISTS idx_device_claims_user_status "
            "ON device_claims(user_id, expires_at, consumed_at, cancelled_at)"
        )
        db.execute(
            "CREATE INDEX IF NOT EXISTS idx_device_claims_token_hash "
            "ON device_claims(token_hash)"
        )
        db.commit()


def init_enrollment_api(app, db_path: str | Path) -> None:
    resolved_db = Path(db_path)
    app.config["FLORAOS_DB_PATH"] = str(resolved_db)
    _init_tables(resolved_db)
    app.register_blueprint(enrollment_api)


def user_has_devices(user_id: int) -> bool:
    with _connect() as db:
        row = db.execute(
            "SELECT 1 FROM device_ownership WHERE user_id = ? LIMIT 1",
            (user_id,),
        ).fetchone()
    return row is not None


def owned_devices(user_id: int) -> list[dict[str, Any]]:
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
            (user_id,),
        ).fetchall()

    return [
        {
            "device_id": row["device_id"],
            "claimed_at": row["claimed_at"],
            "nickname": row["nickname"],
            "last_seen": row["last_seen"],
            "last_message_type": row["last_message_type"],
            "last_message_id": row["last_message_id"],
            "last_heartbeat_at": row["last_heartbeat_at"],
        }
        for row in rows
    ]


def consume_claim_in_transaction(
    db: sqlite3.Connection,
    *,
    device_id: str,
    token: str,
    now: int | None = None,
) -> dict[str, Any]:
    """Bind an already-authenticated FloraOS device to the token's user.

    This function must only be called *after* the existing FloraOS AES-GCM
    authentication/decryption has succeeded. It deliberately accepts the
    authenticated device_id from that layer instead of any browser input.

    The caller owns the surrounding SQLite transaction so the replay guard,
    claim consumption, ownership binding, and device-state update commit
    atomically together.
    """

    if not _valid_token(token):
        return {"ok": False, "error": "invalid_claim_token"}

    if not device_id or len(device_id) > 64:
        return {"ok": False, "error": "invalid_device_id"}

    if now is None:
        now = int(time.time())

    db.row_factory = sqlite3.Row
    claim = db.execute(
        """
        SELECT
            claim_id,
            user_id,
            created_at,
            expires_at,
            consumed_at,
            cancelled_at,
            device_id,
            rejection_reason
        FROM device_claims
        WHERE token_hash = ?
        """,
        (_token_hash(token),),
    ).fetchone()

    if claim is None:
        return {"ok": False, "error": "invalid_claim_token"}

    claim_id = str(claim["claim_id"])
    user_id = int(claim["user_id"])

    if claim["cancelled_at"] is not None:
        return {"ok": False, "reply_status": "cancelled", "claim_id": claim_id, "error": "claim_cancelled"}

    if claim["consumed_at"] is not None:
        # A response can be lost after the server commits the ownership bind.
        # If the *same authenticated physical device* retries the same claim
        # token with a fresh FloraOS message_id, return the prior success
        # idempotently. A different device can never reuse the consumed token.
        if claim["device_id"] == device_id and not claim["rejection_reason"]:
            return {
                "ok": True,
                "status": "already_claimed",
                "claim_id": claim_id,
                "device_id": device_id,
            }
        return {
            "ok": False,
            "reply_status": "consumed",
            "claim_id": claim_id,
            "error": "claim_already_used",
        }

    if int(claim["expires_at"]) < int(now):
        return {"ok": False, "reply_status": "expired", "claim_id": claim_id, "error": "claim_expired"}

    ownership = db.execute(
        "SELECT user_id FROM device_ownership WHERE device_id = ?",
        (device_id,),
    ).fetchone()

    if ownership is not None and int(ownership["user_id"]) != user_id:
        # The authenticated hardware is real, but it already belongs to a
        # different FloraCore account. Consume this one-time claim so it cannot
        # be replayed against another device.
        updated = db.execute(
            """
            UPDATE device_claims
            SET consumed_at = ?, rejection_reason = 'device_already_owned'
            WHERE claim_id = ? AND consumed_at IS NULL
            """,
            (int(now), claim_id),
        )
        if updated.rowcount != 1:
            return {"ok": False, "claim_id": claim_id, "error": "claim_already_used"}
        return {
            "ok": False,
            "claim_id": claim_id,
            "reply_status": "rejected",
            "error": "device_already_owned",
        }

    if ownership is None:
        try:
            db.execute(
                """
                INSERT INTO device_ownership(device_id, user_id, claimed_at)
                VALUES (?, ?, ?)
                """,
                (device_id, user_id, int(now)),
            )
        except sqlite3.IntegrityError:
            # Another transaction may have claimed the device while this
            # request was waiting for SQLite's writer lock. Re-read and apply
            # the same ownership rules deterministically.
            owner_after_race = db.execute(
                "SELECT user_id FROM device_ownership WHERE device_id = ?",
                (device_id,),
            ).fetchone()
            if owner_after_race is None or int(owner_after_race["user_id"]) != user_id:
                db.execute(
                    """
                    UPDATE device_claims
                    SET consumed_at = ?, rejection_reason = 'device_already_owned'
                    WHERE claim_id = ? AND consumed_at IS NULL
                    """,
                    (int(now), claim_id),
                )
                return {
                    "ok": False,
                    "claim_id": claim_id,
                    "reply_status": "rejected",
                    "error": "device_already_owned",
                }

    # Unowned devices are now bound. A device already belonging to the same
    # user is intentionally idempotent when presented with a *fresh* claim.
    updated = db.execute(
        """
        UPDATE device_claims
        SET consumed_at = ?, device_id = ?, rejection_reason = NULL
        WHERE claim_id = ? AND consumed_at IS NULL AND cancelled_at IS NULL
        """,
        (int(now), device_id, claim_id),
    )
    if updated.rowcount != 1:
        return {"ok": False, "claim_id": claim_id, "error": "claim_already_used"}

    # Keep the existing prompt-state table synchronized when it exists. Device
    # ownership remains the authoritative truth for application access.
    table_exists = db.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='user_onboarding'"
    ).fetchone()
    if table_exists is not None:
        db.execute(
            """
            INSERT INTO user_onboarding(user_id, connection_state, updated_at)
            VALUES (?, 'connected', ?)
            ON CONFLICT(user_id) DO UPDATE SET
                connection_state = 'connected',
                updated_at = excluded.updated_at
            """,
            (user_id, int(now)),
        )

    return {
        "ok": True,
        "claim_id": claim_id,
        "status": "claimed",
        "device_id": device_id,
    }


def _claim_status_payload(row: sqlite3.Row, *, user_id: int, now: int) -> dict[str, Any]:
    if row["rejection_reason"]:
        status = "rejected"
    elif row["consumed_at"] is not None and row["device_id"]:
        status = "claimed"
    elif row["cancelled_at"] is not None:
        status = "cancelled"
    elif int(row["expires_at"]) < now:
        status = "expired"
    else:
        status = "pending"

    result: dict[str, Any] = {
        "claim_id": row["claim_id"],
        "status": status,
        "created_at": int(row["created_at"]),
        "expires_at": int(row["expires_at"]),
        "seconds_remaining": max(0, int(row["expires_at"]) - now),
    }

    if status == "claimed" and row["device_id"]:
        with _connect() as db:
            owned = db.execute(
                """
                SELECT device_id, claimed_at, nickname
                FROM device_ownership
                WHERE device_id = ? AND user_id = ?
                """,
                (row["device_id"], user_id),
            ).fetchone()
        if owned is not None:
            result["device"] = {
                "device_id": owned["device_id"],
                "claimed_at": owned["claimed_at"],
                "nickname": owned["nickname"],
            }

    if status == "rejected":
        # Keep the browser message intentionally generic; it does not need to
        # learn whether a particular device belongs to someone else.
        result["error"] = "The device could not be linked to this account."

    return result


@enrollment_api.post("/api/device/claim/start")
def start_claim():
    login_error = _require_login_json()
    if login_error:
        return login_error
    csrf_error = _require_csrf_json()
    if csrf_error:
        return csrf_error

    user_id = int(session["user_id"])
    now = int(time.time())
    expires_at = now + CLAIM_TTL_SECONDS

    # Generate before opening the transaction. The raw token is returned once
    # to this logged-in browser but is never persisted or logged.
    token = secrets.token_urlsafe(CLAIM_TOKEN_BYTES)
    claim_id = secrets.token_urlsafe(CLAIM_ID_BYTES)
    digest = _token_hash(token)

    with _connect() as db:
        # Keep one active claim per account. Creating a new code cancels older
        # unused codes so the user cannot accidentally paste a stale one.
        db.execute(
            """
            UPDATE device_claims
            SET cancelled_at = ?
            WHERE user_id = ?
              AND consumed_at IS NULL
              AND cancelled_at IS NULL
              AND expires_at >= ?
            """,
            (now, user_id, now),
        )
        db.execute(
            """
            INSERT INTO device_claims(
                claim_id,
                user_id,
                token_hash,
                created_at,
                expires_at
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (claim_id, user_id, digest, now, expires_at),
        )
        db.commit()

    return jsonify(
        claim_id=claim_id,
        token=token,
        claim_command=f"claim {token}",
        created_at=now,
        expires_at=expires_at,
        ttl_seconds=CLAIM_TTL_SECONDS,
    ), 201


@enrollment_api.get("/api/device/claim/<claim_id>")
def claim_status(claim_id: str):
    login_error = _require_login_json()
    if login_error:
        return login_error

    user_id = int(session["user_id"])
    with _connect() as db:
        row = db.execute(
            """
            SELECT
                claim_id,
                user_id,
                created_at,
                expires_at,
                consumed_at,
                cancelled_at,
                device_id,
                rejection_reason
            FROM device_claims
            WHERE claim_id = ? AND user_id = ?
            """,
            (claim_id, user_id),
        ).fetchone()

    if row is None:
        # Claim IDs are scoped to the logged-in account. Do not reveal whether
        # another user's claim exists.
        return jsonify(error="Claim not found."), 404

    return jsonify(_claim_status_payload(row, user_id=user_id, now=int(time.time())))


@enrollment_api.post("/api/device/claim/<claim_id>/cancel")
def cancel_claim(claim_id: str):
    login_error = _require_login_json()
    if login_error:
        return login_error
    csrf_error = _require_csrf_json()
    if csrf_error:
        return csrf_error

    user_id = int(session["user_id"])
    now = int(time.time())
    with _connect() as db:
        row = db.execute(
            """
            SELECT consumed_at, cancelled_at
            FROM device_claims
            WHERE claim_id = ? AND user_id = ?
            """,
            (claim_id, user_id),
        ).fetchone()
        if row is None:
            return jsonify(error="Claim not found."), 404
        if row["consumed_at"] is not None:
            return jsonify(error="A consumed claim cannot be cancelled."), 409
        if row["cancelled_at"] is None:
            db.execute(
                """
                UPDATE device_claims
                SET cancelled_at = ?
                WHERE claim_id = ? AND user_id = ? AND consumed_at IS NULL
                """,
                (now, claim_id, user_id),
            )
            db.commit()

    return jsonify(status="cancelled", claim_id=claim_id)


@enrollment_api.get("/api/onboarding")
def onboarding_status():
    login_error = _require_login_json()
    if login_error:
        return login_error

    user_id = int(session["user_id"])
    now = int(time.time())
    devices = owned_devices(user_id)

    with _connect() as db:
        pending = db.execute(
            """
            SELECT claim_id, created_at, expires_at
            FROM device_claims
            WHERE user_id = ?
              AND consumed_at IS NULL
              AND cancelled_at IS NULL
              AND expires_at >= ?
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (user_id, now),
        ).fetchone()

        prompt_row = db.execute(
            "SELECT connection_state FROM user_onboarding WHERE user_id = ?",
            (user_id,),
        ).fetchone()

    connected = bool(devices)
    return jsonify(
        connected=connected,
        sidebar_mode="full" if connected else "connect_only",
        devices=devices,
        prompt_state=(prompt_row["connection_state"] if prompt_row else None),
        pending_claim=(
            {
                "claim_id": pending["claim_id"],
                "created_at": pending["created_at"],
                "expires_at": pending["expires_at"],
                "seconds_remaining": max(0, int(pending["expires_at"]) - now),
            }
            if pending is not None
            else None
        ),
    )
