from __future__ import annotations

from contextlib import closing
from pathlib import Path
from typing import Any
import json
import re
import sqlite3
import time

from flask import Blueprint, current_app, jsonify, request, session


PRODUCT = "FloraCore"
TARGET = "esp32s3"
PUBLIC_ORIGIN = "https://floraos.life"
SUPPORTED_CHANNELS = {"stable", "beta", "dev"}
OTA_STATUSES = {
    "offered",
    "downloading",
    "installed",
    "validated",
    "failed",
    "rolled_back",
}
OTA_TERMINAL_FAILURES = {"failed", "rolled_back"}
OTA_TERMINAL_STATUSES = {"validated", "failed", "rolled_back"}
BLOCKED_SETUP_STATES = {
    "SETUP_IDLE",
    "SETUP_CONNECTING",
    "SETUP_WIFI_CONNECTED",
    "SETUP_CLAIMING",
}

SEMVER_RE = re.compile(
    r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-([0-9A-Za-z.-]+))?"
    r"(?:\+[0-9A-Za-z.-]+)?$"
)

ota_api = Blueprint("floraos_ota", __name__)


def _db_path() -> Path:
    configured = current_app.config.get("FLORAOS_DB_PATH")
    if not configured:
        raise RuntimeError("FLORAOS_DB_PATH is not configured")
    return Path(configured)


def _firmware_root() -> Path:
    configured = current_app.config.get("FLORAOS_FIRMWARE_ROOT")
    if configured:
        return Path(configured)
    return Path(__file__).resolve().parent / "firmware" / "floracore"


def _public_origin() -> str:
    return str(current_app.config.get("FLORAOS_PUBLIC_ORIGIN", PUBLIC_ORIGIN)).rstrip("/")


def _connect_path(path: str | Path) -> sqlite3.Connection:
    db = sqlite3.connect(Path(path), timeout=5)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    db.execute("PRAGMA busy_timeout = 5000")
    return db


def _table_columns(db: sqlite3.Connection, table: str) -> set[str]:
    return {str(row["name"]) for row in db.execute(f"PRAGMA table_info({table})").fetchall()}


def init_ota_schema(db_path: str | Path) -> None:
    """Add OTA/release state without rebuilding any existing FloraOS tables."""
    with closing(_connect_path(db_path)) as db:
        # device_state is created here too so init order is safe. The private
        # device API's CREATE TABLE IF NOT EXISTS remains compatible.
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
        additive_columns = {
            "firmware_product": "TEXT",
            "firmware_target": "TEXT",
            "firmware_version": "TEXT",
            "firmware_channel": "TEXT",
            "firmware_reported_at": "INTEGER",
        }
        for name, definition in additive_columns.items():
            if name not in columns:
                db.execute(f"ALTER TABLE device_state ADD COLUMN {name} {definition}")

        db.execute(
            """
            CREATE TABLE IF NOT EXISTS firmware_releases (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                product TEXT NOT NULL,
                target TEXT NOT NULL,
                version TEXT NOT NULL,
                channel TEXT NOT NULL,
                binary_path TEXT NOT NULL,
                binary_url TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                byte_size INTEGER NOT NULL,
                released_at INTEGER NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                release_notes TEXT,
                signature TEXT,
                signature_algorithm TEXT,
                signing_key_id TEXT,
                UNIQUE(product, target, channel, version)
            )
            """
        )
        db.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_firmware_release_lookup
            ON firmware_releases(product, target, channel, enabled, released_at DESC)
            """
        )

        db.execute(
            """
            CREATE TABLE IF NOT EXISTS device_ota_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id TEXT NOT NULL,
                release_id INTEGER,
                from_version TEXT,
                target_version TEXT NOT NULL,
                started_at INTEGER,
                completed_at INTEGER,
                status TEXT NOT NULL,
                error TEXT,
                result TEXT,
                updated_at INTEGER NOT NULL,
                FOREIGN KEY (release_id) REFERENCES firmware_releases(id)
            )
            """
        )
        db.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_device_ota_history_device
            ON device_ota_history(device_id, updated_at DESC)
            """
        )
        db.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_device_ota_history_release
            ON device_ota_history(device_id, release_id, updated_at DESC)
            """
        )
        db.commit()


def init_ota(
    app,
    db_path: str | Path,
    firmware_root: str | Path | None = None,
    public_origin: str = PUBLIC_ORIGIN,
) -> None:
    resolved_db = Path(db_path)
    app.config["FLORAOS_DB_PATH"] = str(resolved_db)
    app.config["FLORAOS_FIRMWARE_ROOT"] = str(
        Path(firmware_root) if firmware_root else Path(app.root_path) / "firmware" / "floracore"
    )
    app.config["FLORAOS_PUBLIC_ORIGIN"] = public_origin.rstrip("/")
    init_ota_schema(resolved_db)
    app.register_blueprint(ota_api)


def _parse_semver(value: str) -> tuple[int, int, int, tuple[tuple[int, Any], ...]] | None:
    match = SEMVER_RE.fullmatch(str(value or "").strip())
    if not match:
        return None

    major, minor, patch = (int(match.group(i)) for i in (1, 2, 3))
    prerelease = match.group(4)

    # Stable releases sort after prereleases with the same numeric version.
    if prerelease is None:
        pre_key: tuple[tuple[int, Any], ...] = ((2, 0),)
    else:
        identifiers: list[tuple[int, Any]] = []
        for item in prerelease.split("."):
            if item.isdigit():
                identifiers.append((0, int(item)))
            else:
                identifiers.append((1, item))
        # Marker keeps a prerelease below the corresponding stable release.
        pre_key = tuple(identifiers) + ((-1, 0),)

    return major, minor, patch, pre_key


def compare_versions(left: str, right: str) -> int:
    """SemVer comparison. Returns -1, 0, +1."""
    a = _parse_semver(left)
    b = _parse_semver(right)
    if a is None or b is None:
        raise ValueError("Invalid semantic version")

    # Compare numeric triplet first.
    if a[:3] < b[:3]:
        return -1
    if a[:3] > b[:3]:
        return 1

    # Implement SemVer prerelease precedence precisely.
    a_match = SEMVER_RE.fullmatch(left.strip())
    b_match = SEMVER_RE.fullmatch(right.strip())
    assert a_match and b_match
    a_pre = a_match.group(4)
    b_pre = b_match.group(4)

    if a_pre is None and b_pre is None:
        return 0
    if a_pre is None:
        return 1
    if b_pre is None:
        return -1

    a_ids = a_pre.split(".")
    b_ids = b_pre.split(".")
    for x, y in zip(a_ids, b_ids):
        if x == y:
            continue
        x_num = x.isdigit()
        y_num = y.isdigit()
        if x_num and y_num:
            return -1 if int(x) < int(y) else 1
        if x_num != y_num:
            return -1 if x_num else 1
        return -1 if x < y else 1

    if len(a_ids) == len(b_ids):
        return 0
    return -1 if len(a_ids) < len(b_ids) else 1


def valid_semver(value: object) -> bool:
    return isinstance(value, str) and _parse_semver(value.strip()) is not None


def _clean_text(value: object, max_len: int) -> str | None:
    if not isinstance(value, str):
        return None
    cleaned = value.strip()
    if not cleaned or len(cleaned) > max_len:
        return None
    return cleaned


def update_device_firmware_state_in_transaction(
    db: sqlite3.Connection,
    *,
    device_id: str,
    message_type: str,
    payload: dict[str, Any],
    now: int,
) -> None:
    """Persist only firmware identity explicitly reported by authenticated firmware."""
    if message_type == "claim" or not isinstance(payload, dict):
        return

    firmware = payload.get("firmware")
    firmware = firmware if isinstance(firmware, dict) else {}

    product = _clean_text(payload.get("product"), 64) or _clean_text(
        firmware.get("product"), 64
    )
    target = _clean_text(payload.get("target"), 64) or _clean_text(
        firmware.get("target"), 64
    )
    version = _clean_text(payload.get("firmware_version"), 64) or _clean_text(
        firmware.get("version"), 64
    )
    channel = _clean_text(payload.get("firmware_channel"), 32) or _clean_text(
        firmware.get("channel"), 32
    )

    if version is not None and not valid_semver(version):
        version = None
    if channel is not None:
        channel = channel.lower()
        if channel not in SUPPORTED_CHANNELS:
            channel = None

    updates: list[str] = []
    values: list[Any] = []

    for column, value in (
        ("firmware_product", product),
        ("firmware_target", target),
        ("firmware_version", version),
        ("firmware_channel", channel),
    ):
        if value is not None:
            updates.append(f"{column} = ?")
            values.append(value)

    if not updates:
        return

    updates.append("firmware_reported_at = ?")
    values.append(int(now))
    values.append(device_id)

    db.execute(
        f"UPDATE device_state SET {', '.join(updates)} WHERE device_id = ?",
        tuple(values),
    )


def _setup_blocks_ota(payload: dict[str, Any]) -> bool:
    if not isinstance(payload, dict):
        return False

    for key in ("setup_state", "state", "mode"):
        raw = payload.get(key)
        if isinstance(raw, str) and raw.strip().upper() in BLOCKED_SETUP_STATES:
            return True
    return False


def _is_owned(db: sqlite3.Connection, device_id: str) -> bool:
    row = db.execute(
        "SELECT 1 FROM device_ownership WHERE device_id = ? LIMIT 1",
        (device_id,),
    ).fetchone()
    return row is not None


def _release_rows(
    db: sqlite3.Connection,
    *,
    product: str,
    target: str,
    channel: str,
) -> list[sqlite3.Row]:
    return db.execute(
        """
        SELECT
            id, product, target, version, channel, binary_path, binary_url,
            sha256, byte_size, released_at, enabled, release_notes,
            signature, signature_algorithm, signing_key_id
        FROM firmware_releases
        WHERE product = ? AND target = ? AND channel = ? AND enabled = 1
        """,
        (product, target, channel),
    ).fetchall()


def _best_newer_release(
    db: sqlite3.Connection,
    *,
    product: str,
    target: str,
    channel: str,
    current_version: str,
) -> sqlite3.Row | None:
    candidates: list[sqlite3.Row] = []
    for row in _release_rows(db, product=product, target=target, channel=channel):
        try:
            if compare_versions(str(row["version"]), current_version) > 0:
                candidates.append(row)
        except ValueError:
            continue

    if not candidates:
        return None

    best = candidates[0]
    for row in candidates[1:]:
        if compare_versions(str(row["version"]), str(best["version"])) > 0:
            best = row
    return best


def _latest_release_attempt(
    db: sqlite3.Connection,
    *,
    device_id: str,
    release_id: int,
) -> sqlite3.Row | None:
    return db.execute(
        """
        SELECT id, status, from_version, target_version, started_at,
               completed_at, error, result, updated_at
        FROM device_ota_history
        WHERE device_id = ? AND release_id = ?
        ORDER BY id DESC
        LIMIT 1
        """,
        (device_id, int(release_id)),
    ).fetchone()


def _offer_payload(row: sqlite3.Row) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "available": True,
        "version": str(row["version"]),
        "url": str(row["binary_url"]),
        "size": int(row["byte_size"]),
        "sha256": str(row["sha256"]),
    }
    if row["signature"]:
        payload["signature"] = str(row["signature"])
    if row["signature_algorithm"]:
        payload["signature_algorithm"] = str(row["signature_algorithm"])
    if row["signing_key_id"]:
        payload["signing_key_id"] = str(row["signing_key_id"])
    return payload


def _select_release_for_device(
    db: sqlite3.Connection,
    *,
    device_id: str,
) -> tuple[sqlite3.Row | None, sqlite3.Row | None]:
    state = db.execute(
        """
        SELECT firmware_product, firmware_target, firmware_version, firmware_channel
        FROM device_state
        WHERE device_id = ?
        """,
        (device_id,),
    ).fetchone()

    if state is None:
        return None, None

    product = _clean_text(state["firmware_product"], 64)
    target = _clean_text(state["firmware_target"], 64)
    version = _clean_text(state["firmware_version"], 64)
    channel = _clean_text(state["firmware_channel"], 32)

    if not product or not target or not version or not channel:
        return None, state
    if not valid_semver(version):
        return None, state

    channel = channel.lower()
    if channel not in SUPPORTED_CHANNELS:
        return None, state

    release = _best_newer_release(
        db,
        product=product,
        target=target,
        channel=channel,
        current_version=version,
    )
    return release, state


def build_ota_offer_in_transaction(
    db: sqlite3.Connection,
    *,
    device_id: str,
    message_type: str,
    payload: dict[str, Any],
    now: int,
    record_offer: bool = True,
) -> dict[str, Any]:
    """Choose an approved update for an authenticated, owned FloraCore."""
    unavailable = {"available": False}

    if message_type in {"claim", "ota_status"}:
        return unavailable
    if _setup_blocks_ota(payload):
        return unavailable
    if not _is_owned(db, device_id):
        return unavailable

    release, state = _select_release_for_device(db, device_id=device_id)
    if release is None or state is None:
        return unavailable

    # A failed/rolled-back release is not automatically hammered onto the same
    # device every heartbeat. A later release can still be offered normally.
    attempt = _latest_release_attempt(
        db,
        device_id=device_id,
        release_id=int(release["id"]),
    )
    if attempt is not None and str(attempt["status"]) in OTA_TERMINAL_STATUSES:
        return unavailable

    if record_offer:
        current_version = str(state["firmware_version"])
        if attempt is None:
            db.execute(
                """
                INSERT INTO device_ota_history(
                    device_id, release_id, from_version, target_version,
                    started_at, completed_at, status, error, result, updated_at
                ) VALUES (?, ?, ?, ?, ?, NULL, 'offered', NULL, NULL, ?)
                """,
                (
                    device_id,
                    int(release["id"]),
                    current_version,
                    str(release["version"]),
                    int(now),
                    int(now),
                ),
            )
        elif str(attempt["status"]) == "offered":
            db.execute(
                "UPDATE device_ota_history SET updated_at = ? WHERE id = ?",
                (int(now), int(attempt["id"])),
            )

    return _offer_payload(release)


def record_ota_status_in_transaction(
    db: sqlite3.Connection,
    *,
    device_id: str,
    payload: dict[str, Any],
    now: int,
) -> bool:
    """Record OTA progress reported through the authenticated device channel."""
    if not isinstance(payload, dict):
        return False

    status = _clean_text(payload.get("status"), 32)
    target_version = _clean_text(payload.get("target_version"), 64)
    from_version = _clean_text(payload.get("from_version"), 64)

    if status is None:
        return False
    status = status.lower()
    if status not in OTA_STATUSES:
        return False
    if target_version is None or not valid_semver(target_version):
        return False
    if from_version is not None and not valid_semver(from_version):
        from_version = None

    error = _clean_text(payload.get("error"), 512)

    raw_result = payload.get("result")
    if raw_result is None:
        result = None
    elif isinstance(raw_result, str):
        result = raw_result[:2000]
    else:
        try:
            result = json.dumps(
                raw_result,
                separators=(",", ":"),
                sort_keys=True,
            )[:2000]
        except (TypeError, ValueError):
            result = None

    release = db.execute(
        """
        SELECT r.id
        FROM firmware_releases AS r
        LEFT JOIN device_state AS s ON s.device_id = ?
        WHERE r.version = ?
          AND (s.firmware_product IS NULL OR r.product = s.firmware_product)
          AND (s.firmware_target IS NULL OR r.target = s.firmware_target)
          AND (s.firmware_channel IS NULL OR r.channel = s.firmware_channel)
        ORDER BY r.released_at DESC, r.id DESC
        LIMIT 1
        """,
        (device_id, target_version),
    ).fetchone()
    release_id = int(release["id"]) if release is not None else None

    history = None
    if release_id is not None:
        history = db.execute(
            """
            SELECT id, started_at
            FROM device_ota_history
            WHERE device_id = ? AND release_id = ?
            ORDER BY id DESC LIMIT 1
            """,
            (device_id, release_id),
        ).fetchone()

    if history is None:
        history = db.execute(
            """
            SELECT id, started_at
            FROM device_ota_history
            WHERE device_id = ? AND target_version = ?
            ORDER BY id DESC LIMIT 1
            """,
            (device_id, target_version),
        ).fetchone()

    completed_at = int(now) if status in OTA_TERMINAL_STATUSES else None

    if history is None:
        db.execute(
            """
            INSERT INTO device_ota_history(
                device_id, release_id, from_version, target_version,
                started_at, completed_at, status, error, result, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                device_id,
                release_id,
                from_version,
                target_version,
                int(now),
                completed_at,
                status,
                error,
                result,
                int(now),
            ),
        )
    else:
        db.execute(
            """
            UPDATE device_ota_history
            SET
                release_id = COALESCE(release_id, ?),
                from_version = COALESCE(?, from_version),
                started_at = COALESCE(started_at, ?),
                completed_at = ?,
                status = ?,
                error = ?,
                result = ?,
                updated_at = ?
            WHERE id = ?
            """,
            (
                release_id,
                from_version,
                int(now),
                completed_at,
                status,
                error,
                result,
                int(now),
                int(history["id"]),
            ),
        )
    return True


def register_release(
    db_path: str | Path,
    *,
    product: str,
    target: str,
    version: str,
    channel: str,
    binary_path: str,
    binary_url: str,
    sha256: str,
    byte_size: int,
    released_at: int | None = None,
    enabled: bool = True,
    release_notes: str | None = None,
) -> int:
    """Insert immutable release metadata. Existing release identities are not overwritten."""
    if not valid_semver(version):
        raise ValueError("version must be valid SemVer")
    channel = channel.strip().lower()
    if channel not in SUPPORTED_CHANNELS:
        raise ValueError("unsupported channel")
    if len(sha256) != 64 or any(c not in "0123456789abcdef" for c in sha256.lower()):
        raise ValueError("invalid SHA-256")
    if int(byte_size) <= 0:
        raise ValueError("invalid byte size")

    init_ota_schema(db_path)
    now = int(released_at if released_at is not None else time.time())

    with closing(_connect_path(db_path)) as db:
        try:
            cursor = db.execute(
                """
                INSERT INTO firmware_releases(
                    product, target, version, channel,
                    binary_path, binary_url, sha256, byte_size,
                    released_at, enabled, release_notes
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    product,
                    target,
                    version,
                    channel,
                    binary_path,
                    binary_url,
                    sha256.lower(),
                    int(byte_size),
                    now,
                    1 if enabled else 0,
                    release_notes,
                ),
            )
            db.commit()
        except sqlite3.IntegrityError as exc:
            db.rollback()
            raise ValueError(
                f"release already exists: {product}/{target}/{channel}/{version}"
            ) from exc
        return int(cursor.lastrowid)


def _session_user_id() -> int | None:
    raw = session.get("user_id")
    try:
        return int(raw) if raw is not None else None
    except (TypeError, ValueError):
        return None


@ota_api.get("/api/firmware/devices/<device_id>")
def device_firmware_summary(device_id: str):
    """Owner-scoped dashboard view. This endpoint never triggers an OTA."""
    user_id = _session_user_id()
    if user_id is None:
        return jsonify(error="Not authenticated."), 401
    if not device_id or len(device_id) > 64:
        return jsonify(error="Invalid device id."), 400

    with closing(_connect_path(_db_path())) as db:
        ownership = db.execute(
            """
            SELECT claimed_at, nickname
            FROM device_ownership
            WHERE device_id = ? AND user_id = ?
            """,
            (device_id, user_id),
        ).fetchone()
        if ownership is None:
            return jsonify(error="Device not found."), 404

        state = db.execute(
            """
            SELECT
                firmware_product,
                firmware_target,
                firmware_version,
                firmware_channel,
                firmware_reported_at
            FROM device_state
            WHERE device_id = ?
            """,
            (device_id,),
        ).fetchone()

        release, _ = _select_release_for_device(db, device_id=device_id)

        history_rows = db.execute(
            """
            SELECT
                h.from_version,
                h.target_version,
                h.started_at,
                h.completed_at,
                h.status,
                h.error,
                h.result,
                h.updated_at,
                r.version AS release_version,
                r.channel AS release_channel
            FROM device_ota_history AS h
            LEFT JOIN firmware_releases AS r ON r.id = h.release_id
            WHERE h.device_id = ?
            ORDER BY h.updated_at DESC, h.id DESC
            LIMIT 5
            """,
            (device_id,),
        ).fetchall()

        latest_attempt = history_rows[0] if history_rows else None
        release_blocked = False
        if release is not None:
            attempt = _latest_release_attempt(
                db,
                device_id=device_id,
                release_id=int(release["id"]),
            )
            release_blocked = (
                attempt is not None
                and str(attempt["status"]) in OTA_TERMINAL_FAILURES
            )

    installed = state["firmware_version"] if state else None
    channel = state["firmware_channel"] if state else None
    available = None if release is None or release_blocked else str(release["version"])

    if installed is None:
        status_text = "Awaiting firmware report"
    elif latest_attempt is not None and str(latest_attempt["status"]) in {"failed", "rolled_back"}:
        status_text = "Rolled back" if str(latest_attempt["status"]) == "rolled_back" else "Update failed"
    elif latest_attempt is not None and str(latest_attempt["status"]) in {"downloading", "installed"}:
        status_text = str(latest_attempt["status"]).replace("_", " ").title()
    elif available:
        status_text = "Update available"
    else:
        status_text = "Up to date"

    return jsonify(
        device_id=device_id,
        installed=installed,
        channel=channel,
        product=state["firmware_product"] if state else None,
        target=state["firmware_target"] if state else None,
        reported_at=state["firmware_reported_at"] if state else None,
        available=available,
        status=status_text,
        latest_release=(
            {
                "version": str(release["version"]),
                "channel": str(release["channel"]),
                "size": int(release["byte_size"]),
                "sha256": str(release["sha256"]),
                "released_at": int(release["released_at"]),
                "url": str(release["binary_url"]),
            }
            if release is not None and not release_blocked
            else None
        ),
        history=[
            {
                "from_version": row["from_version"],
                "target_version": row["target_version"],
                "started_at": row["started_at"],
                "completed_at": row["completed_at"],
                "status": row["status"],
                "error": row["error"],
                "result": row["result"],
                "updated_at": row["updated_at"],
                "channel": row["release_channel"],
            }
            for row in history_rows
        ],
    )
