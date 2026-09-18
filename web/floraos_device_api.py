from __future__ import annotations

import json
import os
import sqlite3
import time
from contextlib import closing
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import Blueprint, current_app, jsonify, request

from device_enrollment import consume_claim_in_transaction
from floraos_automations import (
    evaluate_automations_in_transaction,
    init_automation_schema,
)
from floraos_commands import (
    build_device_commands_in_transaction,
    init_command_schema,
    record_command_result_in_transaction,
    update_command_capability_in_transaction,
)
from floraos_web_phase20 import process_phase20_message_in_transaction
from floraos_ota import (
    build_ota_offer_in_transaction,
    record_ota_status_in_transaction,
    update_device_firmware_state_in_transaction,
)


PROTOCOL_VERSION = 1
PROTOCOL_LABEL = "floraos-e2ee-v1"
DEVICE_PATH = "/api/device/v1/message"
BASE_DIR = Path(__file__).resolve().parent

device_api = Blueprint("floraos_device_api", __name__)


def _db_path() -> Path:
    configured = current_app.config.get("FLORAOS_DB_PATH")
    if not configured:
        raise RuntimeError("FLORAOS_DB_PATH is not configured")
    return Path(configured)


def _registry_path() -> Path:
    configured = os.environ.get("FLORAOS_DEVICE_KEYS_FILE")
    if configured:
        return Path(configured)
    return BASE_DIR / "device_keys.json"


def _load_device_keys(device_id: str) -> tuple[bytes, bytes] | None:
    path = _registry_path()
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return None

    record = raw.get(device_id)
    if not isinstance(record, dict):
        return None

    try:
        d2s = bytes.fromhex(str(record["d2s_key"]))
        s2d = bytes.fromhex(str(record["s2d_key"]))
    except (KeyError, ValueError, TypeError):
        return None

    if len(d2s) != 32 or len(s2d) != 32:
        return None
    return d2s, s2d


def _aad(device_id: str, direction: str) -> bytes:
    return f"{PROTOCOL_LABEL}|{device_id}|{direction}|{DEVICE_PATH}".encode("utf-8")


def _encrypted_response(device_id: str, key: bytes, plaintext: dict[str, Any]):
    nonce = os.urandom(12)
    data = json.dumps(plaintext, separators=(",", ":"), sort_keys=True).encode("utf-8")
    ciphertext = AESGCM(key).encrypt(nonce, data, _aad(device_id, "s2d"))
    return jsonify(
        v=PROTOCOL_VERSION,
        device_id=device_id,
        nonce=nonce.hex(),
        ciphertext=ciphertext.hex(),
    )


def _init_tables(db_path: Path) -> None:
    with closing(sqlite3.connect(db_path, timeout=5)) as db:
        db.execute("PRAGMA foreign_keys = ON")
        db.execute("PRAGMA busy_timeout = 5000")
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS device_messages (
                device_id TEXT NOT NULL,
                message_id TEXT NOT NULL,
                message_type TEXT NOT NULL,
                client_ts INTEGER NOT NULL,
                received_at INTEGER NOT NULL,
                PRIMARY KEY (device_id, message_id)
            )
            """
        )
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS device_telemetry (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id TEXT NOT NULL,
                message_id TEXT NOT NULL,
                received_at INTEGER NOT NULL,
                payload_json TEXT NOT NULL
            )
            """
        )
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
        db.commit()


def init_device_api(app, db_path: str | Path) -> None:
    """Register the existing FloraOS E2EE endpoint.

    This preserves the established device-authentication model: the outer
    device ID selects server-side derived keys, AES-256-GCM authenticates the
    inner message, and (device_id, message_id) remains the replay guard.
    """
    resolved_db = Path(db_path)
    app.config["FLORAOS_DB_PATH"] = str(resolved_db)
    _init_tables(resolved_db)
    init_command_schema(resolved_db)
    init_automation_schema(resolved_db)
    app.register_blueprint(device_api)


@device_api.post(DEVICE_PATH)
def device_message():
    envelope = request.get_json(silent=True) or {}

    if envelope.get("v") != PROTOCOL_VERSION:
        return jsonify(error="Unsupported protocol version."), 400

    device_id = str(envelope.get("device_id", "")).strip()
    if not device_id or len(device_id) > 64:
        return jsonify(error="Invalid device id."), 400

    keys = _load_device_keys(device_id)
    if keys is None:
        # Keep 403 rather than 401: ESP-IDF may interpret 401 as an HTTP
        # authentication challenge before FloraOS can inspect the JSON body.
        current_app.logger.warning(
            "FloraOS device rejected: unknown/unprovisioned device_id=%s",
            device_id,
        )
        return jsonify(error="Device authentication failed."), 403

    d2s_key, s2d_key = keys

    try:
        nonce = bytes.fromhex(str(envelope.get("nonce", "")))
        ciphertext = bytes.fromhex(str(envelope.get("ciphertext", "")))
    except ValueError:
        return jsonify(error="Malformed encrypted envelope."), 400

    if len(nonce) != 12 or len(ciphertext) < 16 or len(ciphertext) > 16_384:
        return jsonify(error="Malformed encrypted envelope."), 400

    try:
        plaintext = AESGCM(d2s_key).decrypt(
            nonce,
            ciphertext,
            _aad(device_id, "d2s"),
        )
    except InvalidTag:
        current_app.logger.warning(
            "FloraOS device rejected: AES-GCM authentication failed for device_id=%s",
            device_id,
        )
        return jsonify(error="Device authentication failed."), 403

    try:
        message = json.loads(plaintext)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return jsonify(error="Invalid encrypted message."), 400

    if not isinstance(message, dict):
        return jsonify(error="Invalid encrypted message."), 400

    message_id = str(message.get("message_id", ""))
    message_type = str(message.get("type", ""))
    client_ts = message.get("ts", 0)
    payload = message.get("payload", {})

    if len(message_id) != 32 or any(c not in "0123456789abcdefABCDEF" for c in message_id):
        return _encrypted_response(
            device_id,
            s2d_key,
            {"ok": False, "error": "invalid_message_id"},
        )

    if not message_type or len(message_type) > 64:
        return _encrypted_response(
            device_id,
            s2d_key,
            {"ok": False, "reply_to": message_id, "error": "invalid_message_type"},
        )

    if not isinstance(client_ts, int):
        client_ts = 0

    if not isinstance(payload, dict):
        return _encrypted_response(
            device_id,
            s2d_key,
            {"ok": False, "reply_to": message_id, "error": "payload_must_be_object"},
        )

    received_at = int(time.time())
    special_response: dict[str, Any] | None = None
    ota_response: dict[str, Any] = {"available": False}
    command_response: list[dict[str, Any]] = []
    command_result_received: bool | None = None

    try:
        with closing(sqlite3.connect(_db_path(), timeout=5)) as db:
            db.row_factory = sqlite3.Row
            db.execute("PRAGMA foreign_keys = ON")
            db.execute("PRAGMA busy_timeout = 5000")

            # The unique (device_id, message_id) key is the existing replay
            # guard. Claim processing occurs only after this authenticated
            # message has been accepted into the same transaction.
            db.execute(
                """
                INSERT INTO device_messages(
                    device_id,
                    message_id,
                    message_type,
                    client_ts,
                    received_at
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (device_id, message_id, message_type, client_ts, received_at),
            )

            if message_type == "telemetry":
                db.execute(
                    """
                    INSERT INTO device_telemetry(
                        device_id,
                        message_id,
                        received_at,
                        payload_json
                    ) VALUES (?, ?, ?, ?)
                    """,
                    (
                        device_id,
                        message_id,
                        received_at,
                        json.dumps(payload, separators=(",", ":"), sort_keys=True),
                    ),
                )

            elif message_type == "claim":
                claim_token = payload.get("token", "")
                special_response = consume_claim_in_transaction(
                    db,
                    device_id=device_id,
                    token=claim_token if isinstance(claim_token, str) else "",
                    now=received_at,
                )
                special_response = {
                    "reply_to": message_id,
                    "server_time": received_at,
                    **special_response,
                }

                if special_response.get("ok"):
                    current_app.logger.info(
                        "FloraCore device claimed: device_id=%s claim_id=%s",
                        device_id,
                        special_response.get("claim_id"),
                    )
                else:
                    current_app.logger.warning(
                        "FloraCore claim rejected: device_id=%s error=%s",
                        device_id,
                        special_response.get("error"),
                    )

            db.execute(
                """
                INSERT INTO device_state(
                    device_id,
                    last_seen,
                    last_message_type,
                    last_message_id
                ) VALUES (?, ?, ?, ?)
                ON CONFLICT(device_id) DO UPDATE SET
                    last_seen = excluded.last_seen,
                    last_message_type = excluded.last_message_type,
                    last_message_id = excluded.last_message_id
                """,
                (device_id, received_at, message_type, message_id),
            )

            # Firmware identity and command capability are trusted only because
            # this message already passed device-key selection + AES-GCM auth.
            update_device_firmware_state_in_transaction(
                db,
                device_id=device_id,
                message_type=message_type,
                payload=payload,
                now=received_at,
            )
            update_command_capability_in_transaction(
                db,
                device_id=device_id,
                message_type=message_type,
                payload=payload,
                now=received_at,
            )

            # OTA and command-result status both come back through this same
            # authenticated device plane. No plaintext control/status endpoint.
            if message_type == "ota_status":
                record_ota_status_in_transaction(
                    db,
                    device_id=device_id,
                    payload=payload,
                    now=received_at,
                )

            if message_type == "command_result":
                command_result_received = record_command_result_in_transaction(
                    db,
                    device_id=device_id,
                    payload=payload,
                    now=received_at,
                )

            # Advanced-user automations are evaluated only after this message
            # has passed the existing device-key + AES-GCM authentication.
            # They do not control hardware directly: matching flows enqueue a
            # normal validated device_commands row, which is then delivered by
            # the same encrypted response path used by Public API v1.2.
            evaluate_automations_in_transaction(
                db,
                device_id=device_id,
                message_type=message_type,
                payload=payload,
                now=received_at,
            )

            # Physical commands are delivered at-least-once by command_id and
            # only to devices that explicitly reported command_protocol >= 1.
            # Setup/claim and active OTA phases are blocked by the selector.
            # Web intelligence hook: runs only after AES-GCM authentication/replay acceptance.
            process_phase20_message_in_transaction(
                db,
                device_id=device_id,
                message_type=message_type,
                payload=payload,
                now=received_at,
            )

            command_response = build_device_commands_in_transaction(
                db,
                device_id=device_id,
                message_type=message_type,
                payload=payload,
                now=received_at,
            )

            # Never offer an OTA in the same response that carries a physical
            # command. This prevents a command execution from racing an OTA reboot.
            if command_response:
                ota_response = {"available": False}
            else:
                ota_response = build_ota_offer_in_transaction(
                    db,
                    device_id=device_id,
                    message_type=message_type,
                    payload=payload,
                    now=received_at,
                )

            db.commit()

    except sqlite3.IntegrityError:
        return _encrypted_response(
            device_id,
            s2d_key,
            {
                "ok": False,
                "reply_to": message_id,
                "error": "replay_detected",
                "server_time": received_at,
            },
        )

    if special_response is not None:
        return _encrypted_response(device_id, s2d_key, special_response)

    return _encrypted_response(
        device_id,
        s2d_key,
        {
            "ok": True,
            "reply_to": message_id,
            "server_time": received_at,
            "commands": command_response,
            "ota": ota_response,
            **(
                {"command_result_received": command_result_received}
                if message_type == "command_result"
                else {}
            ),
        },
    )
