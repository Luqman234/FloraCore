from __future__ import annotations

from contextlib import closing
from functools import wraps
from pathlib import Path
from typing import Any
import hashlib
import hmac
import ipaddress
import json
import os
import secrets
import sqlite3
import time

from flask import Blueprint, current_app, jsonify, redirect, render_template, request, session
from werkzeug.security import check_password_hash, generate_password_hash

from floraos_security_email import (
    SecurityEmailError,
    send_password_reset_otp,
    send_security_alert,
)


PASSWORD_MIN_LENGTH = 8
PASSWORD_MAX_LENGTH = 128

RESET_TTL_SECONDS = 10 * 60
RESET_MAX_ATTEMPTS = 5
RESET_RESEND_COOLDOWN_SECONDS = 60

SESSION_TOUCH_INTERVAL_SECONDS = 60
DEFAULT_SESSION_TTL_SECONDS = 7 * 24 * 60 * 60
PERMANENT_SESSION_TTL_SECONDS = 30 * 24 * 60 * 60

ONLINE_HEARTBEAT_MAX_AGE_SECONDS = 120

security_api = Blueprint("floraos_account_security", __name__)


def _db_path() -> Path:
    configured = current_app.config.get("FLORAOS_DB_PATH")
    if not configured:
        raise RuntimeError("FLORAOS_DB_PATH is not configured.")
    return Path(configured)


def _connect_path(path: str | Path) -> sqlite3.Connection:
    db = sqlite3.connect(Path(path), timeout=5)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    db.execute("PRAGMA busy_timeout = 5000")
    return db


def init_account_security_schema(db_path: str | Path) -> None:
    with closing(_connect_path(db_path)) as db:
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS account_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL UNIQUE,
                session_token_hash TEXT NOT NULL UNIQUE,
                user_id INTEGER NOT NULL,
                provider TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                last_seen_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                revoked_at INTEGER,
                revoked_reason TEXT,
                ip_address TEXT,
                user_agent TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            """
        )
        db.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_account_sessions_user_active
            ON account_sessions(user_id, revoked_at, expires_at, last_seen_at)
            """
        )

        db.execute(
            """
            CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                event_type TEXT NOT NULL,
                success INTEGER NOT NULL DEFAULT 1,
                ip_address TEXT,
                user_agent TEXT,
                details_json TEXT NOT NULL DEFAULT '{}',
                created_at INTEGER NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            """
        )
        db.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_security_events_user_time
            ON security_events(user_id, created_at DESC, id DESC)
            """
        )

        db.execute(
            """
            CREATE TABLE IF NOT EXISTS password_reset_challenges (
                challenge_hash TEXT PRIMARY KEY,
                user_id INTEGER,
                email TEXT NOT NULL,
                otp_hash TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                last_sent_at INTEGER NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            """
        )
        db.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_password_reset_expiry
            ON password_reset_challenges(expires_at)
            """
        )

        db.execute(
            """
            CREATE TABLE IF NOT EXISTS auth_rate_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scope TEXT NOT NULL,
                subject_hash TEXT,
                client_key TEXT NOT NULL,
                occurred_at INTEGER NOT NULL
            )
            """
        )
        db.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_auth_rate_scope_subject_time
            ON auth_rate_events(scope, subject_hash, occurred_at)
            """
        )
        db.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_auth_rate_scope_client_time
            ON auth_rate_events(scope, client_key, occurred_at)
            """
        )

        db.commit()


def init_account_security(app, db_path: str | Path) -> None:
    app.config["FLORAOS_DB_PATH"] = str(Path(db_path))
    app.config.setdefault(
        "SECURITY_SESSION_TTL_SECONDS",
        int(os.environ.get("SECURITY_SESSION_TTL_SECONDS", DEFAULT_SESSION_TTL_SECONDS)),
    )
    app.config.setdefault(
        "SECURITY_PERMANENT_SESSION_TTL_SECONDS",
        int(
            os.environ.get(
                "SECURITY_PERMANENT_SESSION_TTL_SECONDS",
                PERMANENT_SESSION_TTL_SECONDS,
            )
        ),
    )
    app.config.setdefault(
        "SECURITY_EMAIL_ALERTS",
        os.environ.get("SECURITY_EMAIL_ALERTS", "1").strip().lower()
        in {"1", "true", "yes", "on"},
    )

    init_account_security_schema(db_path)
    app.register_blueprint(security_api)

    @app.before_request
    def _enforce_registered_account_session():
        user_id = _session_user_id()
        if user_id is None:
            return None

        try:
            result = _validate_or_register_current_session(user_id)
        except sqlite3.Error:
            current_app.logger.exception("Account-session validation failed")
            return None

        if result == "revoked":
            session.clear()
            if request.path.startswith("/api/"):
                return jsonify(error="This session is no longer active."), 401
            return redirect("/login?session=revoked")

        return None

    @app.after_request
    def _security_event_hooks(response):
        try:
            if response.status_code < 400:
                _record_successful_security_endpoint_event()
        except Exception:
            current_app.logger.exception("Security event hook failed")
        return response


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


def _require_login_json():
    user_id = _session_user_id()
    if user_id is None:
        return None, (jsonify(error="Not authenticated."), 401)
    return user_id, None


def _require_csrf_json():
    if not _csrf_valid():
        return jsonify(error="Invalid or expired security token."), 403
    return None


def _settings_verified() -> bool:
    raw = session.get("mfa_settings_verified_until")
    try:
        return int(raw) >= int(time.time())
    except (TypeError, ValueError):
        return False


def _require_recent_security_verification():
    if not _settings_verified():
        return (
            jsonify(
                error="Verify this security change with the email security code first.",
                error_code="security_verification_required",
            ),
            403,
        )
    return None


def _normalize_email(value: object) -> str:
    return str(value or "").strip().lower()


def _client_ip() -> str:
    # Cloudflare Tunnel supplies this header. Fall back to remote_addr locally.
    value = request.headers.get("CF-Connecting-IP", "").strip()
    if not value:
        value = (request.remote_addr or "unknown").strip()
    return value[:64]


def _display_ip(value: str | None) -> str:
    raw = str(value or "")
    try:
        ip = ipaddress.ip_address(raw)
    except ValueError:
        return "Unknown"

    if isinstance(ip, ipaddress.IPv4Address):
        parts = raw.split(".")
        return ".".join(parts[:3] + ["×"]) if len(parts) == 4 else raw

    exploded = ip.exploded.split(":")
    return ":".join(exploded[:4]) + ":…"


def _user_agent() -> str:
    return request.headers.get("User-Agent", "")[:512]


def _user_agent_label(value: str | None) -> str:
    ua = str(value or "")
    if not ua:
        return "Unknown browser"

    browser = "Browser"
    if "Firefox/" in ua:
        browser = "Firefox"
    elif "Edg/" in ua:
        browser = "Edge"
    elif "Chrome/" in ua and "Chromium/" not in ua:
        browser = "Chrome"
    elif "Chromium/" in ua:
        browser = "Chromium"
    elif "Safari/" in ua and "Chrome/" not in ua:
        browser = "Safari"

    platform = ""
    if "Windows" in ua:
        platform = "Windows"
    elif "Android" in ua:
        platform = "Android"
    elif "iPhone" in ua or "iPad" in ua:
        platform = "iOS"
    elif "Macintosh" in ua:
        platform = "macOS"
    elif "Linux" in ua:
        platform = "Linux"

    return f"{browser} · {platform}" if platform else browser


def _server_hmac(namespace: str, value: str) -> str:
    secret = str(current_app.secret_key).encode("utf-8")
    message = f"floraos-security|{namespace}|{value}".encode("utf-8")
    return hmac.new(secret, message, hashlib.sha256).hexdigest()


def _session_token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _subject_hash(email: str) -> str:
    return _server_hmac("rate-subject", _normalize_email(email))


def _reset_otp_hash(email: str, otp: str) -> str:
    return _server_hmac("password-reset", f"{_normalize_email(email)}|{otp}")


def _password_error(password: str) -> str | None:
    if len(password) < PASSWORD_MIN_LENGTH:
        return f"Password must be at least {PASSWORD_MIN_LENGTH} characters."
    if len(password) > PASSWORD_MAX_LENGTH:
        return f"Password must be at most {PASSWORD_MAX_LENGTH} characters."
    return None


def _user_row(db: sqlite3.Connection, user_id: int) -> sqlite3.Row | None:
    return db.execute(
        "SELECT id, email, password_hash FROM users WHERE id = ? LIMIT 1",
        (int(user_id),),
    ).fetchone()


def _email_user_row(db: sqlite3.Connection, email: str) -> sqlite3.Row | None:
    return db.execute(
        "SELECT id, email, password_hash FROM users WHERE email = ? LIMIT 1",
        (_normalize_email(email),),
    ).fetchone()


def record_security_event(
    user_id: int,
    event_type: str,
    *,
    success: bool = True,
    details: dict[str, Any] | None = None,
    db: sqlite3.Connection | None = None,
) -> None:
    payload = json.dumps(details or {}, separators=(",", ":"), sort_keys=True)
    values = (
        int(user_id),
        str(event_type)[:80],
        1 if success else 0,
        _client_ip(),
        _user_agent(),
        payload[:8000],
        int(time.time()),
    )

    if db is not None:
        db.execute(
            """
            INSERT INTO security_events(
                user_id, event_type, success, ip_address, user_agent,
                details_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            values,
        )
        return

    with closing(_connect_path(_db_path())) as connection:
        connection.execute(
            """
            INSERT INTO security_events(
                user_id, event_type, success, ip_address, user_agent,
                details_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            values,
        )
        connection.commit()


def _best_effort_alert(
    user_id: int,
    *,
    title: str,
    summary: str,
    details: dict[str, str] | None = None,
) -> None:
    if not bool(current_app.config.get("SECURITY_EMAIL_ALERTS", True)):
        return

    try:
        with closing(_connect_path(_db_path())) as db:
            row = db.execute(
                "SELECT email FROM users WHERE id = ? LIMIT 1",
                (int(user_id),),
            ).fetchone()
        if row is None:
            return
        send_security_alert(
            str(row["email"]),
            title=title,
            summary=summary,
            details=details,
        )
    except SecurityEmailError:
        current_app.logger.warning("Security alert email delivery failed")
    except Exception:
        current_app.logger.exception("Unexpected security alert email failure")


def mark_new_session() -> None:
    """Call after primary+MFA authentication establishes a full session."""
    if _session_user_id() is not None:
        session["security_new_session"] = True


def _register_session(
    db: sqlite3.Connection,
    *,
    user_id: int,
    notify: bool,
) -> None:
    now = int(time.time())
    session_id = "sess_" + secrets.token_urlsafe(12)
    token = secrets.token_urlsafe(32)
    provider = str(session.get("auth_provider") or "unknown")[:40]

    ttl = (
        int(current_app.config["SECURITY_PERMANENT_SESSION_TTL_SECONDS"])
        if session.permanent
        else int(current_app.config["SECURITY_SESSION_TTL_SECONDS"])
    )

    db.execute(
        """
        INSERT INTO account_sessions(
            session_id, session_token_hash, user_id, provider,
            created_at, last_seen_at, expires_at, revoked_at,
            revoked_reason, ip_address, user_agent
        ) VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?, ?)
        """,
        (
            session_id,
            _session_token_hash(token),
            user_id,
            provider,
            now,
            now,
            now + ttl,
            _client_ip(),
            _user_agent(),
        ),
    )

    session["account_session_id"] = session_id
    session["account_session_token"] = token

    if notify:
        record_security_event(
            user_id,
            "new_session",
            details={"provider": provider},
            db=db,
        )

    db.commit()

    if notify:
        _best_effort_alert(
            user_id,
            title="New sign-in",
            summary="A new FloraCore session was created for your account.",
            details={
                "Browser": _user_agent_label(_user_agent()),
                "IP": _display_ip(_client_ip()),
                "Provider": provider,
            },
        )


def _validate_or_register_current_session(user_id: int) -> str:
    token = session.get("account_session_token")
    session_id = session.get("account_session_id")

    if not isinstance(token, str) or not token or not isinstance(session_id, str):
        notify = bool(session.pop("security_new_session", False))
        with closing(_connect_path(_db_path())) as db:
            _register_session(db, user_id=user_id, notify=notify)
        return "registered"

    now = int(time.time())
    with closing(_connect_path(_db_path())) as db:
        row = db.execute(
            """
            SELECT id, last_seen_at, expires_at, revoked_at
            FROM account_sessions
            WHERE session_id = ?
              AND session_token_hash = ?
              AND user_id = ?
            LIMIT 1
            """,
            (session_id, _session_token_hash(token), user_id),
        ).fetchone()

        if row is None or row["revoked_at"] is not None or int(row["expires_at"]) < now:
            return "revoked"

        if now - int(row["last_seen_at"]) >= SESSION_TOUCH_INTERVAL_SECONDS:
            db.execute(
                "UPDATE account_sessions SET last_seen_at = ? WHERE id = ?",
                (now, int(row["id"])),
            )
            db.commit()

    return "ok"


def revoke_current_session(*, reason: str = "logout") -> None:
    user_id = _session_user_id()
    session_id = session.get("account_session_id")
    if user_id is None or not isinstance(session_id, str):
        return

    with closing(_connect_path(_db_path())) as db:
        db.execute(
            """
            UPDATE account_sessions
            SET revoked_at = COALESCE(revoked_at, ?), revoked_reason = ?
            WHERE session_id = ? AND user_id = ?
            """,
            (int(time.time()), reason[:80], session_id, user_id),
        )
        db.commit()


def _revoke_all_sessions(
    db: sqlite3.Connection,
    *,
    user_id: int,
    except_session_id: str | None = None,
    reason: str,
) -> int:
    now = int(time.time())

    if except_session_id:
        cursor = db.execute(
            """
            UPDATE account_sessions
            SET revoked_at = COALESCE(revoked_at, ?), revoked_reason = ?
            WHERE user_id = ?
              AND session_id <> ?
              AND revoked_at IS NULL
            """,
            (now, reason[:80], int(user_id), except_session_id),
        )
    else:
        cursor = db.execute(
            """
            UPDATE account_sessions
            SET revoked_at = COALESCE(revoked_at, ?), revoked_reason = ?
            WHERE user_id = ? AND revoked_at IS NULL
            """,
            (now, reason[:80], int(user_id)),
        )

    return int(cursor.rowcount or 0)


def login_rate_guard(email: str) -> tuple[str, int] | None:
    """Additional account-aware throttling layered on top of app.py's IP limit."""
    now = int(time.time())
    client = _client_ip()
    subject = _subject_hash(email)

    with closing(_connect_path(_db_path())) as db:
        db.execute(
            "DELETE FROM auth_rate_events WHERE occurred_at < ?",
            (now - 24 * 60 * 60,),
        )

        account_count = int(
            db.execute(
                """
                SELECT COUNT(*) AS n
                FROM auth_rate_events
                WHERE scope = 'login_failed'
                  AND subject_hash = ?
                  AND occurred_at >= ?
                """,
                (subject, now - 15 * 60),
            ).fetchone()["n"]
        )

        pair_count = int(
            db.execute(
                """
                SELECT COUNT(*) AS n
                FROM auth_rate_events
                WHERE scope = 'login_failed'
                  AND subject_hash = ?
                  AND client_key = ?
                  AND occurred_at >= ?
                """,
                (subject, client, now - 5 * 60),
            ).fetchone()["n"]
        )

        ip_count = int(
            db.execute(
                """
                SELECT COUNT(*) AS n
                FROM auth_rate_events
                WHERE scope = 'login_failed'
                  AND client_key = ?
                  AND occurred_at >= ?
                """,
                (client, now - 15 * 60),
            ).fetchone()["n"]
        )
        db.commit()

    if account_count >= 8:
        return "Too many failed attempts for this account. Try again in 15 minutes.", 15 * 60
    if ip_count >= 25:
        return "Too many failed sign-in attempts from this network. Try again later.", 15 * 60
    if pair_count >= 5:
        return "Too many failed attempts. Wait a minute before trying again.", 60
    return None


def note_login_failure(email: str) -> None:
    now = int(time.time())
    normalized = _normalize_email(email)

    with closing(_connect_path(_db_path())) as db:
        db.execute(
            """
            INSERT INTO auth_rate_events(scope, subject_hash, client_key, occurred_at)
            VALUES ('login_failed', ?, ?, ?)
            """,
            (_subject_hash(normalized), _client_ip(), now),
        )

        user = _email_user_row(db, normalized)
        if user is not None:
            record_security_event(
                int(user["id"]),
                "login_failed",
                success=False,
                details={},
                db=db,
            )
        db.commit()


def note_login_success(email: str) -> None:
    with closing(_connect_path(_db_path())) as db:
        db.execute(
            """
            DELETE FROM auth_rate_events
            WHERE scope = 'login_failed'
              AND subject_hash = ?
              AND client_key = ?
            """,
            (_subject_hash(email), _client_ip()),
        )
        db.commit()


def _reset_rate_limited(email: str) -> bool:
    now = int(time.time())
    subject = _subject_hash(email)
    client = _client_ip()

    with closing(_connect_path(_db_path())) as db:
        subject_count = int(
            db.execute(
                """
                SELECT COUNT(*) AS n
                FROM auth_rate_events
                WHERE scope = 'password_reset'
                  AND subject_hash = ?
                  AND occurred_at >= ?
                """,
                (subject, now - 60 * 60),
            ).fetchone()["n"]
        )
        ip_count = int(
            db.execute(
                """
                SELECT COUNT(*) AS n
                FROM auth_rate_events
                WHERE scope = 'password_reset'
                  AND client_key = ?
                  AND occurred_at >= ?
                """,
                (client, now - 60 * 60),
            ).fetchone()["n"]
        )

    return subject_count >= 3 or ip_count >= 10


def _record_reset_rate(email: str) -> None:
    with closing(_connect_path(_db_path())) as db:
        db.execute(
            """
            INSERT INTO auth_rate_events(scope, subject_hash, client_key, occurred_at)
            VALUES ('password_reset', ?, ?, ?)
            """,
            (_subject_hash(email), _client_ip(), int(time.time())),
        )
        db.commit()


def _optional_turnstile(body: dict[str, Any], *, action: str):
    try:
        from floraos_turnstile import require_turnstile
    except ImportError:
        return None
    return require_turnstile(body, expected_action=action)


def _record_successful_security_endpoint_event() -> None:
    user_id = _session_user_id()
    if user_id is None:
        return

    path = request.path
    event = None
    alert = None

    if path == "/api/mfa/login/verify":
        body = request.get_json(silent=True) or {}
        event = "recovery_code_used" if body.get("recovery_code") else "mfa_verified"
    elif path == "/api/settings/mfa/email/enable":
        event = "mfa_enabled"
        alert = ("MFA enabled", "Email multi-factor authentication was enabled.")
    elif path == "/api/settings/mfa/authenticator/confirm":
        event = "mfa_enabled"
        alert = ("MFA enabled", "Authenticator multi-factor authentication was enabled.")
    elif path == "/api/settings/mfa/recovery/regenerate":
        event = "recovery_codes_regenerated"
        alert = ("Recovery codes changed", "Your FloraCore recovery codes were regenerated.")
    elif path == "/api/settings/mfa/disable":
        event = "mfa_disabled"
        alert = ("MFA disabled", "Multi-factor authentication was disabled.")

    if event is None:
        return

    record_security_event(user_id, event)

    if alert:
        _best_effort_alert(
            user_id,
            title=alert[0],
            summary=alert[1],
            details={
                "Browser": _user_agent_label(_user_agent()),
                "IP": _display_ip(_client_ip()),
            },
        )


@security_api.get("/forgot-password")
def forgot_password_page():
    if _session_user_id() is not None:
        return redirect("/settings#password")

    return render_template(
        "forgot_password.html",
        csrf_token=_ensure_csrf_token(),
    )


@security_api.post("/api/password-reset/start")
def password_reset_start():
    if not _csrf_valid():
        return jsonify(error="Invalid or expired security token."), 403

    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return jsonify(error="A JSON object is required."), 400

    captcha_error = _optional_turnstile(body, action="password_reset")
    if captcha_error:
        return captcha_error

    email = _normalize_email(body.get("email"))
    if not email or "@" not in email or len(email) > 254:
        # Keep the response generic for account-enumeration resistance.
        return jsonify(
            message="If that email belongs to a FloraCore account, a reset code will be sent."
        )

    if _reset_rate_limited(email):
        return jsonify(
            message="If that email belongs to a FloraCore account, a reset code will be sent."
        )

    _record_reset_rate(email)
    now = int(time.time())
    raw_challenge = secrets.token_urlsafe(32)
    challenge_hash = hashlib.sha256(raw_challenge.encode("utf-8")).hexdigest()
    otp = f"{secrets.randbelow(1_000_000):06d}"

    with closing(_connect_path(_db_path())) as db:
        db.execute(
            "DELETE FROM password_reset_challenges WHERE expires_at < ?",
            (now - 86400,),
        )
        user = _email_user_row(db, email)

        db.execute(
            """
            INSERT INTO password_reset_challenges(
                challenge_hash, user_id, email, otp_hash,
                created_at, expires_at, attempts, last_sent_at
            ) VALUES (?, ?, ?, ?, ?, ?, 0, ?)
            """,
            (
                challenge_hash,
                int(user["id"]) if user is not None else None,
                email,
                _reset_otp_hash(email, otp),
                now,
                now + RESET_TTL_SECONDS,
                now,
            ),
        )
        db.commit()

    session["password_reset_challenge"] = raw_challenge

    if user is not None:
        try:
            send_password_reset_otp(
                str(user["email"]),
                otp,
                expires_minutes=RESET_TTL_SECONDS // 60,
            )
            record_security_event(int(user["id"]), "password_reset_requested")
        except SecurityEmailError:
            current_app.logger.warning("Password reset email delivery failed")

    return jsonify(
        message="If that email belongs to a FloraCore account, a reset code will be sent.",
        expires_in=RESET_TTL_SECONDS,
    )


@security_api.post("/api/password-reset/complete")
def password_reset_complete():
    if not _csrf_valid():
        return jsonify(error="Invalid or expired security token."), 403

    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return jsonify(error="A JSON object is required."), 400

    code = "".join(ch for ch in str(body.get("code", "")) if ch.isdigit())
    new_password = str(body.get("new_password", ""))
    confirm_password = str(body.get("confirm_password", ""))

    if len(code) != 6:
        return jsonify(error="Enter the six-digit reset code."), 400

    password_problem = _password_error(new_password)
    if password_problem:
        return jsonify(error=password_problem), 400
    if new_password != confirm_password:
        return jsonify(error="Passwords do not match."), 400

    raw_challenge = session.get("password_reset_challenge")
    if not isinstance(raw_challenge, str) or not raw_challenge:
        return jsonify(error="Start a new password reset request."), 401

    challenge_hash = hashlib.sha256(raw_challenge.encode("utf-8")).hexdigest()
    now = int(time.time())

    with closing(_connect_path(_db_path())) as db:
        db.execute("BEGIN IMMEDIATE")
        challenge = db.execute(
            """
            SELECT *
            FROM password_reset_challenges
            WHERE challenge_hash = ?
            LIMIT 1
            """,
            (challenge_hash,),
        ).fetchone()

        if challenge is None:
            db.rollback()
            return jsonify(error="Start a new password reset request."), 401

        if int(challenge["expires_at"]) < now:
            db.execute(
                "DELETE FROM password_reset_challenges WHERE challenge_hash = ?",
                (challenge_hash,),
            )
            db.commit()
            session.pop("password_reset_challenge", None)
            return jsonify(error="This reset code expired. Request a new one."), 401

        if int(challenge["attempts"]) >= RESET_MAX_ATTEMPTS:
            db.execute(
                "DELETE FROM password_reset_challenges WHERE challenge_hash = ?",
                (challenge_hash,),
            )
            db.commit()
            session.pop("password_reset_challenge", None)
            return jsonify(error="Too many attempts. Request a new reset code."), 429

        expected = str(challenge["otp_hash"])
        supplied = _reset_otp_hash(str(challenge["email"]), code)
        user_id = challenge["user_id"]

        if user_id is None or not hmac.compare_digest(expected, supplied):
            db.execute(
                """
                UPDATE password_reset_challenges
                SET attempts = attempts + 1
                WHERE challenge_hash = ?
                """,
                (challenge_hash,),
            )
            db.commit()
            return jsonify(error="That reset code is not valid."), 401

        user = _user_row(db, int(user_id))
        if user is None:
            db.rollback()
            return jsonify(error="Unable to reset this account."), 409

        db.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (generate_password_hash(new_password, method="scrypt"), int(user_id)),
        )
        revoked = _revoke_all_sessions(
            db,
            user_id=int(user_id),
            reason="password_reset",
        )
        record_security_event(
            int(user_id),
            "password_reset_completed",
            details={"sessions_revoked": revoked},
            db=db,
        )
        db.execute(
            "DELETE FROM password_reset_challenges WHERE challenge_hash = ?",
            (challenge_hash,),
        )
        db.commit()

    session.clear()

    _best_effort_alert(
        int(user_id),
        title="Password reset completed",
        summary="Your FloraCore password was reset and all existing sessions were revoked.",
        details={
            "Browser": _user_agent_label(_user_agent()),
            "IP": _display_ip(_client_ip()),
        },
    )

    return jsonify(
        message="Password reset complete. Sign in with your new password.",
        redirect="/login",
    )


@security_api.post("/api/settings/password/change")
def settings_change_password():
    user_id, error = _require_login_json()
    if error:
        return error
    csrf_error = _require_csrf_json()
    if csrf_error:
        return csrf_error
    gate = _require_recent_security_verification()
    if gate:
        return gate

    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return jsonify(error="A JSON object is required."), 400

    current_password = str(body.get("current_password", ""))
    new_password = str(body.get("new_password", ""))
    confirm_password = str(body.get("confirm_password", ""))

    problem = _password_error(new_password)
    if problem:
        return jsonify(error=problem), 400
    if new_password != confirm_password:
        return jsonify(error="Passwords do not match."), 400

    with closing(_connect_path(_db_path())) as db:
        db.execute("BEGIN IMMEDIATE")
        user = _user_row(db, int(user_id))
        if user is None:
            db.rollback()
            return jsonify(error="Account not found."), 404

        provider = str(session.get("auth_provider") or "password")
        if provider == "password":
            if not current_password or not check_password_hash(
                str(user["password_hash"]),
                current_password,
            ):
                db.rollback()
                record_security_event(
                    int(user_id),
                    "password_change_failed",
                    success=False,
                )
                return jsonify(error="Current password is incorrect."), 401

        if current_password and check_password_hash(
            str(user["password_hash"]),
            new_password,
        ):
            db.rollback()
            return jsonify(error="Choose a password you are not already using."), 400

        db.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (generate_password_hash(new_password, method="scrypt"), int(user_id)),
        )

        current_session_id = session.get("account_session_id")
        revoked = _revoke_all_sessions(
            db,
            user_id=int(user_id),
            except_session_id=(
                str(current_session_id)
                if isinstance(current_session_id, str)
                else None
            ),
            reason="password_changed",
        )
        record_security_event(
            int(user_id),
            "password_changed",
            details={"other_sessions_revoked": revoked},
            db=db,
        )
        db.commit()

    _best_effort_alert(
        int(user_id),
        title="Password changed",
        summary="Your FloraCore password was changed.",
        details={
            "Other sessions revoked": str(revoked),
            "Browser": _user_agent_label(_user_agent()),
            "IP": _display_ip(_client_ip()),
        },
    )

    return jsonify(
        message="Password changed. Other sessions were revoked.",
        other_sessions_revoked=revoked,
    )


@security_api.get("/api/settings/sessions")
def settings_sessions():
    user_id, error = _require_login_json()
    if error:
        return error

    now = int(time.time())
    current_id = session.get("account_session_id")

    with closing(_connect_path(_db_path())) as db:
        rows = db.execute(
            """
            SELECT
                session_id, provider, created_at, last_seen_at, expires_at,
                ip_address, user_agent
            FROM account_sessions
            WHERE user_id = ?
              AND revoked_at IS NULL
              AND expires_at >= ?
            ORDER BY last_seen_at DESC, id DESC
            LIMIT 50
            """,
            (int(user_id), now),
        ).fetchall()

    return jsonify(
        data=[
            {
                "session_id": str(row["session_id"]),
                "current": str(row["session_id"]) == str(current_id),
                "provider": str(row["provider"]),
                "created_at": int(row["created_at"]),
                "last_seen_at": int(row["last_seen_at"]),
                "expires_at": int(row["expires_at"]),
                "ip": _display_ip(row["ip_address"]),
                "client": _user_agent_label(row["user_agent"]),
            }
            for row in rows
        ]
    )


@security_api.post("/api/settings/sessions/revoke")
def settings_revoke_session():
    user_id, error = _require_login_json()
    if error:
        return error
    csrf_error = _require_csrf_json()
    if csrf_error:
        return csrf_error
    gate = _require_recent_security_verification()
    if gate:
        return gate

    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return jsonify(error="A JSON object is required."), 400
    session_id = str(body.get("session_id", "")).strip()
    if not session_id.startswith("sess_") or len(session_id) > 128:
        return jsonify(error="Invalid session."), 400

    now = int(time.time())
    with closing(_connect_path(_db_path())) as db:
        row = db.execute(
            """
            SELECT session_id
            FROM account_sessions
            WHERE user_id = ? AND session_id = ? AND revoked_at IS NULL
            LIMIT 1
            """,
            (int(user_id), session_id),
        ).fetchone()
        if row is None:
            return jsonify(error="Session not found."), 404

        db.execute(
            """
            UPDATE account_sessions
            SET revoked_at = ?, revoked_reason = 'user_revoked'
            WHERE user_id = ? AND session_id = ?
            """,
            (now, int(user_id), session_id),
        )
        record_security_event(
            int(user_id),
            "session_revoked",
            details={"current": session_id == session.get("account_session_id")},
            db=db,
        )
        db.commit()

    current = session_id == session.get("account_session_id")
    if current:
        session.clear()

    return jsonify(
        message="Session revoked.",
        current=current,
        redirect="/login" if current else None,
    )


@security_api.post("/api/settings/sessions/revoke-others")
def settings_revoke_other_sessions():
    user_id, error = _require_login_json()
    if error:
        return error
    csrf_error = _require_csrf_json()
    if csrf_error:
        return csrf_error
    gate = _require_recent_security_verification()
    if gate:
        return gate

    current_id = session.get("account_session_id")
    with closing(_connect_path(_db_path())) as db:
        revoked = _revoke_all_sessions(
            db,
            user_id=int(user_id),
            except_session_id=str(current_id) if current_id else None,
            reason="user_revoked_others",
        )
        record_security_event(
            int(user_id),
            "other_sessions_revoked",
            details={"count": revoked},
            db=db,
        )
        db.commit()

    return jsonify(message="Other sessions revoked.", revoked=revoked)


@security_api.get("/api/settings/security/activity")
def settings_security_activity():
    user_id, error = _require_login_json()
    if error:
        return error

    try:
        limit = int(request.args.get("limit", "40"))
    except ValueError:
        limit = 40
    limit = max(1, min(limit, 100))

    with closing(_connect_path(_db_path())) as db:
        rows = db.execute(
            """
            SELECT event_type, success, ip_address, user_agent, details_json, created_at
            FROM security_events
            WHERE user_id = ?
            ORDER BY created_at DESC, id DESC
            LIMIT ?
            """,
            (int(user_id), limit),
        ).fetchall()

    data = []
    for row in rows:
        try:
            details = json.loads(str(row["details_json"]))
        except (TypeError, ValueError, json.JSONDecodeError):
            details = {}

        data.append(
            {
                "event_type": str(row["event_type"]),
                "success": bool(row["success"]),
                "ip": _display_ip(row["ip_address"]),
                "client": _user_agent_label(row["user_agent"]),
                "details": details if isinstance(details, dict) else {},
                "created_at": int(row["created_at"]),
            }
        )

    return jsonify(data=data)


@security_api.get("/api/settings/device-control/devices")
def settings_control_devices():
    user_id, error = _require_login_json()
    if error:
        return error

    now = int(time.time())
    with closing(_connect_path(_db_path())) as db:
        rows = db.execute(
            """
            SELECT device_id
            FROM device_ownership
            WHERE user_id = ?
            ORDER BY device_id
            """,
            (int(user_id),),
        ).fetchall()

        result = []
        for row in rows:
            device_id = str(row["device_id"])
            heartbeat = db.execute(
                """
                SELECT received_at
                FROM device_messages
                WHERE device_id = ? AND message_type = 'heartbeat'
                ORDER BY received_at DESC
                LIMIT 1
                """,
                (device_id,),
            ).fetchone()

            state = db.execute(
                """
                SELECT command_protocol
                FROM device_state
                WHERE device_id = ?
                LIMIT 1
                """,
                (device_id,),
            ).fetchone()

            age = (
                now - int(heartbeat["received_at"])
                if heartbeat is not None
                else None
            )
            result.append(
                {
                    "device_id": device_id,
                    "online": age is not None and 0 <= age <= ONLINE_HEARTBEAT_MAX_AGE_SECONDS,
                    "heartbeat_age_seconds": age,
                    "command_protocol": (
                        int(state["command_protocol"])
                        if state is not None and state["command_protocol"] is not None
                        else None
                    ),
                }
            )

    return jsonify(data=result)


@security_api.post("/api/settings/device-control/commands")
def settings_control_command():
    user_id, error = _require_login_json()
    if error:
        return error
    csrf_error = _require_csrf_json()
    if csrf_error:
        return csrf_error

    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return jsonify(error="A JSON object is required."), 400

    device_id = str(body.get("device_id", "")).strip()
    command_type = str(body.get("type", "")).strip()
    parameters = body.get("parameters")
    idempotency_key = str(body.get("idempotency_key", "")).strip()

    if command_type not in {"water", "grow_light"}:
        return jsonify(error="Only water and grow-light controls are available here."), 400

    try:
        from floraos_commands import (
            CommandValidationError,
            command_readiness,
            enqueue_command_in_transaction,
            validate_command,
            validate_idempotency_key,
            validate_ttl,
        )
    except ImportError:
        return jsonify(error="Device command support is unavailable."), 503

    try:
        validated_type, validated_parameters = validate_command(
            command_type,
            parameters,
        )
        validated_key = validate_idempotency_key(idempotency_key)
        ttl = validate_ttl(body.get("expires_in_seconds"))
    except CommandValidationError as exc:
        return jsonify(error=exc.message, error_code=exc.code), 400

    now = int(time.time())

    with closing(_connect_path(_db_path())) as db:
        try:
            db.execute("BEGIN IMMEDIATE")

            ownership = db.execute(
                """
                SELECT 1
                FROM device_ownership
                WHERE user_id = ? AND device_id = ?
                LIMIT 1
                """,
                (int(user_id), device_id),
            ).fetchone()
            if ownership is None:
                db.rollback()
                return jsonify(error="Device not found."), 404

            ready, reason = command_readiness(
                db,
                device_id=device_id,
                now=now,
                heartbeat_max_age_seconds=ONLINE_HEARTBEAT_MAX_AGE_SECONDS,
            )
            if not ready:
                db.rollback()
                messages = {
                    "device_offline": "Device is offline; the command was not queued.",
                    "command_protocol_unavailable": "This FloraCore has not reported command protocol v1.",
                    "ota_in_progress": "A firmware update is in progress.",
                }
                return (
                    jsonify(
                        error=messages.get(reason, "Device control is unavailable."),
                        error_code=reason or "control_unavailable",
                    ),
                    409,
                )

            command, created = enqueue_command_in_transaction(
                db,
                user_id=int(user_id),
                device_id=device_id,
                command_type=validated_type,
                parameters=validated_parameters,
                idempotency_key=validated_key,
                expires_in_seconds=ttl,
                now=now,
            )

            record_security_event(
                int(user_id),
                "device_command_queued",
                details={
                    "device_id": device_id,
                    "type": validated_type,
                },
                db=db,
            )
            db.commit()

        except CommandValidationError as exc:
            db.rollback()
            status = 429 if exc.code == "command_cooldown" else 409
            return jsonify(error=exc.message, error_code=exc.code), status
        except sqlite3.IntegrityError:
            db.rollback()
            return jsonify(
                error="The command could not be queued safely.",
                error_code="command_conflict",
            ), 409

    return jsonify(
        data={
            "command": command,
            "created": bool(created),
        }
    )
