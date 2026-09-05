from __future__ import annotations

from contextlib import closing
from pathlib import Path
from typing import Any
import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import struct
import time
import urllib.parse

from cryptography.fernet import Fernet, InvalidToken
from flask import Blueprint, current_app, jsonify, redirect, render_template, request, session
from floraos_account_security import mark_new_session

from email_service import EmailDeliveryError, send_mfa_otp


MFA_LOGIN_TTL_SECONDS = 10 * 60
MFA_SETTINGS_TTL_SECONDS = 10 * 60
MFA_SETTINGS_VERIFIED_SECONDS = 10 * 60
MFA_MAX_ATTEMPTS = 5
MFA_RESEND_COOLDOWN_SECONDS = 60
MFA_MAX_RESENDS = 5
TOTP_PERIOD_SECONDS = 30
TOTP_DIGITS = 6
TOTP_WINDOW = 1
RECOVERY_CODE_COUNT = 8

mfa_api = Blueprint("floraos_mfa", __name__)


class MFAError(RuntimeError):
    def __init__(self, code: str, message: str, status: int = 400):
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status


def _db_path() -> Path:
    configured = current_app.config.get("FLORAOS_DB_PATH")
    if not configured:
        raise RuntimeError("FLORAOS_DB_PATH is not configured")
    return Path(configured)


def _mfa_key_path() -> Path:
    configured = current_app.config.get("FLORAOS_MFA_KEY_FILE")
    if configured:
        return Path(configured)
    return _db_path().resolve().parent / ".floracore_mfa_key"


def _decode_mfa_key_file(raw: bytes) -> bytes | None:
    # Preferred format: exactly 32 raw random bytes.
    #
    # Never .strip() raw cryptographic key material: random bytes may
    # legitimately begin/end with whitespace-valued bytes.
    if len(raw) == 32:
        return raw

    # Backward-compatible support for a textual urlsafe-base64 key.
    try:
        decoded = base64.urlsafe_b64decode(raw.strip())
    except Exception:
        return None
    return decoded if len(decoded) == 32 else None


def _load_or_create_key_bytes() -> bytes:
    path = _mfa_key_path()
    path.parent.mkdir(parents=True, exist_ok=True)

    if path.exists():
        raw = _decode_mfa_key_file(path.read_bytes())
        if raw is not None:
            return raw
        raise RuntimeError(
            "Invalid FloraOS MFA encryption key file. "
            f"Expected 32 raw bytes (or a valid base64-encoded 32-byte key) at {path}."
        )

    raw = secrets.token_bytes(32)

    # Atomic create prevents multiple Gunicorn workers from generating
    # different keys during the same startup.
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        for _ in range(50):
            try:
                existing = _decode_mfa_key_file(path.read_bytes())
            except OSError:
                existing = None
            if existing is not None:
                return existing
            time.sleep(0.01)
        raise RuntimeError("FloraOS MFA key was created concurrently but could not be read.")

    try:
        view = memoryview(raw)
        written = 0
        while written < len(view):
            written += os.write(fd, view[written:])
        os.fsync(fd)
    finally:
        os.close(fd)

    return raw


def _fernet() -> Fernet:
    return Fernet(base64.urlsafe_b64encode(_load_or_create_key_bytes()))


def _connect_path(path: str | Path) -> sqlite3.Connection:
    db = sqlite3.connect(Path(path), timeout=5)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    db.execute("PRAGMA busy_timeout = 5000")
    return db


def init_mfa_schema(db_path: str | Path) -> None:
    with closing(_connect_path(db_path)) as db:
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS user_mfa (
                user_id INTEGER PRIMARY KEY,
                enabled INTEGER NOT NULL DEFAULT 0,
                method TEXT,
                totp_secret_encrypted TEXT,
                totp_last_counter INTEGER,
                enabled_at INTEGER,
                updated_at INTEGER NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            """
        )
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS mfa_challenges (
                challenge_hash TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                purpose TEXT NOT NULL,
                method TEXT NOT NULL,
                otp_hash TEXT,
                provider TEXT,
                remember INTEGER NOT NULL DEFAULT 0,
                next_url TEXT,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                last_sent_at INTEGER,
                resend_count INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            """
        )
        db.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_mfa_challenges_user
            ON mfa_challenges(user_id, purpose, expires_at)
            """
        )
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS mfa_enrollments (
                user_id INTEGER PRIMARY KEY,
                secret_encrypted TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            """
        )
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS mfa_recovery_codes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                code_hash TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                used_at INTEGER,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                UNIQUE(user_id, code_hash)
            )
            """
        )
        db.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_mfa_recovery_user
            ON mfa_recovery_codes(user_id, used_at)
            """
        )
        db.commit()


def init_mfa(app, db_path: str | Path) -> None:
    resolved = Path(db_path)
    app.config["FLORAOS_DB_PATH"] = str(resolved)
    app.config.setdefault(
        "FLORAOS_MFA_KEY_FILE",
        str(resolved.resolve().parent / ".floracore_mfa_key"),
    )
    init_mfa_schema(resolved)
    with app.app_context():
        _load_or_create_key_bytes()
    app.register_blueprint(mfa_api)


@mfa_api.after_request
def _mfa_no_store(response):
    response.headers["Cache-Control"] = "no-store, max-age=0"
    response.headers["Pragma"] = "no-cache"
    return response


def _api_error(code: str, message: str, status: int):
    return jsonify(error={"code": code, "message": message}), status


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


def _safe_next_url(target: str | None) -> str:
    if (
        not isinstance(target, str)
        or not target.startswith("/")
        or target.startswith("//")
        or "\r" in target
        or "\n" in target
    ):
        return "/dashboard"
    return target


def _challenge_digest(raw_id: str) -> str:
    return hashlib.sha256(raw_id.encode("utf-8")).hexdigest()


def _peppered_digest(namespace: str, value: str) -> str:
    key = _load_or_create_key_bytes()
    return hmac.new(
        key,
        f"{namespace}|{value}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def _otp_digest(user_id: int, purpose: str, code: str) -> str:
    return _peppered_digest(f"otp|{int(user_id)}|{purpose}", code)


def _recovery_digest(user_id: int, code: str) -> str:
    normalized = code.replace("-", "").replace(" ", "").upper()
    return _peppered_digest(f"recovery|{int(user_id)}", normalized)


def _encrypt_secret(secret: str) -> str:
    return _fernet().encrypt(secret.encode("ascii")).decode("ascii")


def _decrypt_secret(token: str) -> str:
    try:
        return _fernet().decrypt(token.encode("ascii")).decode("ascii")
    except (InvalidToken, UnicodeError) as exc:
        raise RuntimeError("Unable to decrypt MFA secret.") from exc


def _generate_otp() -> str:
    return f"{secrets.randbelow(1_000_000):06d}"


def _new_challenge_id() -> str:
    return secrets.token_urlsafe(32)


def _masked_email(email: str) -> str:
    if "@" not in email:
        return "your email"
    local, domain = email.split("@", 1)
    if not local:
        return f"***@{domain}"
    visible = local[0]
    return f"{visible}{'*' * max(3, len(local) - 1)}@{domain}"


def _user_row(db: sqlite3.Connection, user_id: int) -> sqlite3.Row | None:
    return db.execute(
        "SELECT id, email FROM users WHERE id = ? LIMIT 1",
        (int(user_id),),
    ).fetchone()


def _mfa_row(db: sqlite3.Connection, user_id: int) -> sqlite3.Row | None:
    return db.execute(
        """
        SELECT
            user_id, enabled, method, totp_secret_encrypted,
            totp_last_counter, enabled_at, updated_at
        FROM user_mfa
        WHERE user_id = ?
        LIMIT 1
        """,
        (int(user_id),),
    ).fetchone()


def get_mfa_status(user_id: int) -> dict[str, Any]:
    with closing(_connect_path(_db_path())) as db:
        row = _mfa_row(db, user_id)

        recovery_remaining = db.execute(
            """
            SELECT COUNT(*) AS n
            FROM mfa_recovery_codes
            WHERE user_id = ? AND used_at IS NULL
            """,
            (int(user_id),),
        ).fetchone()["n"]

    return {
        "enabled": bool(row and row["enabled"]),
        "method": str(row["method"]) if row and row["enabled"] else None,
        "enabled_at": row["enabled_at"] if row and row["enabled"] else None,
        "recovery_codes_remaining": int(recovery_remaining),
    }


def _establish_session(
    user_id: int,
    email: str,
    *,
    provider: str,
    permanent: bool,
) -> None:
    session.clear()
    session["user_id"] = int(user_id)
    session["email"] = email
    session["auth_provider"] = provider
    session.permanent = bool(permanent)
    mark_new_session()


def _create_challenge(
    db: sqlite3.Connection,
    *,
    user_id: int,
    purpose: str,
    method: str,
    provider: str | None = None,
    remember: bool = False,
    next_url: str | None = None,
    send_email: bool = False,
) -> tuple[str, str | None]:
    raw_id = _new_challenge_id()
    challenge_hash = _challenge_digest(raw_id)
    now = int(time.time())
    ttl = MFA_LOGIN_TTL_SECONDS if purpose == "login" else MFA_SETTINGS_TTL_SECONDS
    otp = _generate_otp() if send_email else None
    otp_hash = _otp_digest(user_id, purpose, otp) if otp else None

    db.execute(
        """
        DELETE FROM mfa_challenges
        WHERE user_id = ? AND purpose = ?
        """,
        (int(user_id), purpose),
    )
    db.execute(
        """
        INSERT INTO mfa_challenges(
            challenge_hash, user_id, purpose, method, otp_hash,
            provider, remember, next_url, created_at, expires_at,
            attempts, last_sent_at, resend_count
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, 0)
        """,
        (
            challenge_hash,
            int(user_id),
            purpose,
            method,
            otp_hash,
            provider,
            1 if remember else 0,
            _safe_next_url(next_url),
            now,
            now + ttl,
            now if otp else None,
        ),
    )
    return raw_id, otp


def _challenge_from_session(
    db: sqlite3.Connection,
    *,
    purpose: str,
) -> sqlite3.Row | None:
    raw_id = session.get(f"mfa_{purpose}_challenge")
    if not isinstance(raw_id, str) or not raw_id:
        return None
    return db.execute(
        """
        SELECT *
        FROM mfa_challenges
        WHERE challenge_hash = ? AND purpose = ?
        LIMIT 1
        """,
        (_challenge_digest(raw_id), purpose),
    ).fetchone()


def _delete_challenge(
    db: sqlite3.Connection,
    *,
    purpose: str,
) -> None:
    raw_id = session.get(f"mfa_{purpose}_challenge")
    if isinstance(raw_id, str) and raw_id:
        db.execute(
            "DELETE FROM mfa_challenges WHERE challenge_hash = ?",
            (_challenge_digest(raw_id),),
        )
    session.pop(f"mfa_{purpose}_challenge", None)


def _totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def _decode_base32(secret: str) -> bytes:
    padding = "=" * ((8 - len(secret) % 8) % 8)
    return base64.b32decode((secret + padding).encode("ascii"), casefold=True)


def totp_code(secret: str, *, counter: int) -> str:
    key = _decode_base32(secret)
    message = struct.pack(">Q", int(counter))
    digest = hmac.new(key, message, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    binary = (
        ((digest[offset] & 0x7F) << 24)
        | ((digest[offset + 1] & 0xFF) << 16)
        | ((digest[offset + 2] & 0xFF) << 8)
        | (digest[offset + 3] & 0xFF)
    )
    return f"{binary % (10 ** TOTP_DIGITS):0{TOTP_DIGITS}d}"


def verify_totp(
    secret: str,
    code: str,
    *,
    now: int | None = None,
    last_counter: int | None = None,
) -> int | None:
    normalized = "".join(ch for ch in str(code) if ch.isdigit())
    if len(normalized) != TOTP_DIGITS:
        return None

    current = int((int(time.time()) if now is None else int(now)) // TOTP_PERIOD_SECONDS)
    for delta in range(-TOTP_WINDOW, TOTP_WINDOW + 1):
        counter = current + delta
        if last_counter is not None and counter <= int(last_counter):
            continue
        expected = totp_code(secret, counter=counter)
        if hmac.compare_digest(expected, normalized):
            return counter
    return None


def _otpauth_uri(email: str, secret: str) -> str:
    issuer = "FloraCore"
    label = urllib.parse.quote(f"{issuer}:{email}", safe="")
    query = urllib.parse.urlencode(
        {
            "secret": secret,
            "issuer": issuer,
            "algorithm": "SHA1",
            "digits": TOTP_DIGITS,
            "period": TOTP_PERIOD_SECONDS,
        }
    )
    return f"otpauth://totp/{label}?{query}"


def _new_recovery_codes() -> list[str]:
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    codes = []
    for _ in range(RECOVERY_CODE_COUNT):
        raw = "".join(secrets.choice(alphabet) for _ in range(12))
        codes.append(f"{raw[:4]}-{raw[4:8]}-{raw[8:]}")
    return codes


def _replace_recovery_codes(
    db: sqlite3.Connection,
    *,
    user_id: int,
) -> list[str]:
    codes = _new_recovery_codes()
    now = int(time.time())
    db.execute("DELETE FROM mfa_recovery_codes WHERE user_id = ?", (int(user_id),))
    db.executemany(
        """
        INSERT INTO mfa_recovery_codes(user_id, code_hash, created_at, used_at)
        VALUES (?, ?, ?, NULL)
        """,
        [
            (int(user_id), _recovery_digest(user_id, code), now)
            for code in codes
        ],
    )
    return codes


def _consume_recovery_code(
    db: sqlite3.Connection,
    *,
    user_id: int,
    code: str,
) -> bool:
    digest = _recovery_digest(user_id, code)
    row = db.execute(
        """
        SELECT id
        FROM mfa_recovery_codes
        WHERE user_id = ? AND code_hash = ? AND used_at IS NULL
        LIMIT 1
        """,
        (int(user_id), digest),
    ).fetchone()
    if row is None:
        return False
    db.execute(
        "UPDATE mfa_recovery_codes SET used_at = ? WHERE id = ?",
        (int(time.time()), int(row["id"])),
    )
    return True


def complete_primary_auth(
    user_id: int,
    email: str,
    *,
    provider: str,
    remember: bool = False,
    next_url: str = "/dashboard",
) -> dict[str, Any]:
    """
    Finish primary authentication, or create an MFA challenge if required.

    The caller has already verified the password/OAuth identity.
    """
    next_url = _safe_next_url(next_url)

    with closing(_connect_path(_db_path())) as db:
        mfa = _mfa_row(db, user_id)
        if mfa is None or not bool(mfa["enabled"]):
            _establish_session(
                int(user_id),
                email,
                provider=provider,
                permanent=remember,
            )
            return {
                "mfa_required": False,
                "redirect": next_url,
            }

        method = str(mfa["method"])
        if method not in {"email", "totp"}:
            raise RuntimeError("Unsupported MFA method.")

        raw_id, otp = _create_challenge(
            db,
            user_id=int(user_id),
            purpose="login",
            method=method,
            provider=provider,
            remember=remember,
            next_url=next_url,
            send_email=(method == "email"),
        )
        db.commit()

    if method == "email":
        assert otp is not None
        try:
            send_mfa_otp(
                email,
                otp,
                purpose="login",
                expires_minutes=MFA_LOGIN_TTL_SECONDS // 60,
            )
        except EmailDeliveryError:
            with closing(_connect_path(_db_path())) as db:
                db.execute(
                    "DELETE FROM mfa_challenges WHERE challenge_hash = ?",
                    (_challenge_digest(raw_id),),
                )
                db.commit()
            # Preserve the login page's existing CSRF session so the user can
            # retry without being forced through a mysterious refresh.
            raise

    # Clear any authenticated browser state only after all setup work that can
    # fail externally (such as SMTP delivery) has succeeded.
    session.clear()
    session["mfa_login_challenge"] = raw_id
    session["csrf_token"] = secrets.token_urlsafe(32)

    return {
        "mfa_required": True,
        "method": method,
        "redirect": "/mfa",
    }


def _settings_verified() -> bool:
    raw = session.get("mfa_settings_verified_until")
    try:
        return int(raw) >= int(time.time())
    except (TypeError, ValueError):
        return False


def _require_settings_verified():
    if not _settings_verified():
        return _api_error(
            "security_verification_required",
            "Verify this security change with a code sent to your email first.",
            403,
        )
    return None


@mfa_api.get("/mfa")
def mfa_page():
    if _session_user_id() is not None:
        return redirect("/dashboard")

    with closing(_connect_path(_db_path())) as db:
        challenge = _challenge_from_session(db, purpose="login")
        if (
            challenge is None
            or int(challenge["expires_at"]) < int(time.time())
            or int(challenge["attempts"]) >= MFA_MAX_ATTEMPTS
        ):
            return render_template(
                "mfa.html",
                expired=True,
                method=None,
                masked_email=None,
                csrf_token=_ensure_csrf_token(),
            )

        user = _user_row(db, int(challenge["user_id"]))
        if user is None:
            return redirect("/login")

    return render_template(
        "mfa.html",
        expired=False,
        method=str(challenge["method"]),
        masked_email=_masked_email(str(user["email"])),
        csrf_token=_ensure_csrf_token(),
    )


@mfa_api.post("/api/mfa/login/verify")
def verify_login_mfa():
    if not _csrf_valid():
        return _api_error("csrf_failed", "Invalid or expired security token.", 403)

    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return _api_error("invalid_request", "A JSON object is required.", 400)

    code = str(body.get("code", "")).strip()
    recovery_code = str(body.get("recovery_code", "")).strip()

    with closing(_connect_path(_db_path())) as db:
        challenge = _challenge_from_session(db, purpose="login")
        now = int(time.time())

        if challenge is None:
            return _api_error("mfa_challenge_missing", "Sign in again to continue.", 401)
        if int(challenge["expires_at"]) < now:
            _delete_challenge(db, purpose="login")
            db.commit()
            return _api_error("mfa_challenge_expired", "This verification session expired.", 401)
        if int(challenge["attempts"]) >= MFA_MAX_ATTEMPTS:
            _delete_challenge(db, purpose="login")
            db.commit()
            return _api_error("mfa_too_many_attempts", "Too many verification attempts.", 429)

        user_id = int(challenge["user_id"])
        user = _user_row(db, user_id)
        mfa = _mfa_row(db, user_id)
        if user is None or mfa is None or not bool(mfa["enabled"]):
            return _api_error("mfa_unavailable", "MFA is not available for this account.", 409)

        verified = False
        method = str(challenge["method"])

        if recovery_code:
            if method != "totp":
                return _api_error(
                    "recovery_not_available",
                    "Recovery codes are available only for authenticator MFA.",
                    400,
                )
            verified = _consume_recovery_code(
                db,
                user_id=user_id,
                code=recovery_code,
            )

        elif method == "email":
            expected = str(challenge["otp_hash"] or "")
            supplied = _otp_digest(user_id, "login", code)
            verified = bool(expected and hmac.compare_digest(expected, supplied))

        elif method == "totp":
            encrypted = mfa["totp_secret_encrypted"]
            if not encrypted:
                return _api_error("mfa_unavailable", "Authenticator MFA is not configured.", 409)
            secret = _decrypt_secret(str(encrypted))
            counter = verify_totp(
                secret,
                code,
                now=now,
                last_counter=mfa["totp_last_counter"],
            )
            if counter is not None:
                verified = True
                db.execute(
                    "UPDATE user_mfa SET totp_last_counter = ?, updated_at = ? WHERE user_id = ?",
                    (counter, now, user_id),
                )

        if not verified:
            db.execute(
                """
                UPDATE mfa_challenges
                SET attempts = attempts + 1
                WHERE challenge_hash = ?
                """,
                (_challenge_digest(str(session["mfa_login_challenge"])),),
            )
            db.commit()
            return _api_error("invalid_mfa_code", "That verification code is not valid.", 401)

        provider = str(challenge["provider"] or "password")
        remember = bool(challenge["remember"])
        next_url = _safe_next_url(challenge["next_url"])

        db.execute(
            "DELETE FROM mfa_challenges WHERE challenge_hash = ?",
            (_challenge_digest(str(session["mfa_login_challenge"])),),
        )
        db.commit()

    _establish_session(
        user_id,
        str(user["email"]),
        provider=provider,
        permanent=remember,
    )
    return jsonify(
        data={
            "verified": True,
            "redirect": next_url,
        }
    )


@mfa_api.post("/api/mfa/login/resend")
def resend_login_mfa():
    if not _csrf_valid():
        return _api_error("csrf_failed", "Invalid or expired security token.", 403)

    with closing(_connect_path(_db_path())) as db:
        challenge = _challenge_from_session(db, purpose="login")
        now = int(time.time())

        if challenge is None:
            return _api_error("mfa_challenge_missing", "Sign in again to continue.", 401)
        if str(challenge["method"]) != "email":
            return _api_error("resend_unavailable", "Authenticator codes are generated by your app.", 400)
        if int(challenge["expires_at"]) < now:
            return _api_error("mfa_challenge_expired", "This verification session expired.", 401)
        if int(challenge["resend_count"]) >= MFA_MAX_RESENDS:
            return _api_error("resend_limit", "Too many resend attempts.", 429)

        last_sent = int(challenge["last_sent_at"] or 0)
        remaining = MFA_RESEND_COOLDOWN_SECONDS - (now - last_sent)
        if remaining > 0:
            return _api_error(
                "resend_cooldown",
                f"Wait {remaining} seconds before requesting another code.",
                429,
            )

        user = _user_row(db, int(challenge["user_id"]))
        if user is None:
            return _api_error("account_not_found", "Account not found.", 404)

        otp = _generate_otp()
        challenge_hash = _challenge_digest(str(session["mfa_login_challenge"]))
        user_email = str(user["email"])
        user_id = int(challenge["user_id"])

    # Do not invalidate the previous still-valid code unless delivery succeeds.
    try:
        send_mfa_otp(
            user_email,
            otp,
            purpose="login",
            expires_minutes=MFA_LOGIN_TTL_SECONDS // 60,
        )
    except EmailDeliveryError:
        return _api_error(
            "email_delivery_failed",
            "FloraCore could not send another sign-in code. Try again shortly.",
            503,
        )

    with closing(_connect_path(_db_path())) as db:
        current = db.execute(
            """
            SELECT challenge_hash, expires_at
            FROM mfa_challenges
            WHERE challenge_hash = ? AND purpose = 'login'
            LIMIT 1
            """,
            (challenge_hash,),
        ).fetchone()
        if current is None:
            return _api_error("mfa_challenge_missing", "Sign in again to continue.", 401)

        now = int(time.time())
        db.execute(
            """
            UPDATE mfa_challenges
            SET
                otp_hash = ?,
                attempts = 0,
                last_sent_at = ?,
                resend_count = resend_count + 1,
                expires_at = ?
            WHERE challenge_hash = ?
            """,
            (
                _otp_digest(user_id, "login", otp),
                now,
                now + MFA_LOGIN_TTL_SECONDS,
                challenge_hash,
            ),
        )
        db.commit()

    return jsonify(data={"resent": True, "expires_in": MFA_LOGIN_TTL_SECONDS})


@mfa_api.get("/settings")
def settings_page():
    user_id = _session_user_id()
    if user_id is None:
        return redirect("/login?next=/settings")

    with closing(_connect_path(_db_path())) as db:
        user = _user_row(db, user_id)
        has_devices = (
            db.execute(
                """
                SELECT 1
                FROM device_ownership
                WHERE user_id = ?
                LIMIT 1
                """,
                (user_id,),
            ).fetchone()
            is not None
        )
    if user is None:
        session.clear()
        return redirect("/login")

    return render_template(
        "settings.html",
        user_id=user_id,
        user_email=str(user["email"]),
        csrf_token=_ensure_csrf_token(),
        mfa_status=get_mfa_status(user_id),
        security_verified=_settings_verified(),
        connect_only=not has_devices,
    )


@mfa_api.get("/api/settings/security")
def settings_security_status():
    user_id = _session_user_id()
    if user_id is None:
        return _api_error("not_authenticated", "Not authenticated.", 401)

    with closing(_connect_path(_db_path())) as db:
        user = _user_row(db, user_id)
    if user is None:
        return _api_error("account_not_found", "Account not found.", 404)

    return jsonify(
        data={
            "email": str(user["email"]),
            "masked_email": _masked_email(str(user["email"])),
            "security_verified": _settings_verified(),
            "mfa": get_mfa_status(user_id),
        }
    )


@mfa_api.post("/api/settings/security/send-code")
def settings_send_code():
    user_id = _session_user_id()
    if user_id is None:
        return _api_error("not_authenticated", "Not authenticated.", 401)
    if not _csrf_valid():
        return _api_error("csrf_failed", "Invalid or expired security token.", 403)

    with closing(_connect_path(_db_path())) as db:
        user = _user_row(db, user_id)
        if user is None:
            return _api_error("account_not_found", "Account not found.", 404)

        existing = _challenge_from_session(db, purpose="settings")
        now = int(time.time())
        if existing is not None:
            last_sent = int(existing["last_sent_at"] or 0)
            if now - last_sent < MFA_RESEND_COOLDOWN_SECONDS:
                remaining = MFA_RESEND_COOLDOWN_SECONDS - (now - last_sent)
                return _api_error(
                    "resend_cooldown",
                    f"Wait {remaining} seconds before requesting another code.",
                    429,
                )

        raw_id, otp = _create_challenge(
            db,
            user_id=user_id,
            purpose="settings",
            method="email",
            send_email=True,
        )
        db.commit()

    assert otp is not None
    try:
        send_mfa_otp(
            str(user["email"]),
            otp,
            purpose="settings",
            expires_minutes=MFA_SETTINGS_TTL_SECONDS // 60,
        )
    except EmailDeliveryError:
        with closing(_connect_path(_db_path())) as db:
            db.execute(
                "DELETE FROM mfa_challenges WHERE challenge_hash = ?",
                (_challenge_digest(raw_id),),
            )
            db.commit()
        return _api_error(
            "email_delivery_failed",
            "FloraCore could not send the security code. Try again shortly.",
            503,
        )
    session["mfa_settings_challenge"] = raw_id

    return jsonify(
        data={
            "sent": True,
            "masked_email": _masked_email(str(user["email"])),
            "expires_in": MFA_SETTINGS_TTL_SECONDS,
        }
    )


@mfa_api.post("/api/settings/security/verify-code")
def settings_verify_code():
    user_id = _session_user_id()
    if user_id is None:
        return _api_error("not_authenticated", "Not authenticated.", 401)
    if not _csrf_valid():
        return _api_error("csrf_failed", "Invalid or expired security token.", 403)

    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return _api_error("invalid_request", "A JSON object is required.", 400)
    code = str(body.get("code", "")).strip()

    with closing(_connect_path(_db_path())) as db:
        challenge = _challenge_from_session(db, purpose="settings")
        now = int(time.time())
        if challenge is None or int(challenge["user_id"]) != user_id:
            return _api_error("security_challenge_missing", "Request a new security code.", 401)
        if int(challenge["expires_at"]) < now:
            _delete_challenge(db, purpose="settings")
            db.commit()
            return _api_error("security_challenge_expired", "This security code expired.", 401)
        if int(challenge["attempts"]) >= MFA_MAX_ATTEMPTS:
            _delete_challenge(db, purpose="settings")
            db.commit()
            return _api_error("security_too_many_attempts", "Too many verification attempts.", 429)

        expected = str(challenge["otp_hash"] or "")
        supplied = _otp_digest(user_id, "settings", code)
        if not expected or not hmac.compare_digest(expected, supplied):
            db.execute(
                """
                UPDATE mfa_challenges
                SET attempts = attempts + 1
                WHERE challenge_hash = ?
                """,
                (_challenge_digest(str(session["mfa_settings_challenge"])),),
            )
            db.commit()
            return _api_error("invalid_security_code", "That security code is not valid.", 401)

        _delete_challenge(db, purpose="settings")
        db.commit()

    session["mfa_settings_verified_until"] = now + MFA_SETTINGS_VERIFIED_SECONDS
    return jsonify(
        data={
            "verified": True,
            "verified_for": MFA_SETTINGS_VERIFIED_SECONDS,
        }
    )


@mfa_api.post("/api/settings/mfa/email/enable")
def enable_email_mfa():
    user_id = _session_user_id()
    if user_id is None:
        return _api_error("not_authenticated", "Not authenticated.", 401)
    if not _csrf_valid():
        return _api_error("csrf_failed", "Invalid or expired security token.", 403)
    gate = _require_settings_verified()
    if gate:
        return gate

    now = int(time.time())
    with closing(_connect_path(_db_path())) as db:
        db.execute(
            """
            INSERT INTO user_mfa(
                user_id, enabled, method, totp_secret_encrypted,
                totp_last_counter, enabled_at, updated_at
            ) VALUES (?, 1, 'email', NULL, NULL, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                enabled = 1,
                method = 'email',
                totp_secret_encrypted = NULL,
                totp_last_counter = NULL,
                enabled_at = excluded.enabled_at,
                updated_at = excluded.updated_at
            """,
            (user_id, now, now),
        )
        db.execute("DELETE FROM mfa_enrollments WHERE user_id = ?", (user_id,))
        db.execute("DELETE FROM mfa_recovery_codes WHERE user_id = ?", (user_id,))
        db.commit()

    return jsonify(data={"enabled": True, "method": "email"})


@mfa_api.post("/api/settings/mfa/authenticator/start")
def start_authenticator_mfa():
    user_id = _session_user_id()
    if user_id is None:
        return _api_error("not_authenticated", "Not authenticated.", 401)
    if not _csrf_valid():
        return _api_error("csrf_failed", "Invalid or expired security token.", 403)
    gate = _require_settings_verified()
    if gate:
        return gate

    with closing(_connect_path(_db_path())) as db:
        user = _user_row(db, user_id)
        if user is None:
            return _api_error("account_not_found", "Account not found.", 404)

        secret = _totp_secret()
        now = int(time.time())
        db.execute(
            """
            INSERT INTO mfa_enrollments(user_id, secret_encrypted, created_at, expires_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                secret_encrypted = excluded.secret_encrypted,
                created_at = excluded.created_at,
                expires_at = excluded.expires_at
            """,
            (
                user_id,
                _encrypt_secret(secret),
                now,
                now + MFA_SETTINGS_TTL_SECONDS,
            ),
        )
        db.commit()

    return jsonify(
        data={
            "setup_key": secret,
            "otpauth_uri": _otpauth_uri(str(user["email"]), secret),
            "expires_in": MFA_SETTINGS_TTL_SECONDS,
        }
    )


@mfa_api.post("/api/settings/mfa/authenticator/confirm")
def confirm_authenticator_mfa():
    user_id = _session_user_id()
    if user_id is None:
        return _api_error("not_authenticated", "Not authenticated.", 401)
    if not _csrf_valid():
        return _api_error("csrf_failed", "Invalid or expired security token.", 403)
    gate = _require_settings_verified()
    if gate:
        return gate

    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return _api_error("invalid_request", "A JSON object is required.", 400)
    code = str(body.get("code", "")).strip()
    now = int(time.time())

    with closing(_connect_path(_db_path())) as db:
        enrollment = db.execute(
            """
            SELECT secret_encrypted, expires_at
            FROM mfa_enrollments
            WHERE user_id = ?
            LIMIT 1
            """,
            (user_id,),
        ).fetchone()
        if enrollment is None or int(enrollment["expires_at"]) < now:
            return _api_error(
                "authenticator_setup_expired",
                "Start authenticator setup again.",
                409,
            )

        secret = _decrypt_secret(str(enrollment["secret_encrypted"]))
        counter = verify_totp(secret, code, now=now)
        if counter is None:
            return _api_error(
                "invalid_authenticator_code",
                "That authenticator code is not valid.",
                401,
            )

        db.execute(
            """
            INSERT INTO user_mfa(
                user_id, enabled, method, totp_secret_encrypted,
                totp_last_counter, enabled_at, updated_at
            ) VALUES (?, 1, 'totp', ?, ?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                enabled = 1,
                method = 'totp',
                totp_secret_encrypted = excluded.totp_secret_encrypted,
                totp_last_counter = excluded.totp_last_counter,
                enabled_at = excluded.enabled_at,
                updated_at = excluded.updated_at
            """,
            (
                user_id,
                _encrypt_secret(secret),
                None,
                now,
                now,
            ),
        )
        recovery_codes = _replace_recovery_codes(db, user_id=user_id)
        db.execute("DELETE FROM mfa_enrollments WHERE user_id = ?", (user_id,))
        db.commit()

    return jsonify(
        data={
            "enabled": True,
            "method": "totp",
            "recovery_codes": recovery_codes,
        }
    )


@mfa_api.post("/api/settings/mfa/recovery/regenerate")
def regenerate_recovery_codes():
    user_id = _session_user_id()
    if user_id is None:
        return _api_error("not_authenticated", "Not authenticated.", 401)
    if not _csrf_valid():
        return _api_error("csrf_failed", "Invalid or expired security token.", 403)
    gate = _require_settings_verified()
    if gate:
        return gate

    with closing(_connect_path(_db_path())) as db:
        mfa = _mfa_row(db, user_id)
        if mfa is None or not bool(mfa["enabled"]) or str(mfa["method"]) != "totp":
            return _api_error(
                "recovery_unavailable",
                "Recovery codes require authenticator MFA.",
                409,
            )
        recovery_codes = _replace_recovery_codes(db, user_id=user_id)
        db.commit()

    return jsonify(data={"recovery_codes": recovery_codes})


@mfa_api.post("/api/settings/mfa/disable")
def disable_mfa():
    user_id = _session_user_id()
    if user_id is None:
        return _api_error("not_authenticated", "Not authenticated.", 401)
    if not _csrf_valid():
        return _api_error("csrf_failed", "Invalid or expired security token.", 403)
    gate = _require_settings_verified()
    if gate:
        return gate

    now = int(time.time())
    with closing(_connect_path(_db_path())) as db:
        db.execute(
            """
            INSERT INTO user_mfa(
                user_id, enabled, method, totp_secret_encrypted,
                totp_last_counter, enabled_at, updated_at
            ) VALUES (?, 0, NULL, NULL, NULL, NULL, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                enabled = 0,
                method = NULL,
                totp_secret_encrypted = NULL,
                totp_last_counter = NULL,
                enabled_at = NULL,
                updated_at = excluded.updated_at
            """,
            (user_id, now),
        )
        db.execute("DELETE FROM mfa_enrollments WHERE user_id = ?", (user_id,))
        db.execute("DELETE FROM mfa_recovery_codes WHERE user_id = ?", (user_id,))
        db.execute("DELETE FROM mfa_challenges WHERE user_id = ?", (user_id,))
        db.commit()

    session.pop("mfa_settings_verified_until", None)
    return jsonify(data={"enabled": False, "method": None})
