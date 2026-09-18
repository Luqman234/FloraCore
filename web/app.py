from __future__ import annotations

from datetime import timedelta
from functools import wraps
from contextlib import contextmanager
from pathlib import Path, PurePosixPath
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import time
from urllib.parse import urljoin, urlparse

from dotenv import load_dotenv
from authlib.integrations.base_client.errors import OAuthError
from authlib.integrations.flask_client import OAuth
from flask import Flask, jsonify, redirect, render_template, request, send_file, session, url_for
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash

from device_enrollment import init_enrollment_api, owned_devices, user_has_devices
from email_service import EmailDeliveryError, send_signup_otp
from floraos_turnstile import init_turnstile, require_turnstile
from floraos_mfa import complete_primary_auth, init_mfa
from floraos_automations import init_automations
from floraos_device_api import init_device_api
from floraos_account_security import init_account_security, login_rate_guard, mark_new_session, note_login_failure, note_login_success, revoke_current_session
from floraos_ota import init_ota
from floraos_public_api import init_public_api
from floraos_plants import init_plants
from floraos_web_phase20 import init_phase20

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")
DB_PATH = BASE_DIR / "users.db"
SECRET_FILE = BASE_DIR / ".floracore_secret"

# FloraCore OTA release files.
# The development channel is intentionally a stable URL:
#   https://floraos.life/firmware/floracore/dev/FloraCore.bin
FIRMWARE_DIR = BASE_DIR / "firmware" / "floracore"
FLORACORE_DEV_DIR = FIRMWARE_DIR / "dev"
FLORACORE_DEV_FIRMWARE = FLORACORE_DEV_DIR / "FloraCore.bin"

EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
PASSWORD_MIN_LENGTH = 8
PASSWORD_MAX_LENGTH = 128
COMMON_PASSWORDS = {
    "password",
    "password123",
    "123456789012",
    "qwerty123456",
    "letmein123456",
    "floracore123",
}

LOGIN_FAILURE_LIMIT = 5
LOGIN_WINDOW_SECONDS = 15 * 60
SIGNUP_LIMIT = 5
SIGNUP_WINDOW_SECONDS = 60 * 60
OTP_TTL_SECONDS = 10 * 60
OTP_MAX_ATTEMPTS = 5
OTP_RESEND_COOLDOWN_SECONDS = 60
OTP_RESEND_LIMIT = 10
OTP_RESEND_WINDOW_SECONDS = 60 * 60
OTP_VERIFY_LIMIT = 30
OTP_VERIFY_WINDOW_SECONDS = 15 * 60
OAUTH_START_LIMIT = 30
OAUTH_START_WINDOW_SECONDS = 10 * 60

SUPPORTED_OAUTH_PROVIDERS = {"google", "github"}


def env_flag(name: str, default: bool = False) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def load_secret_key() -> str:
    """Use SECRET_KEY when supplied; otherwise persist a private local key."""
    configured = os.environ.get("SECRET_KEY")
    if configured:
        return configured

    if SECRET_FILE.exists():
        return SECRET_FILE.read_text(encoding="utf-8").strip()

    secret = secrets.token_hex(32)
    SECRET_FILE.write_text(secret, encoding="utf-8")
    try:
        os.chmod(SECRET_FILE, 0o600)
    except OSError:
        pass
    return secret


app = Flask(__name__)
app.secret_key = load_secret_key()

# Only trust forwarded headers when you explicitly enable this for your
# Cloudflare Tunnel / reverse-proxy deployment.
if env_flag("FLORACORE_TRUST_PROXY"):
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

secure_cookies = env_flag("FLORACORE_SECURE_COOKIES")
public_base_url = os.environ.get("FLORACORE_PUBLIC_URL", "").strip().rstrip("/")

app.config.update(
    SESSION_COOKIE_NAME="floracore_session",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=secure_cookies,
    PERMANENT_SESSION_LIFETIME=timedelta(days=30),
    SESSION_REFRESH_EACH_REQUEST=False,
    MAX_CONTENT_LENGTH=64 * 1024,
    GOOGLE_CLIENT_ID=os.environ.get("GOOGLE_CLIENT_ID", ""),
    GOOGLE_CLIENT_SECRET=os.environ.get("GOOGLE_CLIENT_SECRET", ""),
    GITHUB_CLIENT_ID=os.environ.get("GITHUB_CLIENT_ID", ""),
    GITHUB_CLIENT_SECRET=os.environ.get("GITHUB_CLIENT_SECRET", ""),
)

# Used to keep invalid-email and invalid-password login paths closer in cost.
DUMMY_PASSWORD_HASH = generate_password_hash(secrets.token_urlsafe(32), method="scrypt")


def oauth_provider_configured(provider: str) -> bool:
    provider = provider.lower()
    if provider == "google":
        return bool(app.config["GOOGLE_CLIENT_ID"] and app.config["GOOGLE_CLIENT_SECRET"])
    if provider == "github":
        return bool(app.config["GITHUB_CLIENT_ID"] and app.config["GITHUB_CLIENT_SECRET"])
    return False


oauth = OAuth(app)

if oauth_provider_configured("google"):
    oauth.register(
        name="google",
        server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
        client_kwargs={"scope": "openid email profile"},
    )

if oauth_provider_configured("github"):
    oauth.register(
        name="github",
        access_token_url="https://github.com/login/oauth/access_token",
        authorize_url="https://github.com/login/oauth/authorize",
        api_base_url="https://api.github.com/",
        client_kwargs={"scope": "read:user user:email", "code_challenge_method": "S256"},
    )


@contextmanager
def get_db():
    connection = sqlite3.connect(DB_PATH, timeout=5)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 5000")
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def init_db() -> None:
    with get_db() as db:
        db.execute("PRAGMA journal_mode = WAL")
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at INTEGER NOT NULL DEFAULT (unixepoch())
            )
            """
        )
        # Additive schema upgrade: older FloraCore databases predate explicit
        # email-verification tracking. Existing accounts remain usable; new
        # password accounts are only created after OTP verification.
        user_columns = {row["name"] for row in db.execute("PRAGMA table_info(users)").fetchall()}
        if "email_verified_at" not in user_columns:
            db.execute("ALTER TABLE users ADD COLUMN email_verified_at INTEGER")

        # Pending password signups are intentionally separate from users. A
        # high-entropy signup ID binds the password hash to the browser that
        # initiated that signup, so another person cannot overwrite a pending
        # password simply by requesting a code for the same email address.
        pending_columns = {row["name"] for row in db.execute("PRAGMA table_info(pending_signups)").fetchall()}
        if pending_columns and "signup_id_hash" not in pending_columns:
            # Safe transient-state migration from an earlier development schema.
            # No verified account lives in this table.
            db.execute("DROP TABLE pending_signups")

        db.execute(
            """
            CREATE TABLE IF NOT EXISTS pending_signups (
                signup_id_hash TEXT PRIMARY KEY,
                email TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                otp_hash TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                last_sent_at INTEGER NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        db.execute(
            "CREATE INDEX IF NOT EXISTS idx_pending_signups_email "
            "ON pending_signups(email)"
        )
        db.execute(
            "CREATE INDEX IF NOT EXISTS idx_pending_signups_expires "
            "ON pending_signups(expires_at)"
        )

        db.execute(
            """
            CREATE TABLE IF NOT EXISTS oauth_identities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                provider TEXT NOT NULL,
                provider_user_id TEXT NOT NULL,
                user_id INTEGER NOT NULL,
                email_at_link TEXT NOT NULL,
                created_at INTEGER NOT NULL DEFAULT (unixepoch()),
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                UNIQUE(provider, provider_user_id),
                UNIQUE(provider, user_id)
            )
            """
        )
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS user_onboarding (
                user_id INTEGER PRIMARY KEY,
                connection_state TEXT NOT NULL DEFAULT 'pending',
                updated_at INTEGER NOT NULL DEFAULT (unixepoch()),
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                CHECK (connection_state IN ('pending', 'deferred', 'connect_started', 'connected'))
            )
            """
        )
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS rate_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scope TEXT NOT NULL,
                client_key TEXT NOT NULL,
                occurred_at REAL NOT NULL
            )
            """
        )
        db.execute(
            "CREATE INDEX IF NOT EXISTS idx_rate_events_scope_key_time "
            "ON rate_events(scope, client_key, occurred_at)"
        )
        db.execute(
            "CREATE INDEX IF NOT EXISTS idx_oauth_identities_user "
            "ON oauth_identities(user_id)"
        )

        # Upgrade safety: remove the old known demo account only when it still
        # uses the original public demo password.
        demo = db.execute(
            "SELECT id, password_hash FROM users WHERE email = ?",
            ("admin@example.com",),
        ).fetchone()
        if demo and check_password_hash(demo["password_hash"], "password123"):
            db.execute("DELETE FROM users WHERE id = ?", (demo["id"],))

        db.commit()

    try:
        os.chmod(DB_PATH, 0o600)
    except OSError:
        pass


init_db()
init_mfa(app, DB_PATH)
init_turnstile(app)
init_account_security(app, DB_PATH)

# Device enrollment extends the existing FloraOS E2EE channel. Initialize the
# ownership tables before registering the encrypted device blueprint so an
# authenticated inner message with type="claim" can bind account ownership.
init_enrollment_api(app, DB_PATH)
# OTA schema/release metadata is additive and the selector is consumed by the
# existing encrypted private device API.
init_ota(app, DB_PATH, firmware_root=FIRMWARE_DIR, public_origin="https://floraos.life")
init_automations(app, DB_PATH)
init_device_api(app, DB_PATH)
# Public user/application API. This is separate from the private ESP32 plane.
init_public_api(app, DB_PATH)


init_plants(app, DB_PATH)
init_phase20(app, DB_PATH)
def normalize_email(value: object) -> str:
    return str(value or "").strip().lower()


def valid_email(email: str) -> bool:
    return 3 <= len(email) <= 254 and EMAIL_RE.fullmatch(email) is not None


def password_error(password: str) -> str | None:
    if len(password) < PASSWORD_MIN_LENGTH:
        return f"Password must be at least {PASSWORD_MIN_LENGTH} characters."
    if len(password) > PASSWORD_MAX_LENGTH:
        return f"Password must be at most {PASSWORD_MAX_LENGTH} characters."
    # Common-password detection is a client-side advisory meter only.
    # Server-side signup enforces length, not "uncommon" composition.
    return None


def generate_signup_otp() -> str:
    """Generate a cryptographically-random six-digit email OTP."""
    return f"{secrets.randbelow(1_000_000):06d}"


def signup_otp_hash(email: str, otp: str) -> str:
    """Protect the low-entropy OTP with a server-side HMAC pepper."""
    key = str(app.secret_key).encode("utf-8")
    message = f"floracore-signup-otp\x00{normalize_email(email)}\x00{otp}".encode("utf-8")
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def signup_id_hash(signup_id: str) -> str:
    """Hash a 256-bit pending-signup identifier before database storage."""
    return hashlib.sha256(signup_id.encode("utf-8")).hexdigest()


def masked_email(email: str) -> str:
    local, sep, domain = email.partition("@")
    if not sep:
        return email
    if len(local) <= 2:
        masked_local = local[:1] + "*"
    else:
        masked_local = local[:2] + "*" * min(6, len(local) - 2)
    return f"{masked_local}@{domain}"


def client_key() -> str:
    # request.remote_addr respects ProxyFix only when FLORACORE_TRUST_PROXY=1.
    return request.remote_addr or "unknown"


def rate_limited(scope: str, limit: int, window_seconds: int) -> bool:
    cutoff = time.time() - window_seconds
    key = client_key()
    with get_db() as db:
        db.execute("DELETE FROM rate_events WHERE occurred_at < ?", (time.time() - 86400,))
        count = db.execute(
            "SELECT COUNT(*) AS n FROM rate_events "
            "WHERE scope = ? AND client_key = ? AND occurred_at >= ?",
            (scope, key, cutoff),
        ).fetchone()["n"]
        db.commit()
    return count >= limit


def record_rate_event(scope: str) -> None:
    with get_db() as db:
        db.execute(
            "INSERT INTO rate_events(scope, client_key, occurred_at) VALUES (?, ?, ?)",
            (scope, client_key(), time.time()),
        )
        db.commit()


def clear_rate_events(scope: str) -> None:
    with get_db() as db:
        db.execute(
            "DELETE FROM rate_events WHERE scope = ? AND client_key = ?",
            (scope, client_key()),
        )
        db.commit()


def csrf_token() -> str:
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


def csrf_valid() -> bool:
    supplied = request.headers.get("X-CSRF-Token", "")
    expected = session.get("csrf_token", "")
    return bool(supplied and expected and hmac.compare_digest(supplied, expected))


def require_csrf():
    if not csrf_valid():
        return jsonify(error="Invalid or expired security token. Refresh the page and try again."), 403
    return None


def is_safe_next_url(target: str | None) -> bool:
    if not target:
        return False
    host_url = request.host_url
    test_url = urlparse(urljoin(host_url, target))
    reference_url = urlparse(host_url)
    return test_url.scheme in {"http", "https"} and test_url.netloc == reference_url.netloc


def oauth_callback_url(provider: str) -> str:
    path = url_for("oauth_callback", provider=provider)
    if public_base_url:
        return f"{public_base_url}{path}"
    return url_for("oauth_callback", provider=provider, _external=True)


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            if session.get("mfa_login_challenge"):
                return redirect("/mfa")
            next_url = request.full_path if request.query_string else request.path
            return redirect(url_for("login_page", next=next_url))
        return view(*args, **kwargs)

    return wrapped


def establish_session(user_id: int, email: str, *, provider: str, permanent: bool = False) -> None:
    session.clear()
    session["user_id"] = user_id
    session["email"] = email
    session["auth_provider"] = provider
    session.permanent = permanent
    mark_new_session()


def create_onboarding_record(db: sqlite3.Connection, user_id: int) -> None:
    """Mark a newly-created account as needing first-device onboarding."""
    db.execute(
        "INSERT OR IGNORE INTO user_onboarding(user_id, connection_state) VALUES (?, 'pending')",
        (user_id,),
    )


def get_onboarding_state(user_id: int) -> str | None:
    with get_db() as db:
        row = db.execute(
            "SELECT connection_state FROM user_onboarding WHERE user_id = ?",
            (user_id,),
        ).fetchone()
    return str(row["connection_state"]) if row else None


def set_onboarding_state(user_id: int, state: str) -> None:
    allowed = {"pending", "deferred", "connect_started", "connected"}
    if state not in allowed:
        raise ValueError("Invalid onboarding state")
    with get_db() as db:
        db.execute(
            """
            INSERT INTO user_onboarding(user_id, connection_state, updated_at)
            VALUES (?, ?, unixepoch())
            ON CONFLICT(user_id) DO UPDATE SET
                connection_state = excluded.connection_state,
                updated_at = excluded.updated_at
            """,
            (user_id, state),
        )
        db.commit()


def find_or_create_oauth_user(provider: str, provider_user_id: str, email: str) -> sqlite3.Row:
    """Find/link an OAuth identity using a provider-verified email.

    OAuth access tokens are deliberately not stored. The stable provider user ID
    is saved so future logins do not depend on the provider email staying the same.
    """
    with get_db() as db:
        existing = db.execute(
            """
            SELECT u.id, u.email
            FROM oauth_identities oi
            JOIN users u ON u.id = oi.user_id
            WHERE oi.provider = ? AND oi.provider_user_id = ?
            """,
            (provider, provider_user_id),
        ).fetchone()
        if existing:
            return existing

        user = db.execute(
            "SELECT id, email FROM users WHERE email = ?",
            (email,),
        ).fetchone()

        if user is None:
            # The user authenticates through the external identity provider. We
            # still keep password_hash NOT NULL for backward compatibility with
            # the existing users table; this random credential is never shown or
            # accepted by any user.
            unusable_password = generate_password_hash(secrets.token_urlsafe(64), method="scrypt")
            cursor = db.execute(
                "INSERT INTO users(email, password_hash, email_verified_at) "
                "VALUES (?, ?, unixepoch())",
                (email, unusable_password),
            )
            user_id = int(cursor.lastrowid)
            create_onboarding_record(db, user_id)
        else:
            user_id = int(user["id"])
            # The provider has just proven control of this same verified email.
            db.execute(
                "UPDATE users SET email_verified_at = COALESCE(email_verified_at, unixepoch()) WHERE id = ?",
                (user_id,),
            )

        try:
            db.execute(
                """
                INSERT INTO oauth_identities(provider, provider_user_id, user_id, email_at_link)
                VALUES (?, ?, ?, ?)
                """,
                (provider, provider_user_id, user_id, email),
            )
            db.commit()
        except sqlite3.IntegrityError:
            db.rollback()
            # A concurrent callback may have created the identity first.
            linked = db.execute(
                """
                SELECT u.id, u.email
                FROM oauth_identities oi
                JOIN users u ON u.id = oi.user_id
                WHERE oi.provider = ? AND oi.provider_user_id = ?
                """,
                (provider, provider_user_id),
            ).fetchone()
            if linked:
                return linked
            raise

        return db.execute(
            "SELECT id, email FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()


def google_identity(token: dict) -> tuple[str, str]:
    userinfo = token.get("userinfo") or {}
    provider_user_id = str(userinfo.get("sub") or "").strip()
    email = normalize_email(userinfo.get("email"))
    verified = userinfo.get("email_verified") in {True, "true", "1", 1}

    if not provider_user_id or not valid_email(email) or not verified:
        raise ValueError("Google did not return a verified identity.")
    return provider_user_id, email


def github_identity(remote) -> tuple[str, str]:
    profile_response = remote.get("user")
    profile_response.raise_for_status()
    profile = profile_response.json()
    provider_user_id = str(profile.get("id") or "").strip()

    email_response = remote.get("user/emails")
    email_response.raise_for_status()
    emails = email_response.json()

    verified_emails = [
        item for item in emails
        if item.get("verified") is True and valid_email(normalize_email(item.get("email")))
    ]
    primary = next((item for item in verified_emails if item.get("primary") is True), None)
    chosen = primary or (verified_emails[0] if verified_emails else None)
    email = normalize_email(chosen.get("email")) if chosen else ""

    if not provider_user_id or not email:
        raise ValueError("GitHub did not return a verified email address.")
    return provider_user_id, email



def file_sha256(path: Path) -> str:
    """Return SHA-256 for a file without loading the whole firmware into RAM."""
    digest = hashlib.sha256()
    with path.open("rb") as firmware:
        for chunk in iter(lambda: firmware.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


@app.after_request
def security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; "
        "script-src 'self' https://challenges.cloudflare.com; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self' https://challenges.cloudflare.com; "
        "frame-src https://challenges.cloudflare.com; "
        "font-src 'self'; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "frame-ancestors 'none'; "
        "form-action 'self' https://accounts.google.com https://github.com",
    )

    if request.path.startswith("/api/") or request.path in {
        "/login", "/signup", "/dashboard", "/connect", "/settings/developer", "/automations"
    } or request.path.startswith("/auth/") or request.path.startswith("/firmware/"):
        response.headers.setdefault("Cache-Control", "no-store")

    if secure_cookies:
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

    return response



@app.get("/firmware/floracore/<path:artifact_path>")
def floracore_firmware_artifact(artifact_path: str):
    """
    Safe Gunicorn fallback for approved firmware artifacts.

    Production should let nginx serve /firmware/ directly from disk. This
    fallback keeps OTA functional before that cutover and never lists folders.
    """
    parts = tuple(PurePosixPath(artifact_path).parts)

    allowed = False
    immutable = False

    # Mutable development pointer:
    #   dev/FloraCore.bin
    if parts == ("dev", "FloraCore.bin"):
        allowed = True

    # Immutable development archive:
    #   dev/releases/<version>/FloraCore.bin
    elif (
        len(parts) == 4
        and parts[0] == "dev"
        and parts[1] == "releases"
        and parts[3] == "FloraCore.bin"
    ):
        allowed = True
        immutable = True

    # Immutable beta/stable releases:
    #   stable/<version>/FloraCore.bin
    #   beta/<version>/FloraCore.bin
    elif (
        len(parts) == 3
        and parts[0] in {"stable", "beta"}
        and parts[2] == "FloraCore.bin"
    ):
        allowed = True
        immutable = True

    if not allowed or any(part in {"", ".", ".."} for part in parts):
        return jsonify(
            error={
                "code": "firmware_not_found",
                "message": "Firmware artifact not found.",
            }
        ), 404

    firmware_path = (FIRMWARE_DIR / Path(*parts)).resolve()
    firmware_root = FIRMWARE_DIR.resolve()

    try:
        firmware_path.relative_to(firmware_root)
    except ValueError:
        return jsonify(
            error={
                "code": "firmware_not_found",
                "message": "Firmware artifact not found.",
            }
        ), 404

    if not firmware_path.is_file():
        return jsonify(
            error={
                "code": "firmware_not_available",
                "message": "Firmware artifact is not available.",
            }
        ), 404

    response = send_file(
        firmware_path,
        mimetype="application/octet-stream",
        as_attachment=False,
        download_name="FloraCore.bin",
        conditional=True,
        etag=True,
        last_modified=firmware_path.stat().st_mtime,
    )

    # Version-addressed artifacts are immutable. The dev pointer intentionally
    # revalidates so a new test image is visible immediately.
    if immutable:
        response.headers["Cache-Control"] = "public, max-age=31536000, immutable"
    else:
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"

    return response


@app.get("/")
def landing_page():
    hostname = request.host.partition(":")[0].lower()
    if hostname == "about.floraos.life":
        return render_template("about.html")
    return render_template("landing.html")


@app.get("/login")
def login_page():
    if "user_id" in session:
        return redirect(url_for("dashboard_page"))

    next_url = request.args.get("next")
    if not is_safe_next_url(next_url):
        next_url = "/dashboard"

    oauth_error_provider = request.args.get("oauth_error", "").lower()
    oauth_error = None
    if oauth_error_provider in SUPPORTED_OAUTH_PROVIDERS:
        oauth_error = (
            f"{oauth_error_provider.title()} sign-in could not be completed. "
            "Please try again or use email and password."
        )

    return render_template(
        "login.html",
        csrf_token=csrf_token(),
        next_url=next_url,
        oauth_error=oauth_error,
        oauth_configured={
            "google": oauth_provider_configured("google"),
            "github": oauth_provider_configured("github"),
        },
    )


@app.get("/signup")
def signup_page():
    if "user_id" in session:
        return redirect(url_for("dashboard_page"))

    oauth_error_provider = request.args.get("oauth_error", "").lower()
    oauth_error = None
    if oauth_error_provider in SUPPORTED_OAUTH_PROVIDERS:
        oauth_error = (
            f"{oauth_error_provider.title()} sign-up could not be completed. "
            "Please try again or create an account with email."
        )

    return render_template(
        "signup.html",
        csrf_token=csrf_token(),
        oauth_error=oauth_error,
        oauth_configured={
            "google": oauth_provider_configured("google"),
            "github": oauth_provider_configured("github"),
        },
    )


@app.get("/auth/<provider>")
def oauth_start(provider: str):
    provider = provider.lower()
    if provider not in SUPPORTED_OAUTH_PROVIDERS or not oauth_provider_configured(provider):
        return redirect(url_for("login_page", oauth_error=provider if provider in SUPPORTED_OAUTH_PROVIDERS else ""))

    if "user_id" in session:
        return redirect(url_for("dashboard_page"))

    if rate_limited("oauth_start", OAUTH_START_LIMIT, OAUTH_START_WINDOW_SECONDS):
        return redirect(url_for("login_page", oauth_error=provider))
    record_rate_event("oauth_start")

    next_url = request.args.get("next", "/dashboard")
    if not is_safe_next_url(next_url):
        next_url = "/dashboard"

    source = request.args.get("source", "login")
    if source not in {"login", "signup"}:
        source = "login"

    session["oauth_next"] = next_url
    session["oauth_source"] = source

    remote = oauth.create_client(provider)
    if remote is None:
        return redirect(url_for("login_page", oauth_error=provider))

    return remote.authorize_redirect(oauth_callback_url(provider))


@app.get("/auth/<provider>/callback")
def oauth_callback(provider: str):
    provider = provider.lower()
    source = session.get("oauth_source", "login")
    error_endpoint = "signup_page" if source == "signup" else "login_page"

    if provider not in SUPPORTED_OAUTH_PROVIDERS or not oauth_provider_configured(provider):
        return redirect(url_for(error_endpoint, oauth_error=provider if provider in SUPPORTED_OAUTH_PROVIDERS else ""))

    remote = oauth.create_client(provider)
    if remote is None:
        return redirect(url_for(error_endpoint, oauth_error=provider))

    try:
        token = remote.authorize_access_token()

        if provider == "google":
            provider_user_id, email = google_identity(token)
        else:
            provider_user_id, email = github_identity(remote)

        user = find_or_create_oauth_user(provider, provider_user_id, email)
        if user is None:
            raise RuntimeError("Unable to create local user.")

        next_url = session.get("oauth_next", "/dashboard")
        if not is_safe_next_url(next_url):
            next_url = "/dashboard"

        auth_result = complete_primary_auth(
            int(user["id"]),
            str(user["email"]),
            provider=provider,
            remember=False,
            next_url=next_url,
        )
        return redirect(auth_result["redirect"])

    except (OAuthError, ValueError, sqlite3.Error, RuntimeError) as exc:
        app.logger.warning("%s OAuth sign-in failed (%s)", provider, exc.__class__.__name__)
        return redirect(url_for(error_endpoint, oauth_error=provider))
    except Exception:
        # Do not leak provider responses, tokens, or internal details to users.
        app.logger.exception("Unexpected %s OAuth sign-in failure", provider)
        return redirect(url_for(error_endpoint, oauth_error=provider))


@app.get("/dashboard")
@login_required
def dashboard_page():
    user_id = int(session["user_id"])
    onboarding_state = get_onboarding_state(user_id)
    devices = owned_devices(user_id)
    connected = bool(devices)

    # Ownership is authoritative. The onboarding table controls only whether a
    # newly-created account should still see the first-device prompt.
    if connected and onboarding_state != "connected":
        set_onboarding_state(user_id, "connected")
        onboarding_state = "connected"

    return render_template(
        "dashboard.html",
        signed_in=True,
        user_email=session.get("email"),
        user_id=user_id,
        csrf_token=csrf_token(),
        onboarding_state=onboarding_state,
        connect_only=not connected,
        show_connect_prompt=(not connected and onboarding_state == "pending"),
        owned_devices=devices,
    )


@app.get("/connect")
@login_required
def connect_page():
    user_id = int(session["user_id"])
    return render_template(
        "connect.html",
        user_email=session.get("email"),
        user_id=user_id,
        csrf_token=csrf_token(),
        connected=user_has_devices(user_id),
    )


@app.get("/settings/developer")
@login_required
def developer_page():
    user_id = int(session["user_id"])
    return render_template(
        "developer.html",
        user_email=session.get("email"),
        user_id=user_id,
        csrf_token=csrf_token(),
    )


@app.get("/docs")
def docs_page():
    return render_template("docs.html")


@app.post("/api/signup")
def signup():
    """Start password registration and send an email OTP.

    No user account is created until /api/signup/verify succeeds.
    """
    csrf_error = require_csrf()
    if csrf_error:
        return csrf_error

    if rate_limited("signup", SIGNUP_LIMIT, SIGNUP_WINDOW_SECONDS):
        return jsonify(error="Too many signup attempts. Try again later."), 429

    data = request.get_json(silent=True) or {}
    email = normalize_email(data.get("email"))
    password = str(data.get("password", ""))
    confirm_password = str(data.get("confirm_password", ""))

    captcha_error = require_turnstile(data, expected_action="signup")
    if captcha_error:
        return captcha_error

    if not valid_email(email):
        return jsonify(error="Enter a valid email address."), 400

    error = password_error(password)
    if error:
        return jsonify(error=error), 400

    if password != confirm_password:
        return jsonify(error="Passwords do not match."), 400

    now = int(time.time())
    with get_db() as db:
        existing = db.execute("SELECT 1 FROM users WHERE email = ?", (email,)).fetchone()
        if existing:
            return jsonify(error="An account with this email already exists."), 409

        # Per-address cooldown prevents accidental/spam invalidation storms while
        # still allowing multiple independent pending signups safely.
        latest = db.execute(
            "SELECT MAX(last_sent_at) AS sent FROM pending_signups WHERE email = ?",
            (email,),
        ).fetchone()
        last_sent = int(latest["sent"] or 0)
        retry_after = OTP_RESEND_COOLDOWN_SECONDS - (now - last_sent)
        if retry_after > 0:
            return jsonify(
                error=f"A verification code was just sent. Wait {retry_after} seconds before requesting another.",
                retry_after=retry_after,
            ), 429

        # Keep transient rows bounded without touching valid recent signups.
        db.execute("DELETE FROM pending_signups WHERE expires_at < ?", (now - 86400,))
        db.commit()

    record_rate_event("signup")

    otp = generate_signup_otp()
    signup_id = secrets.token_urlsafe(32)  # >= 256 bits of randomness
    signup_hash = signup_id_hash(signup_id)
    expires_at = now + OTP_TTL_SECONDS
    password_hash = generate_password_hash(password, method="scrypt")
    otp_hash = signup_otp_hash(email, otp)

    try:
        send_signup_otp(email, otp, expires_minutes=OTP_TTL_SECONDS // 60)
    except EmailDeliveryError as exc:
        app.logger.warning("Signup OTP delivery failed (%s)", exc.__class__.__name__)
        return jsonify(
            error="We couldn't send the verification email. Please try again in a moment.",
            error_code="email_delivery_failed",
        ), 503

    try:
        with get_db() as db:
            db.execute(
                """
                INSERT INTO pending_signups(
                    signup_id_hash, email, password_hash, otp_hash,
                    created_at, expires_at, last_sent_at, attempts
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, 0)
                """,
                (signup_hash, email, password_hash, otp_hash, now, expires_at, now),
            )
            db.commit()
    except sqlite3.Error:
        app.logger.exception("Could not persist pending signup after OTP delivery")
        return jsonify(
            error="The verification email was sent, but signup could not be started. Please request a new code.",
            error_code="signup_state_failed",
        ), 500

    return jsonify(
        message="Verification code sent.",
        verification_required=True,
        signup_id=signup_id,
        email=masked_email(email),
        expires_in=OTP_TTL_SECONDS,
    ), 202


@app.post("/api/signup/verify")
def verify_signup_otp():
    csrf_error = require_csrf()
    if csrf_error:
        return csrf_error

    if rate_limited("signup_otp_verify", OTP_VERIFY_LIMIT, OTP_VERIFY_WINDOW_SECONDS):
        return jsonify(error="Too many verification attempts. Try again later."), 429

    data = request.get_json(silent=True) or {}
    signup_id = str(data.get("signup_id", "")).strip()
    otp = re.sub(r"\D", "", str(data.get("otp", "")))

    if len(signup_id) < 32 or len(otp) != 6:
        record_rate_event("signup_otp_verify")
        return jsonify(error="Enter the 6-digit verification code."), 400

    pending_hash = signup_id_hash(signup_id)
    now = int(time.time())
    with get_db() as db:
        pending = db.execute(
            "SELECT * FROM pending_signups WHERE signup_id_hash = ?",
            (pending_hash,),
        ).fetchone()

        if pending is None:
            record_rate_event("signup_otp_verify")
            return jsonify(
                error="This verification session is no longer active. Start sign-up again.",
                error_code="otp_not_found",
            ), 404

        email = str(pending["email"])
        if int(pending["expires_at"]) <= now:
            return jsonify(
                error="That verification code has expired. Request a new one.",
                error_code="otp_expired",
            ), 410

        if int(pending["attempts"]) >= OTP_MAX_ATTEMPTS:
            return jsonify(
                error="Too many incorrect codes. Request a new code.",
                error_code="otp_attempts_exceeded",
            ), 429

        expected = str(pending["otp_hash"])
        supplied = signup_otp_hash(email, otp)
        if not hmac.compare_digest(expected, supplied):
            attempts = int(pending["attempts"]) + 1
            db.execute(
                "UPDATE pending_signups SET attempts = ? WHERE signup_id_hash = ?",
                (attempts, pending_hash),
            )
            db.commit()
            record_rate_event("signup_otp_verify")
            if attempts >= OTP_MAX_ATTEMPTS:
                return jsonify(
                    error="Too many incorrect codes. Request a new code.",
                    error_code="otp_attempts_exceeded",
                ), 429
            return jsonify(
                error="That verification code is incorrect.",
                error_code="otp_incorrect",
                attempts_remaining=OTP_MAX_ATTEMPTS - attempts,
            ), 400

        try:
            cursor = db.execute(
                "INSERT INTO users(email, password_hash, email_verified_at) VALUES (?, ?, ?)",
                (email, str(pending["password_hash"]), now),
            )
            user_id = int(cursor.lastrowid)
            create_onboarding_record(db, user_id)
            # Once verified, every other outstanding signup for this address is stale.
            db.execute("DELETE FROM pending_signups WHERE email = ?", (email,))
            db.commit()
        except sqlite3.IntegrityError:
            db.rollback()
            db.execute("DELETE FROM pending_signups WHERE email = ?", (email,))
            db.commit()
            return jsonify(error="An account with this email already exists."), 409

    clear_rate_events("signup_otp_verify")
    establish_session(user_id, email, provider="password")
    return jsonify(
        message="Email verified. Account created.",
        user={"id": user_id, "email": email},
        redirect="/dashboard",
    ), 201


@app.post("/api/signup/resend")
def resend_signup_otp():
    csrf_error = require_csrf()
    if csrf_error:
        return csrf_error

    if rate_limited("signup_otp_resend", OTP_RESEND_LIMIT, OTP_RESEND_WINDOW_SECONDS):
        return jsonify(error="Too many verification emails. Try again later."), 429

    data = request.get_json(silent=True) or {}
    signup_id = str(data.get("signup_id", "")).strip()
    if len(signup_id) < 32:
        return jsonify(error="This verification session is no longer active."), 404

    pending_hash = signup_id_hash(signup_id)
    now = int(time.time())
    with get_db() as db:
        pending = db.execute(
            "SELECT email, last_sent_at FROM pending_signups WHERE signup_id_hash = ?",
            (pending_hash,),
        ).fetchone()
        if pending is None:
            return jsonify(
                error="This verification session is no longer active. Start sign-up again.",
                error_code="otp_not_found",
            ), 404

        email = str(pending["email"])
        if db.execute("SELECT 1 FROM users WHERE email = ?", (email,)).fetchone():
            db.execute("DELETE FROM pending_signups WHERE email = ?", (email,))
            db.commit()
            return jsonify(error="An account with this email already exists."), 409

    retry_after = OTP_RESEND_COOLDOWN_SECONDS - (now - int(pending["last_sent_at"]))
    if retry_after > 0:
        return jsonify(
            error=f"Wait {retry_after} seconds before requesting another code.",
            retry_after=retry_after,
        ), 429

    otp = generate_signup_otp()
    expires_at = now + OTP_TTL_SECONDS
    otp_hash = signup_otp_hash(email, otp)
    record_rate_event("signup_otp_resend")

    try:
        send_signup_otp(email, otp, expires_minutes=OTP_TTL_SECONDS // 60)
    except EmailDeliveryError as exc:
        app.logger.warning("Signup OTP resend failed (%s)", exc.__class__.__name__)
        return jsonify(
            error="We couldn't send another verification email. Please try again in a moment.",
            error_code="email_delivery_failed",
        ), 503

    with get_db() as db:
        db.execute(
            """
            UPDATE pending_signups
            SET otp_hash = ?, created_at = ?, expires_at = ?,
                last_sent_at = ?, attempts = 0
            WHERE signup_id_hash = ?
            """,
            (otp_hash, now, expires_at, now, pending_hash),
        )
        db.commit()

    return jsonify(
        message="A new verification code was sent.",
        email=masked_email(email),
        expires_in=OTP_TTL_SECONDS,
    )


@app.post("/api/login")
def login():
    csrf_error = require_csrf()
    if csrf_error:
        return csrf_error

    if rate_limited("login", LOGIN_FAILURE_LIMIT, LOGIN_WINDOW_SECONDS):
        return jsonify(error="Too many failed login attempts. Try again in a few minutes."), 429

    data = request.get_json(silent=True) or {}
    email = normalize_email(data.get("email"))
    password = str(data.get("password", ""))
    remember = bool(data.get("remember", False))
    next_url = str(data.get("next", "/dashboard"))

    captcha_error = require_turnstile(data, expected_action="login")
    if captcha_error:
        return captcha_error

    security_limit = login_rate_guard(email)
    if security_limit:
        message, retry_after = security_limit
        return jsonify(error=message, retry_after=retry_after), 429

    if not valid_email(email) or not password:
        return jsonify(error="Invalid email or password."), 401

    with get_db() as db:
        user = db.execute(
            "SELECT id, email, password_hash FROM users WHERE email = ?",
            (email,),
        ).fetchone()

    password_hash = user["password_hash"] if user else DUMMY_PASSWORD_HASH
    password_ok = check_password_hash(password_hash, password)

    if user is None or not password_ok:
        note_login_failure(email)
        record_rate_event("login")
        return jsonify(error="Invalid email or password."), 401

    clear_rate_events("login")
    note_login_success(email)
    try:
        auth_result = complete_primary_auth(
            int(user["id"]),
            str(user["email"]),
            provider="password",
            remember=remember,
            next_url=next_url,
        )
    except EmailDeliveryError:
        app.logger.warning("MFA email delivery failed during password sign-in")
        return jsonify(error="Unable to send the MFA verification code. Try again shortly."), 503

    if auth_result.get("mfa_required"):
        return jsonify(
            message="Additional verification required.",
            mfa_required=True,
            method=auth_result.get("method"),
            user={"id": user["id"], "email": user["email"]},
            redirect=auth_result["redirect"],
        )

    if not is_safe_next_url(next_url):
        next_url = "/dashboard"

    return jsonify(
        message="Login successful.",
        user={"id": user["id"], "email": user["email"]},
        redirect=next_url,
    )


@app.post("/api/onboarding/connection-choice")
@login_required
def onboarding_connection_choice():
    csrf_error = require_csrf()
    if csrf_error:
        return csrf_error

    data = request.get_json(silent=True) or {}
    choice = str(data.get("choice", "")).strip().lower()
    state_by_choice = {
        "later": "deferred",
        "yes": "connect_started",
    }
    state = state_by_choice.get(choice)
    if state is None:
        return jsonify(error="Invalid connection choice."), 400

    user_id = int(session["user_id"])
    # Do not let a preference override real ownership.
    if user_has_devices(user_id):
        set_onboarding_state(user_id, "connected")
        return jsonify(
            message="FloraCore is already connected.",
            connection_state="connected",
            redirect="/dashboard",
        )

    set_onboarding_state(user_id, state)
    return jsonify(
        message="Onboarding preference saved.",
        connection_state=state,
        redirect="/connect" if choice == "yes" else "/dashboard",
    )


@app.get("/api/devices")
def devices_api():
    if "user_id" not in session:
        return jsonify(error="Not authenticated."), 401
    return jsonify(devices=owned_devices(int(session["user_id"])))


@app.get("/api/device/latest/<device_id>")
def latest_device_telemetry(device_id: str):
    if "user_id" not in session:
        return jsonify(error="Not authenticated."), 401
    if not device_id or len(device_id) > 64:
        return jsonify(error="Invalid device id."), 400

    user_id = int(session["user_id"])
    with get_db() as db:
        ownership = db.execute(
            """
            SELECT claimed_at, nickname
            FROM device_ownership
            WHERE device_id = ? AND user_id = ?
            """,
            (device_id, user_id),
        ).fetchone()

        if ownership is None:
            # Do not disclose another account's device existence.
            return jsonify(error="Device not found."), 404

        state = db.execute(
            """
            SELECT last_seen, last_message_type, last_message_id
            FROM device_state
            WHERE device_id = ?
            """,
            (device_id,),
        ).fetchone()

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

    result = {
        "device_id": device_id,
        "claimed_at": ownership["claimed_at"],
        "nickname": ownership["nickname"],
        "last_seen": state["last_seen"] if state else None,
        "last_message_type": state["last_message_type"] if state else None,
        "last_message_id": state["last_message_id"] if state else None,
        "telemetry": None,
    }

    if telemetry is not None:
        try:
            payload = json.loads(telemetry["payload_json"])
        except (json.JSONDecodeError, TypeError):
            payload = None
        result["telemetry"] = {
            "message_id": telemetry["message_id"],
            "received_at": telemetry["received_at"],
            "payload": payload,
        }

    return jsonify(result)


@app.get("/api/health")
def health():
    return jsonify(
        ok=True,
        service="FloraCore",
        device_api="/api/device/v1/message",
        public_api="/api/v1",
        public_api_version="1.1",
        enrollment_api="/api/device/claim/start",
        ota_distribution="/firmware/floracore/",
    )


@app.post("/api/logout")
def logout():
    csrf_error = require_csrf()
    if csrf_error:
        return csrf_error

    revoke_current_session(reason="logout")
    session.clear()
    return jsonify(message="Logged out.")


@app.get("/api/me")
def me():
    if "user_id" not in session:
        return jsonify(error="Not authenticated."), 401

    return jsonify(
        user={
            "id": int(session["user_id"]),
            "user_id": int(session["user_id"]),
            "email": session["email"],
            "auth_provider": session.get("auth_provider", "password"),
            "connection_onboarding": get_onboarding_state(int(session["user_id"])),
        }
    )


if __name__ == "__main__":
    # Development server only. For floraos.life use Gunicorn behind your
    # existing Cloudflare Tunnel / reverse proxy.
    app.run(host="127.0.0.1", port=5000, debug=env_flag("FLORACORE_DEBUG"))
