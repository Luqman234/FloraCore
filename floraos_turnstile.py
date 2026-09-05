from __future__ import annotations

from dataclasses import dataclass
from typing import Any
import json
import os
import socket
import time
import urllib.error
import urllib.parse
import urllib.request

from flask import current_app, jsonify, redirect, render_template, request, session


SITEVERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
MAX_TOKEN_LENGTH = 2048
VERIFY_TIMEOUT_SECONDS = 7.0
DEFAULT_ENTRY_TTL_SECONDS = 30 * 60

# Browser-facing routes that must never be intercepted by the entry gate.
# Device/API/firmware traffic stays completely separate from the human web gate.
ENTRY_GATE_EXACT_EXEMPT = {
    "/security-check",
    "/api/security-check/verify",
    "/favicon.ico",
    "/robots.txt",
}
ENTRY_GATE_PREFIX_EXEMPT = (
    "/static/",
    "/firmware/",
    "/api/",
    "/oauth/",
)


@dataclass(frozen=True)
class TurnstileResult:
    ok: bool
    code: str
    message: str
    hostname: str | None = None
    action: str | None = None


def _env_flag(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _hostnames_from_env() -> tuple[str, ...]:
    raw = os.environ.get("TURNSTILE_HOSTNAMES", "floraos.life")
    values = []
    for item in raw.split(","):
        value = item.strip().lower().rstrip(".")
        if value and value not in values:
            values.append(value)
    return tuple(values)


def _positive_int_env(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return int(default)
    try:
        value = int(raw)
    except ValueError as exc:
        raise RuntimeError(f"{name} must be an integer.") from exc
    if value < 1:
        raise RuntimeError(f"{name} must be at least 1 second.")
    return value


def _entry_gate_hostnames() -> tuple[str, ...]:
    raw = os.environ.get("TURNSTILE_ENTRY_HOSTNAMES", "floraos.life")
    values = []
    for item in raw.split(","):
        value = item.strip().lower().rstrip(".")
        if value and value not in values:
            values.append(value)
    return tuple(values)


def _safe_entry_next(value: str | None) -> str:
    if (
        not isinstance(value, str)
        or not value.startswith("/")
        or value.startswith("//")
        or "\r" in value
        or "\n" in value
        or value.startswith("/security-check")
        or value.startswith("/api/security-check/")
    ):
        return "/"
    return value


def _entry_gate_verified() -> bool:
    raw = session.get("turnstile_entry_verified_until")
    try:
        return int(raw) >= int(time.time())
    except (TypeError, ValueError):
        return False


def _should_gate_browser_request() -> bool:
    if not bool(current_app.config.get("TURNSTILE_ENTRY_GATE")):
        return False
    if not bool(current_app.config.get("TURNSTILE_ENABLED")):
        return False
    if request.method not in {"GET", "HEAD"}:
        return False

    host = request.host.split(":", 1)[0].lower().rstrip(".")
    allowed_hosts = set(current_app.config.get("TURNSTILE_ENTRY_HOSTNAMES", ()))
    if allowed_hosts and host not in allowed_hosts:
        return False

    path = request.path or "/"
    if path in ENTRY_GATE_EXACT_EXEMPT:
        return False
    if any(path.startswith(prefix) for prefix in ENTRY_GATE_PREFIX_EXEMPT):
        return False

    # OAuth callbacks must not be interrupted after the provider redirects back.
    if "oauth" in path.lower() and ("callback" in path.lower() or "authorize" in path.lower()):
        return False

    # The bare public entry point is intentionally checked every time it is
    # opened/reloaded. After a successful site-entry verification, one redirect
    # back to "/" is allowed so we do not create a challenge loop.
    if path == "/":
        if session.pop("turnstile_root_bypass_once", False):
            return False
        return True

    # Once inside the website, do not challenge every navigation. The short
    # session clearance protects deep links while keeping the site usable.
    return not _entry_gate_verified()


def init_turnstile(app) -> None:
    site_key = os.environ.get("TURNSTILE_SITE_KEY", "").strip()
    secret_key = os.environ.get("TURNSTILE_SECRET_KEY", "").strip()
    required = _env_flag("TURNSTILE_REQUIRED", False)
    hostnames = _hostnames_from_env()

    if bool(site_key) != bool(secret_key):
        raise RuntimeError(
            "Cloudflare Turnstile is partially configured. "
            "Set both TURNSTILE_SITE_KEY and TURNSTILE_SECRET_KEY, or neither."
        )

    if required and not site_key:
        raise RuntimeError(
            "TURNSTILE_REQUIRED=1 but TURNSTILE_SITE_KEY / "
            "TURNSTILE_SECRET_KEY are not configured."
        )

    app.config["TURNSTILE_SITE_KEY"] = site_key
    app.config["TURNSTILE_SECRET_KEY"] = secret_key
    app.config["TURNSTILE_REQUIRED"] = required
    app.config["TURNSTILE_HOSTNAMES"] = hostnames
    app.config["TURNSTILE_ENABLED"] = bool(site_key and secret_key)
    app.config["TURNSTILE_ENTRY_GATE"] = _env_flag("TURNSTILE_ENTRY_GATE", True)
    app.config["TURNSTILE_ENTRY_TTL_SECONDS"] = _positive_int_env(
        "TURNSTILE_ENTRY_TTL_SECONDS",
        DEFAULT_ENTRY_TTL_SECONDS,
    )
    app.config["TURNSTILE_ENTRY_HOSTNAMES"] = _entry_gate_hostnames()

    if not app.config["TURNSTILE_ENABLED"]:
        app.logger.warning(
            "Cloudflare Turnstile is installed but inactive. "
            "Set TURNSTILE_SITE_KEY and TURNSTILE_SECRET_KEY to enable it."
        )

    @app.before_request
    def _turnstile_entry_gate():
        if not _should_gate_browser_request():
            return None

        next_url = request.full_path if request.query_string else request.path
        next_url = _safe_entry_next(next_url)
        return redirect("/security-check?next=" + urllib.parse.quote(next_url, safe=""))

    @app.get("/security-check")
    def _turnstile_security_check_page():
        if not bool(current_app.config.get("TURNSTILE_ENABLED")):
            return redirect("/")

        if _entry_gate_verified():
            return redirect(_safe_entry_next(request.args.get("next")))

        response = current_app.make_response(
            render_template(
                "security_check.html",
                next_url=_safe_entry_next(request.args.get("next")),
            )
        )
        response.headers["Cache-Control"] = "no-store, max-age=0"
        response.headers["Pragma"] = "no-cache"
        return response

    @app.post("/api/security-check/verify")
    def _turnstile_security_check_verify():
        body = request.get_json(silent=True)
        if not isinstance(body, dict):
            return jsonify(
                error="A JSON object is required.",
                error_code="invalid_request",
            ), 400

        token = str(
            body.get("turnstile_token")
            or body.get("cf-turnstile-response")
            or ""
        ).strip()

        result = verify_turnstile_token(token, expected_action="site_entry")
        if not result.ok:
            status = 503 if result.code == "captcha_unavailable" else 403
            return jsonify(
                error=result.message,
                error_code=result.code,
            ), status

        ttl = int(current_app.config["TURNSTILE_ENTRY_TTL_SECONDS"])
        next_url = _safe_entry_next(body.get("next"))
        session["turnstile_entry_verified_until"] = int(time.time()) + ttl
        if next_url == "/":
            session["turnstile_root_bypass_once"] = True

        return jsonify(
            data={
                "verified": True,
                "expires_in": ttl,
                "redirect": next_url,
            }
        )

    @app.context_processor
    def _turnstile_template_context():
        return {
            "turnstile_enabled": bool(current_app.config.get("TURNSTILE_ENABLED")),
            "turnstile_site_key": str(current_app.config.get("TURNSTILE_SITE_KEY", "")),
        }


def _visitor_ip() -> str | None:
    # floraos.life is behind Cloudflare Tunnel, so CF-Connecting-IP is the
    # useful client address. Fall back to Flask's remote_addr for local tests.
    forwarded = request.headers.get("CF-Connecting-IP", "").strip()
    if forwarded:
        return forwarded[:64]
    remote = (request.remote_addr or "").strip()
    return remote[:64] if remote else None


def _siteverify(
    *,
    secret: str,
    token: str,
    remote_ip: str | None,
) -> dict[str, Any]:
    payload = {
        "secret": secret,
        "response": token,
    }
    if remote_ip:
        payload["remoteip"] = remote_ip

    encoded = urllib.parse.urlencode(payload).encode("utf-8")
    req = urllib.request.Request(
        SITEVERIFY_URL,
        data=encoded,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
            "User-Agent": "FloraCore-Turnstile/1.0",
        },
        method="POST",
    )

    with urllib.request.urlopen(req, timeout=VERIFY_TIMEOUT_SECONDS) as response:
        if response.status != 200:
            raise RuntimeError(f"Turnstile Siteverify returned HTTP {response.status}")
        raw = response.read(64 * 1024)

    parsed = json.loads(raw.decode("utf-8"))
    if not isinstance(parsed, dict):
        raise RuntimeError("Turnstile Siteverify returned an invalid response.")
    return parsed


def verify_turnstile_token(
    token: str,
    *,
    expected_action: str,
) -> TurnstileResult:
    enabled = bool(current_app.config.get("TURNSTILE_ENABLED"))
    required = bool(current_app.config.get("TURNSTILE_REQUIRED"))

    if not enabled:
        if required:
            return TurnstileResult(
                False,
                "captcha_unavailable",
                "Security verification is temporarily unavailable.",
            )
        return TurnstileResult(True, "captcha_disabled", "Turnstile is not configured.")

    if not isinstance(token, str) or not token or len(token) > MAX_TOKEN_LENGTH:
        return TurnstileResult(
            False,
            "captcha_required",
            "Complete the security check and try again.",
        )

    secret = str(current_app.config["TURNSTILE_SECRET_KEY"])
    expected_hostnames = {
        str(host).lower().rstrip(".")
        for host in current_app.config.get("TURNSTILE_HOSTNAMES", ())
        if str(host).strip()
    }

    try:
        result = _siteverify(
            secret=secret,
            token=token,
            remote_ip=_visitor_ip(),
        )
    except (
        urllib.error.URLError,
        urllib.error.HTTPError,
        TimeoutError,
        socket.timeout,
        json.JSONDecodeError,
        UnicodeDecodeError,
        RuntimeError,
    ):
        current_app.logger.warning("Cloudflare Turnstile Siteverify request failed")
        return TurnstileResult(
            False,
            "captcha_unavailable",
            "Security verification could not be completed. Try again.",
        )

    success = result.get("success") is True
    action = str(result.get("action") or "")
    hostname = str(result.get("hostname") or "").lower().rstrip(".")

    if not success:
        # Do not expose Cloudflare's detailed error codes to the browser.
        return TurnstileResult(
            False,
            "captcha_failed",
            "Security verification failed. Try again.",
            hostname=hostname or None,
            action=action or None,
        )

    if action != expected_action:
        current_app.logger.warning(
            "Turnstile action mismatch: expected=%s received=%s",
            expected_action,
            action or "(empty)",
        )
        return TurnstileResult(
            False,
            "captcha_failed",
            "Security verification failed. Try again.",
            hostname=hostname or None,
            action=action or None,
        )

    if expected_hostnames and hostname not in expected_hostnames:
        current_app.logger.warning(
            "Turnstile hostname mismatch for action=%s hostname=%s",
            expected_action,
            hostname or "(empty)",
        )
        return TurnstileResult(
            False,
            "captcha_failed",
            "Security verification failed. Try again.",
            hostname=hostname or None,
            action=action or None,
        )

    return TurnstileResult(
        True,
        "captcha_ok",
        "Security verification passed.",
        hostname=hostname or None,
        action=action or None,
    )


def require_turnstile(data: dict[str, Any], *, expected_action: str):
    token = str(
        data.get("turnstile_token")
        or data.get("cf-turnstile-response")
        or ""
    ).strip()

    result = verify_turnstile_token(token, expected_action=expected_action)
    if result.ok:
        return None

    status = 503 if result.code == "captcha_unavailable" else 403
    return (
        jsonify(
            error=result.message,
            error_code=result.code,
        ),
        status,
    )
