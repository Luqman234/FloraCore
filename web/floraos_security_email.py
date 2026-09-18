from __future__ import annotations

from email.message import EmailMessage
from email.utils import formataddr
import html
import os
import smtplib
import ssl
from typing import Mapping


class SecurityEmailError(RuntimeError):
    """Raised when a FloraCore security email cannot be delivered."""


def _env_flag(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _smtp_config() -> dict:
    try:
        port = int(os.environ.get("SMTP_PORT", "587"))
        timeout = float(os.environ.get("SMTP_TIMEOUT", "12"))
    except ValueError as exc:
        raise SecurityEmailError("Invalid SMTP numeric configuration.") from exc

    use_ssl = _env_flag("SMTP_USE_SSL", False)
    use_tls = _env_flag("SMTP_USE_TLS", not use_ssl)
    if use_ssl and use_tls:
        raise SecurityEmailError("SMTP_USE_SSL and SMTP_USE_TLS cannot both be enabled.")

    host = os.environ.get("SMTP_HOST", "").strip()
    sender = os.environ.get("SMTP_FROM_EMAIL", "").strip()
    if not host or not sender:
        raise SecurityEmailError("SMTP is not configured.")

    return {
        "host": host,
        "port": port,
        "timeout": timeout,
        "use_ssl": use_ssl,
        "use_tls": use_tls,
        "username": os.environ.get("SMTP_USERNAME", "").strip(),
        "password": os.environ.get("SMTP_PASSWORD", ""),
        "sender": sender,
        "sender_name": os.environ.get("SMTP_FROM_NAME", "FloraCore").strip() or "FloraCore",
    }


def _send(message: EmailMessage) -> None:
    cfg = _smtp_config()
    context = ssl.create_default_context()

    try:
        if cfg["use_ssl"]:
            with smtplib.SMTP_SSL(
                cfg["host"],
                cfg["port"],
                timeout=cfg["timeout"],
                context=context,
            ) as smtp:
                if cfg["username"]:
                    smtp.login(cfg["username"], cfg["password"])
                smtp.send_message(message)
        else:
            with smtplib.SMTP(cfg["host"], cfg["port"], timeout=cfg["timeout"]) as smtp:
                smtp.ehlo()
                if cfg["use_tls"]:
                    smtp.starttls(context=context)
                    smtp.ehlo()
                if cfg["username"]:
                    smtp.login(cfg["username"], cfg["password"])
                smtp.send_message(message)
    except (OSError, smtplib.SMTPException) as exc:
        raise SecurityEmailError("SMTP delivery failed.") from exc


def _message(recipient: str, subject: str) -> EmailMessage:
    cfg = _smtp_config()
    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = formataddr((cfg["sender_name"], cfg["sender"]))
    message["To"] = recipient
    message["Auto-Submitted"] = "auto-generated"
    return message


def send_password_reset_otp(
    recipient: str,
    otp: str,
    *,
    expires_minutes: int = 10,
) -> None:
    message = _message(recipient, f"{otp} is your FloraCore password reset code")
    message.set_content(
        "Reset your FloraCore password\n\n"
        f"Your password reset code is: {otp}\n\n"
        f"This code expires in {expires_minutes} minutes.\n\n"
        "If you did not request a password reset, ignore this message. "
        "Your password has not been changed.\n"
    )
    message.add_alternative(
        f"""<!doctype html>
<html>
  <body style="margin:0;background:#07111F;color:#F4F7FB;font-family:Arial,sans-serif;padding:32px 16px">
    <div style="max-width:520px;margin:auto;background:#0F2132;border:1px solid #294154;border-radius:18px;padding:30px">
      <div style="font-size:14px;color:#92C3D3;font-weight:700;letter-spacing:.04em">FLORACORE SECURITY</div>
      <h1 style="font-size:25px;margin:18px 0 8px">Reset your password.</h1>
      <p style="color:#A9B8C6;line-height:1.6;margin:0 0 22px">Enter this code on the FloraCore password-reset page:</p>
      <div style="font-size:34px;letter-spacing:.22em;font-weight:800;text-align:center;background:#07111F;border:1px solid #36556B;border-radius:14px;padding:18px 10px;color:#F4F7FB">{html.escape(otp)}</div>
      <p style="color:#97A7B8;line-height:1.6;font-size:14px;margin:22px 0 0">
        This code expires in {int(expires_minutes)} minutes. If you did not request this, ignore this email.
      </p>
    </div>
  </body>
</html>""",
        subtype="html",
    )
    _send(message)


def send_security_alert(
    recipient: str,
    *,
    title: str,
    summary: str,
    details: Mapping[str, str] | None = None,
) -> None:
    """Best used for high-value account events.

    Callers should catch SecurityEmailError so an alert-delivery outage never
    rolls back a password/session/MFA security action that already succeeded.
    """
    details = dict(details or {})
    message = _message(recipient, f"FloraCore security alert: {title}")

    plain_details = "\n".join(f"{key}: {value}" for key, value in details.items())
    message.set_content(
        f"FloraCore security alert\n\n{title}\n\n{summary}\n\n"
        + (plain_details + "\n\n" if plain_details else "")
        + "If you did not perform this action, sign in to FloraCore and review "
          "Settings → Security immediately.\n"
    )

    html_details = "".join(
        "<tr>"
        f"<td style='padding:7px 10px;color:#8295A5;font-size:13px'>{html.escape(str(key))}</td>"
        f"<td style='padding:7px 10px;color:#DDE8ED;font-size:13px'>{html.escape(str(value))}</td>"
        "</tr>"
        for key, value in details.items()
    )

    message.add_alternative(
        f"""<!doctype html>
<html>
  <body style="margin:0;background:#07111F;color:#F4F7FB;font-family:Arial,sans-serif;padding:32px 16px">
    <div style="max-width:560px;margin:auto;background:#0F2132;border:1px solid #294154;border-radius:18px;padding:30px">
      <div style="font-size:14px;color:#92C3D3;font-weight:700;letter-spacing:.04em">FLORACORE SECURITY</div>
      <h1 style="font-size:24px;margin:18px 0 8px">{html.escape(title)}</h1>
      <p style="color:#A9B8C6;line-height:1.6;margin:0">{html.escape(summary)}</p>
      {f"<table style='width:100%;border-collapse:collapse;margin-top:18px;background:#07131F;border-radius:10px'>{html_details}</table>" if html_details else ""}
      <p style="color:#97A7B8;line-height:1.6;font-size:13px;margin:22px 0 0">
        If this was not you, review your FloraCore security settings immediately.
      </p>
    </div>
  </body>
</html>""",
        subtype="html",
    )
    _send(message)
