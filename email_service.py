from __future__ import annotations

from email.message import EmailMessage
from email.utils import formataddr
import os
import smtplib
import ssl


class EmailDeliveryError(RuntimeError):
    """Raised when FloraCore cannot deliver a transactional email."""


def _env_flag(name: str, default: bool = False) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def send_signup_otp(recipient: str, otp: str, *, expires_minutes: int = 10) -> None:
    """Send a password-signup OTP through the configured SMTP server.

    Required environment variables:
      SMTP_HOST
      SMTP_FROM_EMAIL

    Usually also required:
      SMTP_USERNAME
      SMTP_PASSWORD

    The common production configuration is port 587 + STARTTLS.
    """
    host = os.environ.get("SMTP_HOST", "").strip()
    from_email = os.environ.get("SMTP_FROM_EMAIL", "").strip()
    from_name = os.environ.get("SMTP_FROM_NAME", "FloraCore").strip() or "FloraCore"
    username = os.environ.get("SMTP_USERNAME", "").strip()
    password = os.environ.get("SMTP_PASSWORD", "")

    try:
        port = int(os.environ.get("SMTP_PORT", "587"))
        timeout = float(os.environ.get("SMTP_TIMEOUT", "12"))
    except ValueError as exc:
        raise EmailDeliveryError("Invalid SMTP numeric configuration") from exc

    use_ssl = _env_flag("SMTP_USE_SSL", False)
    use_tls = _env_flag("SMTP_USE_TLS", not use_ssl)

    if not host or not from_email:
        raise EmailDeliveryError("SMTP is not configured")
    if use_ssl and use_tls:
        raise EmailDeliveryError("SMTP_USE_SSL and SMTP_USE_TLS cannot both be enabled")

    message = EmailMessage()
    message["Subject"] = f"{otp} is your FloraCore verification code"
    message["From"] = formataddr((from_name, from_email))
    message["To"] = recipient
    message["Auto-Submitted"] = "auto-generated"
    message.set_content(
        f"Verify your FloraCore email\n\n"
        f"Your verification code is: {otp}\n\n"
        f"This code expires in {expires_minutes} minutes.\n\n"
        "If you did not try to create a FloraCore account, you can ignore this email.\n"
        "FloraCore will never ask you to send this code to another person.\n"
    )
    message.add_alternative(
        f"""<!doctype html>
<html>
  <body style="margin:0;background:#07111F;color:#F4F7FB;font-family:Arial,sans-serif;padding:32px 16px">
    <div style="max-width:520px;margin:auto;background:#0F2132;border:1px solid #294154;border-radius:18px;padding:30px">
      <div style="font-size:14px;color:#92C3D3;font-weight:700;letter-spacing:.04em">FLORACORE</div>
      <h1 style="font-size:25px;margin:18px 0 8px">Verify your email.</h1>
      <p style="color:#A9B8C6;line-height:1.6;margin:0 0 22px">Enter this code on the FloraCore sign-up page:</p>
      <div style="font-size:34px;letter-spacing:.22em;font-weight:800;text-align:center;background:#07111F;border:1px solid #36556B;border-radius:14px;padding:18px 10px;color:#F4F7FB">{otp}</div>
      <p style="color:#97A7B8;line-height:1.6;font-size:14px;margin:22px 0 0">This code expires in {expires_minutes} minutes. If you did not try to create a FloraCore account, ignore this email.</p>
    </div>
  </body>
</html>""",
        subtype="html",
    )

    context = ssl.create_default_context()
    try:
        if use_ssl:
            with smtplib.SMTP_SSL(host, port, timeout=timeout, context=context) as smtp:
                if username:
                    smtp.login(username, password)
                smtp.send_message(message)
        else:
            with smtplib.SMTP(host, port, timeout=timeout) as smtp:
                smtp.ehlo()
                if use_tls:
                    smtp.starttls(context=context)
                    smtp.ehlo()
                if username:
                    smtp.login(username, password)
                smtp.send_message(message)
    except (OSError, smtplib.SMTPException) as exc:
        raise EmailDeliveryError("SMTP delivery failed") from exc

def send_mfa_otp(
    recipient: str,
    otp: str,
    *,
    purpose: str = "login",
    expires_minutes: int = 10,
) -> None:
    """Send a FloraCore MFA/security verification code.

    Uses the same SMTP configuration as signup verification.
    """
    host = os.environ.get("SMTP_HOST", "").strip()
    from_email = os.environ.get("SMTP_FROM_EMAIL", "").strip()
    from_name = os.environ.get("SMTP_FROM_NAME", "FloraCore").strip() or "FloraCore"
    username = os.environ.get("SMTP_USERNAME", "").strip()
    password = os.environ.get("SMTP_PASSWORD", "")

    try:
        port = int(os.environ.get("SMTP_PORT", "587"))
        timeout = float(os.environ.get("SMTP_TIMEOUT", "12"))
    except ValueError as exc:
        raise EmailDeliveryError("Invalid SMTP numeric configuration") from exc

    use_ssl = _env_flag("SMTP_USE_SSL", False)
    use_tls = _env_flag("SMTP_USE_TLS", not use_ssl)

    if not host or not from_email:
        raise EmailDeliveryError("SMTP is not configured")
    if use_ssl and use_tls:
        raise EmailDeliveryError("SMTP_USE_SSL and SMTP_USE_TLS cannot both be enabled")

    if purpose == "settings":
        subject = f"{otp} is your FloraCore security code"
        heading = "Confirm this security change."
        intro = "Enter this code in FloraCore Settings to continue:"
        plain_context = "confirm a security-sensitive account change"
    else:
        subject = f"{otp} is your FloraCore sign-in code"
        heading = "Complete your sign-in."
        intro = "Enter this code to finish signing in to FloraCore:"
        plain_context = "finish signing in"

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = formataddr((from_name, from_email))
    message["To"] = recipient
    message["Auto-Submitted"] = "auto-generated"
    message.set_content(
        f"{heading}\n\n"
        f"Your verification code is: {otp}\n\n"
        f"This code expires in {expires_minutes} minutes.\n\n"
        f"If you did not try to {plain_context}, you can ignore this email.\n"
        "FloraCore will never ask you to send this code to another person.\n"
    )
    message.add_alternative(
        f"""<!doctype html>
<html>
  <body style="margin:0;background:#07111F;color:#F4F7FB;font-family:Arial,sans-serif;padding:32px 16px">
    <div style="max-width:520px;margin:auto;background:#0F2132;border:1px solid #294154;border-radius:18px;padding:30px">
      <div style="font-size:14px;color:#92C3D3;font-weight:700;letter-spacing:.04em">FLORACORE SECURITY</div>
      <h1 style="font-size:25px;margin:18px 0 8px">{heading}</h1>
      <p style="color:#A9B8C6;line-height:1.6;margin:0 0 22px">{intro}</p>
      <div style="font-size:34px;letter-spacing:.22em;font-weight:800;text-align:center;background:#07111F;border:1px solid #36556B;border-radius:14px;padding:18px 10px;color:#F4F7FB">{otp}</div>
      <p style="color:#97A7B8;line-height:1.6;font-size:14px;margin:22px 0 0">This code expires in {expires_minutes} minutes. If this was not you, ignore this message.</p>
    </div>
  </body>
</html>""",
        subtype="html",
    )

    context = ssl.create_default_context()
    try:
        if use_ssl:
            with smtplib.SMTP_SSL(host, port, timeout=timeout, context=context) as smtp:
                if username:
                    smtp.login(username, password)
                smtp.send_message(message)
        else:
            with smtplib.SMTP(host, port, timeout=timeout) as smtp:
                smtp.ehlo()
                if use_tls:
                    smtp.starttls(context=context)
                    smtp.ehlo()
                if username:
                    smtp.login(username, password)
                smtp.send_message(message)
    except (OSError, smtplib.SMTPException) as exc:
        raise EmailDeliveryError("SMTP delivery failed") from exc
