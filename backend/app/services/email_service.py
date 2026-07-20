"""
Transactional email via SMTP (aiosmtplib, STARTTLS on port 587).

send_email() never raises — a failed send logs the error and returns False
so callers can decide whether to surface anything to the user. The dominant
pattern in this codebase is "best-effort side effect, never blocks the
primary transaction."

If SMTP_HOST is unset (local dev, CI), send_email() logs the rendered
subject/recipient/body to stdout instead of connecting, so nothing requires
a live mail server to run.
"""
from __future__ import annotations

import logging
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email import encoders

import aiosmtplib

from app.config import settings

log = logging.getLogger(__name__)


class Attachment:
    """One file to attach — content is raw bytes."""

    def __init__(self, filename: str, content: bytes, mime_type: str = "application/octet-stream"):
        self.filename = filename
        self.content = content
        self.mime_type = mime_type


def _wrap_html(title: str, body_html: str) -> str:
    return f"""
    <div style="font-family: -apple-system, Segoe UI, Roboto, sans-serif; max-width: 560px; margin: 0 auto; color: #1a1a2e;">
      <div style="padding: 24px 0; border-bottom: 2px solid #5b6ef5;">
        <span style="font-weight: 800; font-size: 20px; letter-spacing: -.3px;">Sen<span style="color:#5b6ef5">tinel</span></span>
      </div>
      <div style="padding: 28px 0;">
        <h2 style="font-size: 17px; margin: 0 0 16px;">{title}</h2>
        {body_html}
      </div>
      <div style="padding: 16px 0; border-top: 1px solid #e5e7eb; color: #888; font-size: 11px;">
        Sentinel — DMARC &amp; MTA-STS monitoring
      </div>
    </div>
    """


def _startup_check() -> None:
    if settings.smtp_host:
        log.info("Email: SMTP configured (host=%s port=%d from=%s)", settings.smtp_host, settings.smtp_port, settings.email_from_address)
    else:
        log.warning(
            "Email: SMTP_HOST is not set — all emails will be logged to stdout only. "
            "Set SMTP_HOST, SMTP_USER, and SMTP_PASSWORD in .env to enable real delivery."
        )


_startup_check()


async def send_email(
    to: str,
    subject: str,
    body_html: str,
    *,
    title: str | None = None,
    text_body: str | None = None,
    attachments: list[Attachment] | None = None,
) -> bool:
    html = _wrap_html(title, body_html) if title else body_html

    if not settings.smtp_host:
        att_note = f" [+{len(attachments)} attachment(s): {', '.join(a.filename for a in attachments)}]" if attachments else ""
        log.info("EMAIL [dev mode, no SMTP_HOST] to=%s subject=%r%s\n%s", to, subject, att_note, text_body or body_html)
        return True

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = f"{settings.email_from_name} <{settings.email_from_address}>"
    msg["To"] = to

    if text_body:
        msg.attach(MIMEText(text_body, "plain", "utf-8"))
    msg.attach(MIMEText(html, "html", "utf-8"))

    if attachments:
        outer = MIMEMultipart("mixed")
        outer["Subject"] = subject
        outer["From"] = msg["From"]
        outer["To"] = to
        outer.attach(msg)
        for a in attachments:
            part = MIMEBase(*a.mime_type.split("/", 1))
            part.set_payload(a.content)
            encoders.encode_base64(part)
            part.add_header("Content-Disposition", "attachment", filename=a.filename)
            outer.attach(part)
        msg = outer

    try:
        await aiosmtplib.send(
            msg,
            hostname=settings.smtp_host,
            port=settings.smtp_port,
            username=settings.smtp_user or None,
            password=settings.smtp_password or None,
            start_tls=True,
        )
        return True
    except aiosmtplib.SMTPException as e:
        log.warning("SMTP send failed to %s: %s", to, e)
        return False
    except Exception as e:
        log.warning("SMTP send raised unexpected error to %s: %s", to, e)
        return False
