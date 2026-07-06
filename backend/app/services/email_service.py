"""
Transactional email via SendGrid's REST API, called directly through httpx
(already a dependency everywhere else in this codebase — see advisor_service.py)
rather than pulling in the SendGrid SDK for what is, structurally, one POST
request with a bearer token.

Design choice: send_email() never raises. A failed email send should not take
down the request that triggered it — an invite, a password reset, a report
delivery. It logs failures and returns a bool so callers can decide whether
to surface anything to the user, but the dominant call pattern across this
codebase (see audit_service.log, recommendation_service.evaluate_and_alert_domain)
is "best-effort side effect, never blocks the primary transaction" — email
follows the same rule.

If SENDGRID_API_KEY is unset (local dev, CI), send_email() logs the rendered
subject/recipient/body instead of calling out to SendGrid at all, so nothing
in this codebase requires a real API key to run.
"""
from __future__ import annotations

import base64
import logging

import httpx

from app.config import settings

log = logging.getLogger(__name__)

_SENDGRID_URL = "https://api.sendgrid.com/v3/mail/send"


class Attachment:
    """One file to attach — content is raw bytes, base64-encoded at send time."""

    def __init__(self, filename: str, content: bytes, mime_type: str = "application/octet-stream"):
        self.filename = filename
        self.content = content
        self.mime_type = mime_type


def _wrap_html(title: str, body_html: str) -> str:
    """Minimal consistent branding wrapper — not meant to be a full design system,
    just enough that every transactional email looks like it came from the same product."""
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


async def send_email(
    to: str,
    subject: str,
    body_html: str,
    *,
    title: str | None = None,
    text_body: str | None = None,
    attachments: list[Attachment] | None = None,
) -> bool:
    """
    Send a transactional email. `body_html` is wrapped in a consistent branded
    shell unless `title` is omitted, in which case body_html is sent as-is.
    Returns True on a confirmed send (or dev-mode log), False on failure —
    callers should treat False as "log and move on," not as a reason to fail
    the request that triggered the email.
    """
    html = _wrap_html(title, body_html) if title else body_html

    if not settings.sendgrid_api_key:
        att_note = f" [+{len(attachments)} attachment(s): {', '.join(a.filename for a in attachments)}]" if attachments else ""
        log.info("EMAIL [dev mode, no SENDGRID_API_KEY] to=%s subject=%r%s\n%s", to, subject, att_note, text_body or body_html)
        return True

    payload = {
        "personalizations": [{"to": [{"email": to}]}],
        "from": {"email": settings.email_from_address, "name": settings.email_from_name},
        "subject": subject,
        "content": [
            *([{"type": "text/plain", "value": text_body}] if text_body else []),
            {"type": "text/html", "value": html},
        ],
    }
    if attachments:
        payload["attachments"] = [
            {
                "content": base64.b64encode(a.content).decode(),
                "filename": a.filename,
                "type": a.mime_type,
                "disposition": "attachment",
            }
            for a in attachments
        ]

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(
                _SENDGRID_URL,
                headers={"Authorization": f"Bearer {settings.sendgrid_api_key}"},
                json=payload,
            )
        if resp.status_code >= 300:
            log.warning("SendGrid send failed: %s %s", resp.status_code, resp.text[:300])
            return False
        return True
    except httpx.HTTPError as e:
        log.warning("SendGrid send raised: %s", e)
        return False
