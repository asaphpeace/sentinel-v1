"""
Background job: emails the PDF report to tenants that have opted into
report_schedule (weekly/monthly) and whose plan includes scheduled_reports.

"Due" is computed from last_report_sent_at rather than a fixed day-of-week,
so the schedule self-corrects after downtime (a missed run doesn't mean
waiting until the literal next Monday — it sends as soon as the job runs
again and finds the tenant overdue) and so two tenants who both pick
"weekly" don't all get emailed on the same calendar day, spreading load.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from app.database import AsyncSessionLocal
from app.models.user import Tenant, User
from app.routers.overview import get_report_data
from app.services.email_service import Attachment, send_email
from app.services.pdf_report_service import render_report_pdf
from app.services.plan_limits import check_feature

log = logging.getLogger(__name__)

_INTERVAL_DAYS = {"weekly": 7, "monthly": 30}


def _is_due(tenant: Tenant) -> bool:
    interval = _INTERVAL_DAYS.get(tenant.report_schedule)
    if interval is None:
        return False
    if tenant.last_report_sent_at is None:
        return True
    last = tenant.last_report_sent_at
    if last.tzinfo is None:
        last = last.replace(tzinfo=timezone.utc)
    return datetime.now(timezone.utc) - last >= timedelta(days=interval)


async def send_scheduled_reports() -> None:
    async with AsyncSessionLocal() as db:
        tenants = (
            await db.execute(select(Tenant).where(Tenant.report_schedule != "off"))
        ).scalars().all()

        for tenant in tenants:
            if not check_feature(tenant, "scheduled_reports"):
                continue  # downgraded since opting in — silently skip, don't email
            if not _is_due(tenant):
                continue

            try:
                await _send_one(db, tenant)
            except Exception:
                log.exception("Scheduled report failed for tenant %s", tenant.id)


async def _send_one(db, tenant: Tenant) -> None:
    recipient = tenant.billing_email
    actor = (await db.execute(select(User).where(User.tenant_id == tenant.id, User.role == "admin"))).scalars().first()
    if not recipient:
        recipient = actor.email if actor else None
    if not recipient or not actor:
        log.warning("Scheduled report skipped for tenant %s — no recipient/admin user", tenant.id)
        return

    report = await get_report_data(db=db, user=actor, period_days=30)
    pdf_bytes = await render_report_pdf(report, brand_name=tenant.brand_name)

    sent = await send_email(
        to=recipient,
        subject=f"Your {tenant.report_schedule} Sentinel security report — {report.sentinel.grade} ({report.sentinel.score}/100)",
        title="Your scheduled security report is ready",
        body_html=(
            f"<p>Attached is your {tenant.report_schedule} email security posture report for "
            f"<strong>{tenant.name}</strong>.</p>"
            f"<p>Current grade: <strong>{report.sentinel.grade}</strong> ({report.sentinel.score}/100)</p>"
            f"<p style=\"color:#888;font-size:12px;\">Manage your report schedule from Billing settings in the app.</p>"
        ),
        text_body=f"Your {tenant.report_schedule} Sentinel report is attached. Current grade: {report.sentinel.grade} ({report.sentinel.score}/100).",
        attachments=[Attachment(
            filename=f"sentinel-report-{report.generated_at[:10]}.pdf",
            content=pdf_bytes,
            mime_type="application/pdf",
        )],
    )
    if sent:
        tenant.last_report_sent_at = datetime.now(timezone.utc)
        await db.commit()
