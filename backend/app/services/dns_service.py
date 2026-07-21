"""
DNS record polling and change detection.
Queries live DNS for DMARC, SPF, MX, DKIM, MTA-STS, TLS-RPT records.
Stores a change event in dns_records whenever a value changes.
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any

import dns.exception
from app.services.dns_resolver import resolver as _resolver
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import AsyncSessionLocal
from app.models import Alert, Domain, DnsRecord
from app.schemas.dns import _is_security_alert
from app.services.advisor_service import generate_dns_risk_assessment

log = logging.getLogger(__name__)

DKIM_SELECTORS = [
    "google", "s1", "s2", "selector1", "selector2", "k1", "k2",
    "mail", "default", "dkim", "email", "zoho", "sendgrid",
]


async def _txt_lookup(name: str) -> str | None:
    try:
        answers = await _resolver.resolve(name, "TXT")
        parts = []
        for rdata in answers:
            parts.append("".join(s.decode() for s in rdata.strings))
        return " | ".join(sorted(parts)) if parts else None
    except dns.exception.DNSException:
        return None


async def _cname_lookup(name: str) -> str | None:
    try:
        answers = await _resolver.resolve(name, "CNAME")
        return str(answers[0].target).rstrip(".")
    except dns.exception.DNSException:
        return None


async def _mx_lookup(domain_name: str) -> str | None:
    try:
        answers = await _resolver.resolve(domain_name, "MX")
        hosts = sorted(f"{r.preference} {str(r.exchange).rstrip('.')}" for r in answers)
        return " | ".join(hosts) if hosts else None
    except dns.exception.DNSException:
        return None


async def _last_value(db: AsyncSession, domain_id: uuid.UUID, record_type: str, host: str) -> str | None:
    stmt = (
        select(DnsRecord.current_value)
        .where(DnsRecord.domain_id == domain_id, DnsRecord.record_type == record_type, DnsRecord.record_host == host)
        .order_by(DnsRecord.detected_at.desc())
        .limit(1)
    )
    result = await db.execute(stmt)
    return result.scalar_one_or_none()


async def _record_change(
    db: AsyncSession,
    domain_id: uuid.UUID,
    tenant_id: uuid.UUID,
    record_type: str,
    host: str,
    previous: str | None,
    current: str | None,
    summary: str,
    domain_name: str = "",
) -> None:
    record_id = uuid.uuid4()
    record = DnsRecord(
        id=record_id,
        domain_id=domain_id,
        record_type=record_type,
        record_host=host,
        previous_value=previous,
        current_value=current,
        change_summary=summary,
        detected_at=datetime.now(timezone.utc),
    )
    db.add(record)

    # A drift event — record_change() only ever fires when poll_domain_dns
    # already found current != previous, so this isn't an extra dedup check,
    # it's classifying a change that's already known to be real. Without this,
    # is_security_alert was computed for the DNS Timeline page but never rang
    # the bell — someone's web host silently dropping the DMARC record months
    # after setup would only be noticed by someone who happened to visit that
    # page (see GUIDED_ONBOARDING_PLAN.md Part 3 #6).
    if _is_security_alert(record_type, previous, current):
        db.add(Alert(
            id=uuid.uuid4(),
            domain_id=domain_id,
            tenant_id=tenant_id,
            severity="critical" if current is None else "warn",
            category="dns",
            title=f"{record_type} record changed unexpectedly on {domain_name or host}",
            body=f"{summary} at {host}. This looks like a security regression, not a routine update.",
            action=(
                "Open the DNS Timeline for this domain, confirm whether this change was intentional, "
                "and use \"Revert: copy this\" on the previous value if it wasn't."
            ),
        ))

    await db.commit()

    # Generate risk assessment in background — never blocks DNS polling
    import asyncio

    change_type = "added" if previous is None else "removed" if current is None else "modified"

    async def _bg_risk(rec_id: uuid.UUID) -> None:
        try:
            result = await generate_dns_risk_assessment(
                record_type=record_type,
                previous_value=previous,
                current_value=current,
                domain_name=domain_name or host,
                change_type=change_type,
            )
            async with AsyncSessionLocal() as bg_db:
                from sqlalchemy import select as _select
                rec = (await bg_db.execute(_select(DnsRecord).where(DnsRecord.id == rec_id))).scalar_one_or_none()
                if rec:
                    rec.risk_severity    = result["severity"]
                    rec.risk_explanation = result["explanation"]
                    rec.risk_action      = result["action"]
                    rec.risk_is_ai       = result["is_ai"]
                    await bg_db.commit()
        except Exception:
            log.exception("DNS risk assessment failed for record %s", rec_id)

    asyncio.create_task(_bg_risk(record_id))


async def poll_domain_dns(db: AsyncSession, domain: Domain) -> list[dict]:
    """
    Check all DNS records for a domain and store changes.
    Returns list of change dicts for this poll run.
    """
    changes = []
    name = domain.name

    checks: list[tuple[str, str, Any]] = [
        ("DMARC",   f"_dmarc.{name}",            _txt_lookup(f"_dmarc.{name}")),
        ("SPF",     name,                         _txt_lookup(name)),
        ("MX",      name,                         _mx_lookup(name)),
        ("MTA-STS", f"_mta-sts.{name}",           _txt_lookup(f"_mta-sts.{name}")),
        ("TLS-RPT", f"_smtp._tls.{name}",         _txt_lookup(f"_smtp._tls.{name}")),
        ("CNAME",   f"mta-sts.{name}",            _cname_lookup(f"mta-sts.{name}")),
    ]

    for record_type, host, coro in checks:
        current = await coro
        previous = await _last_value(db, domain.id, record_type, host)

        if current != previous:
            if previous is None and current is not None:
                summary = f"{record_type} record created"
            elif current is None:
                summary = f"{record_type} record removed"
            else:
                summary = f"{record_type} record changed"

            await _record_change(db, domain.id, domain.tenant_id, record_type, host, previous, current, summary, name)
            changes.append({"type": record_type, "host": host, "summary": summary, "value": current})

    # DKIM: check known selectors
    for sel in DKIM_SELECTORS:
        host = f"{sel}._domainkey.{name}"
        current = await _txt_lookup(host)
        previous = await _last_value(db, domain.id, "DKIM", host)
        if current != previous:
            summary = f"DKIM selector {sel}._domainkey {'added' if previous is None else 'changed' if current else 'removed'}"
            await _record_change(db, domain.id, domain.tenant_id, "DKIM", host, previous, current, summary, name)
            changes.append({"type": "DKIM", "host": host, "summary": summary, "value": current})

    log.info("DNS poll for %s: %d changes", name, len(changes))
    return changes


async def get_dns_timeline(db: AsyncSession, domain_id: uuid.UUID, limit: int = 50) -> list[DnsRecord]:
    stmt = (
        select(DnsRecord)
        .where(DnsRecord.domain_id == domain_id)
        .order_by(DnsRecord.detected_at.desc())
        .limit(limit)
    )
    result = await db.execute(stmt)
    return result.scalars().all()


async def poll_all_domains() -> None:
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(Domain).where(Domain.is_active == True))
        domains = result.scalars().all()
        for domain in domains:
            try:
                await poll_domain_dns(db, domain)
            except Exception:
                log.exception("DNS poll failed for %s", domain.name)
