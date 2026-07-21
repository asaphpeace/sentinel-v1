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


def _spf_summary(previous: str | None, current: str | None) -> str:
    if previous is None:
        return "SPF record published for the first time"
    if current is None:
        return "SPF record removed — domain is now unprotected against spoofing"

    def _includes(val: str) -> set[str]:
        return {t for t in val.split() if t.startswith("include:")}

    def _mechanisms(val: str) -> set[str]:
        return {t for t in val.split() if not t.startswith("v=") and not t.startswith("include:")}

    def _policy(val: str) -> str:
        for t in val.split():
            if t in ("+all", "-all", "~all", "?all", "all"):
                return t
        return "none"

    added_inc   = _includes(current)   - _includes(previous)
    removed_inc = _includes(previous)  - _includes(current)
    prev_pol    = _policy(previous)
    curr_pol    = _policy(current)

    parts = []
    if added_inc:
        parts.append(f"added sender(s): {', '.join(sorted(added_inc))}")
    if removed_inc:
        parts.append(f"removed sender(s): {', '.join(sorted(removed_inc))}")
    if prev_pol != curr_pol:
        direction = "tightened" if curr_pol in ("-all",) else "relaxed" if curr_pol in ("~all", "?all", "+all") else "changed"
        parts.append(f"enforcement {direction}: {prev_pol} → {curr_pol}")
    if not parts:
        parts.append("record content modified")
    return "SPF record updated — " + "; ".join(parts)


def _dmarc_summary(previous: str | None, current: str | None) -> str:
    if previous is None:
        return "DMARC record published for the first time"
    if current is None:
        return "DMARC record removed — domain has no DMARC policy"

    def _tag(val: str, tag: str) -> str | None:
        for part in val.split(";"):
            part = part.strip()
            if part.lower().startswith(tag + "="):
                return part.split("=", 1)[1].strip()
        return None

    prev_p = _tag(previous, "p")
    curr_p = _tag(current, "p")
    prev_pct = _tag(previous, "pct")
    curr_pct = _tag(current, "pct")
    prev_sp = _tag(previous, "sp")
    curr_sp = _tag(current, "sp")

    _tighten_order = ["none", "quarantine", "reject"]

    parts = []
    if prev_p != curr_p and prev_p and curr_p:
        try:
            direction = "tightened" if _tighten_order.index(curr_p) > _tighten_order.index(prev_p) else "relaxed"
        except ValueError:
            direction = "changed"
        parts.append(f"policy {direction}: p={prev_p} → p={curr_p}")
    if prev_pct != curr_pct:
        parts.append(f"coverage changed: pct={prev_pct or '100'} → pct={curr_pct or '100'}")
    if prev_sp != curr_sp:
        parts.append(f"subdomain policy changed: sp={prev_sp or 'inherit'} → sp={curr_sp or 'inherit'}")
    if not parts:
        parts.append("reporting or other tag modified")
    return "DMARC record updated — " + "; ".join(parts)


def _mta_sts_summary(previous: str | None, current: str | None) -> str:
    if previous is None:
        return "MTA-STS TXT record published for the first time"
    if current is None:
        return "MTA-STS TXT record removed — MTA-STS enforcement is no longer signalled"

    def _count(val: str) -> int:
        return len([p for p in val.split(" | ") if p.strip()])

    def _id(val: str) -> str | None:
        for part in val.replace(" | ", ";").split(";"):
            part = part.strip()
            if part.lower().startswith("id="):
                return part.split("=", 1)[1].strip()
        return None

    curr_count = _count(current)
    if curr_count > 1:
        return (
            f"Duplicate MTA-STS TXT records detected — {curr_count} records found at this host. "
            "Only one v=STSv1 record is valid; receiving servers will behave unpredictably. "
            "Remove all but the current record from your DNS provider."
        )

    prev_id = _id(previous)
    curr_id = _id(current)
    if prev_id and curr_id and prev_id != curr_id:
        return (
            f"MTA-STS policy ID updated — id= changed from {prev_id} to {curr_id}. "
            "This is expected whenever you publish a new MTA-STS policy file. No action needed if you made this change."
        )

    return "MTA-STS TXT record modified"


def _mx_summary(previous: str | None, current: str | None) -> str:
    if previous is None:
        return "MX records published for the first time"
    if current is None:
        return "All MX records removed — domain can no longer receive email"

    prev_set = set(previous.split(" | "))
    curr_set = set(current.split(" | "))
    added   = curr_set - prev_set
    removed = prev_set - curr_set
    parts = []
    if added:
        parts.append(f"added: {', '.join(sorted(added))}")
    if removed:
        parts.append(f"removed: {', '.join(sorted(removed))}")
    if not parts:
        return "MX records modified"
    return "MX records changed — " + "; ".join(parts)


def _build_summary(record_type: str, previous: str | None, current: str | None, host: str = "") -> str:
    if record_type == "SPF":
        return _spf_summary(previous, current)
    if record_type == "DMARC":
        return _dmarc_summary(previous, current)
    if record_type == "MTA-STS":
        return _mta_sts_summary(previous, current)
    if record_type == "MX":
        return _mx_summary(previous, current)
    if record_type == "DKIM":
        sel = host.split("._domainkey.")[0] if "._domainkey." in host else host
        if previous is None:
            return f"DKIM key published for selector {sel}"
        if current is None:
            return f"DKIM key removed for selector {sel}"
        return f"DKIM key rotated for selector {sel}"
    if record_type == "TLS-RPT":
        if previous is None:
            return "TLS-RPT reporting record published"
        if current is None:
            return "TLS-RPT reporting record removed"
        return "TLS-RPT reporting address changed"
    if record_type == "CNAME":
        if previous is None:
            return f"CNAME created: {host} → {current}"
        if current is None:
            return f"CNAME removed from {host}"
        return f"CNAME changed: {previous} → {current}"
    # fallback
    if previous is None:
        return f"{record_type} record created"
    if current is None:
        return f"{record_type} record removed"
    return f"{record_type} record changed"


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
            summary = _build_summary(record_type, previous, current, host)
            await _record_change(db, domain.id, domain.tenant_id, record_type, host, previous, current, summary, name)
            changes.append({"type": record_type, "host": host, "summary": summary, "value": current})

    # DKIM: check known selectors
    for sel in DKIM_SELECTORS:
        host = f"{sel}._domainkey.{name}"
        current = await _txt_lookup(host)
        previous = await _last_value(db, domain.id, "DKIM", host)
        if current != previous:
            summary = _build_summary("DKIM", previous, current, host)
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
