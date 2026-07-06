"""
Parse DMARC aggregate report XML (RFC 7489) into DB rows.
"""
from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import datetime, timezone

from lxml import etree
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import AsyncSessionLocal
from app.models import Domain, DmarcReport, DmarcRecord
from app.models.sender_recommendation import SenderRecommendation

log = logging.getLogger(__name__)


def _ts(epoch: str) -> datetime:
    return datetime.fromtimestamp(int(epoch), tz=timezone.utc)


def _text(el, tag: str, default: str = "") -> str:
    child = el.find(tag)
    return child.text.strip() if child is not None and child.text else default


async def parse_dmarc_xml(db: AsyncSession, domain: Domain, xml_text: str) -> DmarcReport | None:
    root = etree.fromstring(xml_text.encode())

    meta = root.find("report_metadata")
    report_id = _text(meta, "report_id")

    # Idempotency guard — mirrors the DB-level partial unique index
    # (uq_dmarc_reports_domain_report). Checked here too, not just left to
    # the constraint, because letting an IntegrityError bubble up from
    # poll_inbox's per-message try/except means the message never gets
    # marked \Seen and gets retried forever. A clean early-return here lets
    # the caller still mark it seen.
    if report_id:
        existing = await db.execute(
            select(DmarcReport).where(DmarcReport.domain_id == domain.id, DmarcReport.report_id == report_id)
        )
        if existing.scalar_one_or_none():
            log.info("DMARC report %s already ingested for domain %s — skipping duplicate", report_id, domain.name)
            return None

    report = DmarcReport(
        id=uuid.uuid4(),
        domain_id=domain.id,
        report_id=report_id,
        org_name=_text(meta, "org_name"),
        org_email=_text(meta, "email"),
        period_begin=_ts(_text(meta.find("date_range"), "begin")),
        period_end=_ts(_text(meta.find("date_range"), "end")),
        raw_xml=xml_text,
    )
    db.add(report)

    for record_el in root.findall("record"):
        row_el = record_el.find("row")
        policy_el = row_el.find("policy_evaluated") if row_el is not None else None
        ids_el = record_el.find("identifiers")
        auth_el = record_el.find("auth_results")

        source_ip = _text(row_el, "source_ip")
        count = int(_text(row_el, "count", "0"))
        disposition = _text(policy_el, "disposition")
        dkim_aligned = _text(policy_el, "dkim") == "pass"
        spf_aligned = _text(policy_el, "spf") == "pass"
        dmarc_result = "pass" if (dkim_aligned or spf_aligned) else "fail"

        header_from = _text(ids_el, "header_from")
        envelope_from = _text(ids_el, "envelope_from") or None
        envelope_to = _text(ids_el, "envelope_to") or None

        # First DKIM result
        dkim_el = auth_el.find("dkim") if auth_el is not None else None
        dkim_domain = _text(dkim_el, "domain") if dkim_el is not None else None
        dkim_selector = _text(dkim_el, "selector") if dkim_el is not None else None
        dkim_result = _text(dkim_el, "result") if dkim_el is not None else None

        # First SPF result
        spf_el = auth_el.find("spf") if auth_el is not None else None
        spf_domain = _text(spf_el, "domain") if spf_el is not None else None
        spf_result = _text(spf_el, "result") if spf_el is not None else None

        rec = DmarcRecord(
            id=uuid.uuid4(),
            report_id=report.id,
            domain_id=domain.id,
            source_ip=source_ip,
            count=count,
            disposition=disposition,
            dkim_aligned=dkim_aligned,
            spf_aligned=spf_aligned,
            dmarc_result=dmarc_result,
            header_from=header_from,
            envelope_from=envelope_from,
            envelope_to=envelope_to,
            dkim_domain=dkim_domain or None,
            dkim_selector=dkim_selector or None,
            dkim_result=dkim_result or None,
            spf_domain=spf_domain or None,
            spf_result=spf_result or None,
        )
        db.add(rec)

    await db.commit()

    # Detect new source_orgs and generate sender recommendations in background
    new_orgs: list[tuple[str, str | None, str | None, str | None, int, int]] = []
    for record_el in root.findall("record"):
        row_el = record_el.find("row")
        auth_el = record_el.find("auth_results")
        policy_el = row_el.find("policy_evaluated") if row_el is not None else None

        source_ip = _text(row_el, "source_ip")
        count = int(_text(row_el, "count", "0"))
        dkim_aligned = _text(policy_el, "dkim") == "pass"
        spf_aligned = _text(policy_el, "spf") == "pass"
        dmarc_pass = dkim_aligned or spf_aligned

        spf_el = auth_el.find("spf") if auth_el is not None else None
        spf_domain = _text(spf_el, "domain") if spf_el is not None else None
        dkim_el = auth_el.find("dkim") if auth_el is not None else None
        dkim_result = _text(dkim_el, "result") if dkim_el is not None else None
        spf_result = _text(spf_el, "result") if spf_el is not None else None

        # Use SPF domain as source_org proxy; fall back to IP
        org = spf_domain or source_ip
        if org:
            new_orgs.append((org, source_ip, dkim_result, spf_result, count, count if dmarc_pass else 0))

    if new_orgs:
        asyncio.create_task(_bg_sender_recs(domain.id, domain.name, new_orgs))

    return report


async def _bg_sender_recs(
    domain_id: uuid.UUID,
    domain_name: str,
    org_entries: list[tuple[str, str | None, str | None, str | None, int, int]],
) -> None:
    """
    For each source_org in this report that has no prior recommendation, generate one.
    Runs entirely in a fresh session — never blocks the parser.
    """
    from app.services.advisor_service import generate_sender_recommendation

    async with AsyncSessionLocal() as db:
        existing = set(
            row[0]
            for row in (
                await db.execute(
                    select(SenderRecommendation.source_org)
                    .where(SenderRecommendation.domain_id == domain_id)
                )
            ).all()
        )

    # Collapse duplicate orgs in this report (sum counts)
    merged: dict[str, tuple[str | None, str | None, str | None, int, int]] = {}
    for org, ip, dkim_r, spf_r, total, passed in org_entries:
        if org in merged:
            _, _, _, t, p = merged[org]
            merged[org] = (ip, dkim_r, spf_r, t + total, p + passed)
        else:
            merged[org] = (ip, dkim_r, spf_r, total, passed)

    for org, (ip, dkim_r, spf_r, total, passed) in merged.items():
        if org in existing:
            continue
        try:
            result = await generate_sender_recommendation(
                source_org=org,
                source_ip=ip,
                domain_name=domain_name,
                dkim_result=dkim_r,
                spf_result=spf_r,
                total_count=total,
                pass_count=passed,
            )
            async with AsyncSessionLocal() as db:
                db.add(SenderRecommendation(
                    id=uuid.uuid4(),
                    domain_id=domain_id,
                    source_org=org,
                    source_ip=ip,
                    classification=result["classification"],
                    recommendation=result["recommendation"],
                    dns_fix=result["dns_fix"],
                    is_ai=result["is_ai"],
                ))
                await db.commit()
        except Exception:
            log.exception("Sender recommendation failed for org=%s domain=%s", org, domain_name)
