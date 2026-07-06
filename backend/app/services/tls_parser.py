"""
Parse SMTP TLS report JSON (RFC 8460) into DB rows.
"""
from __future__ import annotations

import asyncio
import json
import logging
import uuid
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import AsyncSessionLocal
from app.models import Domain, TlsReport, TlsPolicy, TlsFailureDetail, SenderRecommendation

log = logging.getLogger(__name__)


def _ts(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


async def parse_tls_json(db: AsyncSession, domain: Domain, json_text: str) -> TlsReport | None:
    data = json.loads(json_text)
    report_id = data.get("report-id", "")

    # Same idempotency guard as parse_dmarc_xml — see that function's comment.
    if report_id:
        existing = await db.execute(
            select(TlsReport).where(TlsReport.domain_id == domain.id, TlsReport.report_id == report_id)
        )
        if existing.scalar_one_or_none():
            log.info("TLS report %s already ingested for domain %s — skipping duplicate", report_id, domain.name)
            return None

    report = TlsReport(
        id=uuid.uuid4(),
        domain_id=domain.id,
        report_id=report_id,
        org_name=data.get("organization-name", ""),
        org_contact=data.get("contact-info", ""),
        period_begin=_ts(data["date-range"]["start-datetime"]),
        period_end=_ts(data["date-range"]["end-datetime"]),
        raw_json=json_text,
    )
    db.add(report)

    new_failures: list[tuple[str, str, int]] = []  # (mx_host, result_type, failed_count)

    for pol in data.get("policies", []):
        pinfo = pol.get("policy", {})
        policy = TlsPolicy(
            id=uuid.uuid4(),
            report_id=report.id,
            domain_id=domain.id,
            policy_type=pinfo.get("policy-type", ""),
            policy_domain=pinfo.get("policy-domain", ""),
            policy_mx_host=pinfo.get("mx-host", None),
            policy_string=json.dumps(pinfo.get("policy-string", [])),
            total_successful_session_count=pol.get("summary", {}).get("total-successful-session-count", 0),
            total_failure_session_count=pol.get("summary", {}).get("total-failure-session-count", 0),
        )
        db.add(policy)

        for fd in pol.get("failure-details", []):
            detail = TlsFailureDetail(
                id=uuid.uuid4(),
                policy_id=policy.id,
                domain_id=domain.id,
                result_type=fd.get("result-type", ""),
                sending_mta_ip=fd.get("sending-mta-ip"),
                receiving_mx_hostname=fd.get("receiving-mx-hostname"),
                receiving_mx_helo=fd.get("receiving-mx-helo"),
                receiving_ip=fd.get("receiving-ip"),
                failed_session_count=fd.get("failed-session-count", 0),
                additional_information=fd.get("additional-information"),
                failure_reason_code=fd.get("failure-reason-code"),
            )
            db.add(detail)
            mx_host = fd.get("receiving-mx-hostname") or pinfo.get("mx-host") or "unknown host"
            result_type = fd.get("result-type", "")
            failed_count = fd.get("failed-session-count", 0)
            if result_type and failed_count > 0:
                new_failures.append((mx_host, result_type, failed_count))

    await db.commit()

    if new_failures:
        asyncio.create_task(_bg_tls_recs(domain.id, new_failures))

    return report


async def _bg_tls_recs(domain_id: uuid.UUID, failures: list[tuple[str, str, int]]) -> None:
    """
    Extends the DMARC sender-recommendation pipeline to TLS failures
    (GUIDED_ONBOARDING_PLAN.md Part 2, item 3). Same "new thing seen ->
    generate a recommendation once" pattern as _bg_sender_recs in
    dmarc_parser.py — runs in a fresh session, never blocks the parser.
    """
    from app.services.advisor_service import generate_tls_recommendation

    # Collapse duplicate (mx_host, result_type) pairs in this report, summing counts.
    merged: dict[tuple[str, str], int] = {}
    for mx_host, result_type, count in failures:
        merged[(mx_host, result_type)] = merged.get((mx_host, result_type), 0) + count

    async with AsyncSessionLocal() as db:
        existing_rows = (await db.execute(
            select(SenderRecommendation.source_org)
            .where(SenderRecommendation.domain_id == domain_id, SenderRecommendation.classification == "tls_issue")
        )).all()
        existing = {row[0] for row in existing_rows}

    for (mx_host, result_type), failed_count in merged.items():
        source_org = f"{mx_host} ({result_type})"
        if source_org in existing:
            continue
        result = generate_tls_recommendation(mx_host, result_type, failed_count)
        async with AsyncSessionLocal() as db:
            db.add(SenderRecommendation(
                id=uuid.uuid4(),
                domain_id=domain_id,
                source_org=source_org,
                source_ip=None,
                classification=result["classification"],
                recommendation=result["recommendation"],
                dns_fix=result["dns_fix"],
                is_ai=result["is_ai"],
            ))
            await db.commit()
