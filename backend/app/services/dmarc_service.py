"""
DMARC record generation, DNS checking, compliance computation, and aggregation.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

import dns.exception
from app.services.dns_resolver import resolver as _resolver
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Domain, DmarcRecord, DmarcAggregate
from app.services.reporting_address import rua_mailto
from app.services.source_classifier import classify_source


# ── Record generation ──────────────────────────────────────────────────────────

def generate_dmarc_record(domain_name: str, slug: str, policy: str = "none", pct: int = 100) -> str:
    rua = rua_mailto(slug)
    return f"v=DMARC1; p={policy}; pct={pct}; rua={rua}; ruf={rua}; fo=1"


def next_policy(current: str) -> str | None:
    order = ["none", "quarantine", "reject"]
    try:
        idx = order.index(current)
        return order[idx + 1] if idx + 1 < len(order) else None
    except ValueError:
        return "none"


def generate_record_diff(domain: Domain) -> dict[str, str]:
    """Return current and proposed record strings for the review modal."""
    current = domain.dmarc_policy or f"v=DMARC1; p={domain.dmarc_stage}; pct={domain.dmarc_pct}; rua={rua_mailto(domain.reporting_slug)}"
    proposed_policy = next_policy(domain.dmarc_stage) or "reject"
    proposed = generate_dmarc_record(domain.name, domain.reporting_slug, policy=proposed_policy, pct=25 if proposed_policy == "quarantine" else 100)
    return {"host": f"_dmarc.{domain.name} TXT", "current": current, "proposed": proposed}


# ── DNS check ─────────────────────────────────────────────────────────────────

async def check_dmarc_dns(domain_name: str) -> dict[str, Any]:
    """
    Returns {'exists': bool, 'record': str | None, 'policy': str | None, 'error': str | None}
    """
    try:
        answers = await _resolver.resolve(f"_dmarc.{domain_name}", "TXT")
        for rdata in answers:
            txt = "".join(s.decode() for s in rdata.strings)
            if txt.startswith("v=DMARC1"):
                policy = None
                for part in txt.split(";"):
                    part = part.strip()
                    if part.startswith("p="):
                        policy = part[2:].strip()
                return {"exists": True, "record": txt, "policy": policy, "error": None}
        return {"exists": False, "record": None, "policy": None, "error": None}
    except dns.exception.DNSException as e:
        return {"exists": False, "record": None, "policy": None, "error": str(e)}


# ── Aggregation ────────────────────────────────────────────────────────────────

async def rebuild_aggregates(db: AsyncSession, domain_id: uuid.UUID) -> None:
    """
    Re-compute DmarcAggregate rows from raw DmarcRecord rows for a domain.
    Groups by (source_ip, header_from, envelope_from, dkim_domain, dkim_selector,
               spf_domain, disposition) within each report period.
    """
    # Delete existing aggregates for this domain
    await db.execute(
        text("DELETE FROM dmarc_aggregates WHERE domain_id = :did"),
        {"did": str(domain_id)},
    )

    # Pull all raw records joined with their report period dates
    from app.models.dmarc_report import DmarcReport
    stmt = (
        select(DmarcRecord, DmarcReport.period_begin, DmarcReport.period_end)
        .join(DmarcReport, DmarcRecord.report_id == DmarcReport.id)
        .where(DmarcRecord.domain_id == domain_id)
    )
    result = await db.execute(stmt)
    rows = result.all()

    # Group in Python — small enough for typical report volumes
    groups: dict[tuple, dict] = {}
    for r, period_begin, period_end in rows:
        key = (
            r.source_ip,
            r.header_from,
            r.envelope_from or "",
            r.dkim_domain or "",
            r.dkim_selector or "",
            r.spf_domain or "",
            r.disposition,
        )
        if key not in groups:
            groups[key] = {
                "domain_id": domain_id,
                "source_ip": r.source_ip,
                "header_from": r.header_from,
                "envelope_from": r.envelope_from,
                "dkim_domain": r.dkim_domain,
                "dkim_selector": r.dkim_selector,
                "dkim_result": r.dkim_result,
                "dkim_aligned": r.dkim_aligned,
                "spf_domain": r.spf_domain,
                "spf_result": r.spf_result,
                "spf_aligned": r.spf_aligned,
                "disposition": r.disposition,
                "rdns": r.rdns,
                "asn": r.asn,
                "source_org": r.org_name or r.rdns or r.source_ip,
                "total_count": 0,
                "pass_count": 0,
                "fail_count": 0,
                "unaligned_count": 0,
                "period_begin": period_begin,
                "period_end": period_end,
            }
        g = groups[key]
        g["total_count"] += r.count
        # Use the most recent period seen for this group
        if period_begin > g["period_begin"]:
            g["period_begin"] = period_begin
            g["period_end"] = period_end
        if r.dmarc_result == "pass":
            g["pass_count"] += r.count
        else:
            g["fail_count"] += r.count
            if r.dkim_aligned or r.spf_aligned:
                g["unaligned_count"] += r.count

    now = datetime.now(timezone.utc)
    for key, g in groups.items():
        cls_result = classify_source(g)
        agg = DmarcAggregate(
            id=uuid.uuid4(),
            classification=cls_result["classification"],
            classification_reason=cls_result["reason"],
            classification_confidence=cls_result["confidence"],
            computed_at=now,
            **{k: v for k, v in g.items()},
        )
        db.add(agg)

    await db.commit()


# ── Compliance % ───────────────────────────────────────────────────────────────

async def compute_compliance(db: AsyncSession, domain_id: uuid.UUID) -> float | None:
    stmt = select(
        func.sum(DmarcAggregate.total_count).label("total"),
        func.sum(DmarcAggregate.pass_count).label("passed"),
    ).where(DmarcAggregate.domain_id == domain_id)
    result = await db.execute(stmt)
    row = result.one()
    if not row.total:
        return None
    return round(row.passed / row.total * 100, 1)


# ── Plain-English auth explanation ─────────────────────────────────────────────

AUTH_EXPLANATIONS: dict[tuple, str] = {
    # (dkim_aligned, spf_aligned, dkim_result, spf_result)
    (True,  True,  "pass", "pass"):      "Both SPF and DKIM pass and are aligned to your domain — this is a clean, fully authenticated message.",
    (True,  False, "pass", "pass"):      "DKIM passes and is aligned to your domain. SPF passes but for a different domain (not aligned), so DMARC still passes via DKIM.",
    (False, True,  "pass", "pass"):      "SPF passes and is aligned to your domain. DKIM passes but for a different domain (not aligned), so DMARC still passes via SPF.",
    (True,  False, "pass", "fail"):      "DKIM is signed and aligned to your domain — DMARC passes. SPF failed (possibly a forwarder or relay that changes the envelope sender).",
    (True,  False, "pass", "softfail"):  "DKIM is aligned and passes — DMARC passes. SPF returned a softfail, which is expected when mail is relayed through a third party.",
    (False, True,  "fail", "pass"):      "SPF is aligned and passes — DMARC passes via SPF. The DKIM signature was invalid or missing, which is unusual; check your signing key.",
    (False, False, "pass", "pass"):      "Both SPF and DKIM pass, but neither is aligned to your domain. This is common with bulk senders that sign with their own domain (e.g., mcsv.net). DMARC fails because alignment is the requirement.",
    (False, False, "pass", "fail"):      "DKIM passes but is not aligned to your domain, and SPF fails. DMARC fails. The sender authenticates its own infrastructure but not yours.",
    (False, False, "fail", "pass"):      "DKIM is missing or invalid, SPF passes but not for your domain. DMARC fails. Likely a third-party sender that hasn't been set up with DKIM for your domain.",
    (False, False, "none", "fail"):      "No DKIM signature at all, and SPF failed. This is a hallmark of spoofing or an unauthorized sender.",
    (False, False, "fail", "fail"):      "Both SPF and DKIM fail with no alignment. This message is not authorized to send as your domain — likely a spoof attempt.",
    (False, False, "none", "none"):      "No SPF record evaluated and no DKIM signature. This message has zero authentication — it should not be sending as your domain.",
}

_FALLBACK = "Authentication result could not be fully interpreted. Review the raw SPF and DKIM values above."


def explain_auth_result(
    dkim_aligned: bool,
    spf_aligned: bool,
    dkim_result: str | None,
    spf_result: str | None,
) -> str:
    key = (dkim_aligned, spf_aligned, dkim_result or "none", spf_result or "none")
    return AUTH_EXPLANATIONS.get(key, _FALLBACK)
