"""
DMARC aggregated data endpoints.
All data is read from pre-computed dmarc_aggregates — never raw records.
"""
from __future__ import annotations

import uuid
from collections import defaultdict

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import Domain, DmarcAggregate, DmarcRecord
from app.models.sender_recommendation import SenderRecommendation
from app.models.user import User
from app.routers.auth import get_current_user
from app.schemas.dmarc import (
    DmarcOverviewOut, DmarcSourceOut, DmarcIpOut, DmarcAuthDetailOut, DmarcComplianceOut,
    RecordDiffOut, SubdomainGroupOut,
)
from app.services.dmarc_service import compute_compliance, generate_record_diff, explain_auth_result
from app.services.source_classifier import classify_source
from app.services.verdict_service import compute_verdict

router = APIRouter(prefix="/domains/{domain_id}/dmarc", tags=["dmarc"])


async def _get_domain(domain_id: str, tenant_id: uuid.UUID, db: AsyncSession) -> Domain:
    result = await db.execute(select(Domain).where(Domain.id == domain_id, Domain.tenant_id == tenant_id))
    domain = result.scalar_one_or_none()
    if not domain:
        raise HTTPException(status_code=404, detail="Domain not found")
    return domain


def _group_by_header_from(aggs: list[DmarcAggregate], domain_name: str) -> dict[str, list[DmarcAggregate]]:
    """Bucket aggregates by the domain that actually sent them (header_from),
    falling back to domain_name for the rare row with no header_from at all."""
    groups: dict[str, list[DmarcAggregate]] = defaultdict(list)
    for a in aggs:
        groups[(a.header_from or domain_name).strip().lower()].append(a)
    return groups


def _build_sources(aggs: list[DmarcAggregate]) -> list[DmarcSourceOut]:
    """
    Group a set of aggregates by source_org (the sending ESP/IP), each with
    its IP/auth-detail drill-down. Pulled out as its own function so it can
    be called once over everything (the flat `sources` list, kept for
    backward compatibility) and again per header-from bucket (the new
    subdomain folding below) without duplicating this logic.
    """
    org_groups: dict[str, list[DmarcAggregate]] = defaultdict(list)
    for agg in aggs:
        org_groups[agg.source_org].append(agg)

    sources: list[DmarcSourceOut] = []
    for org, org_aggs in org_groups.items():
        ip_groups: dict[str, list[DmarcAggregate]] = defaultdict(list)
        for a in org_aggs:
            ip_groups[a.source_ip].append(a)

        ips: list[DmarcIpOut] = []
        for ip, ip_aggs in ip_groups.items():
            auth_details: list[DmarcAuthDetailOut] = []
            for a in ip_aggs:
                dmarc_res_row = "pass" if (a.dkim_aligned or a.spf_aligned) else "fail"
                expl = explain_auth_result(a.dkim_aligned, a.spf_aligned, a.dkim_result, a.spf_result)
                verd = compute_verdict(
                    header_from=a.header_from,
                    envelope_from=a.envelope_from,
                    dkim_domain=a.dkim_domain,
                    dkim_result=a.dkim_result,
                    dkim_aligned=a.dkim_aligned,
                    spf_domain=a.spf_domain,
                    spf_result=a.spf_result,
                    spf_aligned=a.spf_aligned,
                    dmarc_result=dmarc_res_row,
                )
                auth_details.append(DmarcAuthDetailOut(
                    header_from=a.header_from,
                    envelope_from=a.envelope_from,
                    dkim_selector=a.dkim_selector,
                    dkim_domain=a.dkim_domain,
                    dkim_result=a.dkim_result,
                    dkim_aligned=a.dkim_aligned,
                    spf_domain=a.spf_domain,
                    spf_result=a.spf_result,
                    spf_aligned=a.spf_aligned,
                    dmarc_result=dmarc_res_row,
                    disposition=a.disposition,
                    volume=a.total_count,
                    explanation=expl,
                    **verd,
                ))

            rep = ip_aggs[0]
            ip_total = sum(a.total_count for a in ip_aggs)
            dmarc_res = "pass" if any(a.dkim_aligned or a.spf_aligned for a in ip_aggs) else "fail"
            # Envelope mismatch flag for the IP row indicator (use dominant auth detail)
            dominant = max(auth_details, key=lambda d: d.volume)
            ips.append(DmarcIpOut(
                source_ip=ip,
                rdns=rep.rdns,
                asn=rep.asn,
                volume=ip_total,
                spf_result=rep.spf_result,
                dkim_result=rep.dkim_result,
                dmarc_result=dmarc_res,
                dkim_aligned=any(a.dkim_aligned for a in ip_aggs),
                spf_aligned=any(a.spf_aligned for a in ip_aggs),
                envelope_mismatch=dominant.envelope_mismatch,
                known_esp=dominant.known_esp,
                auth_details=auth_details,
            ))

        # Org-level classification (use first agg as representative)
        rep_agg = org_aggs[0]
        cls = classify_source({
            "dkim_aligned": any(a.dkim_aligned for a in org_aggs),
            "spf_aligned": any(a.spf_aligned for a in org_aggs),
            "dkim_result": rep_agg.dkim_result,
            "spf_result": rep_agg.spf_result,
            "rdns": rep_agg.rdns,
            "asn": rep_agg.asn,
            "org_name": org,
            "source_org": org,
            "dkim_domain": rep_agg.dkim_domain,
            "header_from": rep_agg.header_from,
        })
        org_vol = sum(a.total_count for a in org_aggs)
        org_pass = sum(a.pass_count for a in org_aggs)
        dkim_aligned_org = any(a.dkim_aligned for a in org_aggs)
        spf_aligned_org = any(a.spf_aligned for a in org_aggs)

        sources.append(DmarcSourceOut(
            source_org=org,
            volume=org_vol,
            spf_alignment="ALIGNED" if spf_aligned_org else ("FAIL" if rep_agg.spf_result == "fail" else "UNALIGNED"),
            dkim_alignment="ALIGNED" if dkim_aligned_org else ("NONE" if not rep_agg.dkim_result or rep_agg.dkim_result == "none" else "UNALIGNED"),
            dmarc_result="PASS" if org_pass > 0 else "FAIL",
            classification=cls["classification"],
            classification_label=cls["label"],
            classification_reason=cls["reason"],
            classification_confidence=cls["confidence"],
            recommended_action=cls["action"],
            ips=sorted(ips, key=lambda x: x.volume, reverse=True),
        ))

    sources.sort(key=lambda s: s.volume, reverse=True)
    return sources


@router.get("", response_model=DmarcOverviewOut)
async def get_dmarc_overview(
    domain_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    domain = await _get_domain(domain_id, user.tenant_id, db)

    # Load all aggregates for this domain
    result = await db.execute(
        select(DmarcAggregate).where(DmarcAggregate.domain_id == domain.id)
    )
    aggs = result.scalars().all()

    if not aggs:
        return DmarcOverviewOut(
            domain=domain.name,
            policy=domain.dmarc_policy,
            pct=domain.dmarc_pct,
            compliance=DmarcComplianceOut(total=0, pass_count=0, fail_count=0, unaligned_count=0, compliance_pct=None),
            sources=[],
        )

    sources = _build_sources(aggs)

    total_msgs = sum(a.total_count for a in aggs)
    total_pass = sum(a.pass_count for a in aggs)
    total_fail = sum(a.fail_count for a in aggs)
    total_unaligned = sum(a.unaligned_count for a in aggs)
    comp_pct = round(total_pass / total_msgs * 100, 1) if total_msgs else None

    dkim_pass = sum(a.total_count for a in aggs if a.dkim_aligned)
    spf_pass  = sum(a.total_count for a in aggs if a.spf_aligned)
    dkim_pct  = round(dkim_pass / total_msgs * 100, 1) if total_msgs else None
    spf_pct   = round(spf_pass  / total_msgs * 100, 1) if total_msgs else None

    # Fold sources under the header-from domain that actually sent them.
    # Per DMARC's tree-walk behaviour, a subdomain with no DMARC record of
    # its own is evaluated against the organizational domain's record and
    # its aggregate data arrives here regardless of whether it's separately
    # monitored — see SubdomainGroupOut's docstring.
    header_from_groups = _group_by_header_from(aggs, domain.name)

    monitored_names: set[str] = set()
    if len(header_from_groups) > 1:
        monitored_result = await db.execute(
            select(Domain.name).where(Domain.tenant_id == user.tenant_id, Domain.is_active == True)
        )
        monitored_names = {n.lower() for n in monitored_result.scalars().all()}

    subdomain_groups = [
        SubdomainGroupOut(
            header_from=header_from,
            is_primary=(header_from == domain.name.lower()),
            is_monitored=(header_from in monitored_names) or (header_from == domain.name.lower()),
            volume=sum(a.total_count for a in group_aggs),
            sources=_build_sources(group_aggs),
        )
        for header_from, group_aggs in header_from_groups.items()
    ]
    # Primary domain's own traffic first, then subdomains by volume.
    subdomain_groups.sort(key=lambda g: (not g.is_primary, -g.volume))

    return DmarcOverviewOut(
        domain=domain.name,
        policy=domain.dmarc_policy,
        pct=domain.dmarc_pct,
        compliance=DmarcComplianceOut(
            total=total_msgs,
            pass_count=total_pass,
            fail_count=total_fail,
            unaligned_count=total_unaligned,
            compliance_pct=comp_pct,
            dkim_pct=dkim_pct,
            spf_pct=spf_pct,
        ),
        sources=sources,
        subdomain_groups=subdomain_groups,
    )


@router.get("/record-diff", response_model=RecordDiffOut)
async def get_record_diff(
    domain_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    domain = await _get_domain(domain_id, user.tenant_id, db)
    diff = generate_record_diff(domain)

    # Gate checks
    aggs = (await db.execute(select(DmarcAggregate).where(DmarcAggregate.domain_id == domain.id))).scalars().all()
    fail_sources = [a.source_org for a in aggs if a.fail_count > 0 and a.classification != "spoof"]
    gates = [
        {"label": "Primary senders aligned", "ok": len(fail_sources) == 0},
        {"label": "At least 30 days of report data collected", "ok": len(aggs) > 0},
    ]
    if fail_sources:
        for src in set(fail_sources[:3]):
            gates.append({"label": f"{src} — still failing alignment", "ok": False})

    return RecordDiffOut(
        host=diff["host"],
        current=diff["current"],
        proposed=diff["proposed"],
        why=f"Advancing {domain.name} from {domain.dmarc_stage} to the next policy stage.",
        gates=gates,
        ready=all(g["ok"] for g in gates),
    )


@router.get("/sender-recommendations")
async def get_sender_recommendations(
    domain_id: str,
    include_dismissed: bool = Query(False),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    from datetime import datetime, timezone

    domain = await _get_domain(domain_id, user.tenant_id, db)
    stmt = (
        select(SenderRecommendation)
        .where(SenderRecommendation.domain_id == domain.id)
        .order_by(SenderRecommendation.created_at.desc())
    )
    if not include_dismissed:
        stmt = stmt.where(SenderRecommendation.dismissed == False)
    recs = (await db.execute(stmt)).scalars().all()
    now = datetime.now(timezone.utc)
    return [
        {
            "id": str(r.id),
            "source_org": r.source_org,
            "source_ip": r.source_ip,
            "classification": r.classification,
            "recommendation": r.recommendation,
            "dns_fix": r.dns_fix,
            "is_ai": r.is_ai,
            "dismissed": r.dismissed,
            "snoozed_until": r.snoozed_until.isoformat() if r.snoozed_until else None,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in recs
        # A snooze that hasn't elapsed yet hides the item without losing it —
        # Part 3 #15. Once snoozed_until passes, it reappears on its own,
        # same as it would have if never snoozed.
        if not (r.snoozed_until and r.snoozed_until > now)
    ]


@router.post("/sender-recommendations/{rec_id}/dismiss")
async def dismiss_sender_recommendation(
    domain_id: str,
    rec_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    domain = await _get_domain(domain_id, user.tenant_id, db)
    result = await db.execute(
        select(SenderRecommendation).where(
            SenderRecommendation.id == rec_id,
            SenderRecommendation.domain_id == domain.id,
        )
    )
    rec = result.scalar_one_or_none()
    if not rec:
        raise HTTPException(status_code=404, detail="Recommendation not found")
    rec.dismissed = True
    await db.commit()
    return {"ok": True}


@router.post("/sender-recommendations/{rec_id}/snooze")
async def snooze_sender_recommendation(
    domain_id: str,
    rec_id: str,
    days: int = Query(14, ge=1, le=90),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """
    "Not now, remind me in N days" — Part 3 #15, the third state between
    act-now and dismiss-forever. The item simply stops appearing in the
    default list until snoozed_until passes, then reappears unchanged.
    """
    from datetime import datetime, timedelta, timezone

    domain = await _get_domain(domain_id, user.tenant_id, db)
    result = await db.execute(
        select(SenderRecommendation).where(
            SenderRecommendation.id == rec_id,
            SenderRecommendation.domain_id == domain.id,
        )
    )
    rec = result.scalar_one_or_none()
    if not rec:
        raise HTTPException(status_code=404, detail="Recommendation not found")
    rec.snoozed_until = datetime.now(timezone.utc) + timedelta(days=days)
    await db.commit()
    return {"ok": True, "snoozed_until": rec.snoozed_until.isoformat()}


@router.post("/mark-published")
async def mark_dmarc_published(
    domain_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    domain = await _get_domain(domain_id, user.tenant_id, db)
    domain.dmarc_record_published = True
    await db.commit()
    return {"ok": True}
