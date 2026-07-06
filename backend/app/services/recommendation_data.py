"""
Builds DomainRecommendationInput for recommendation_engine.py from the database.

This is the only module that touches a DB session for recommendations — the
engine itself stays pure. Keeping the split means the gate logic in
recommendation_engine.py can be unit-tested with plain dataclasses, while any
query inefficiency or data-shape change is isolated here.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Domain, DmarcAggregate, DmarcRecord, DmarcReport, SslCert, TlsPolicy, TlsReport
from app.services.recommendation_engine import (
    DomainRecommendationInput,
    SourceVolumeInput,
    TLS_ENFORCE_GATE_PCT,
    TLS_ENFORCE_MIN_DAYS,
)

_WINDOW_DAYS = 7  # current/prior compliance comparison window
_SOURCE_WINDOW_DAYS = 30  # dry-run simulation / regression-gate lookback window


async def _dmarc_days_collected(db: AsyncSession, domain_id: uuid.UUID) -> int:
    stmt = select(func.min(DmarcReport.period_begin)).where(DmarcReport.domain_id == domain_id)
    earliest = (await db.execute(stmt)).scalar()
    if earliest is None:
        return 0
    now = datetime.now(timezone.utc)
    if earliest.tzinfo is None:
        earliest = earliest.replace(tzinfo=timezone.utc)
    return max((now - earliest).days, 0)


async def _dmarc_window_compliance(
    db: AsyncSession, domain_id: uuid.UUID, start: datetime, end: datetime
) -> float | None:
    stmt = (
        select(
            func.sum(DmarcRecord.count).label("total"),
            func.sum(case((DmarcRecord.dmarc_result == "pass", DmarcRecord.count), else_=0)).label("passed"),
        )
        .join(DmarcReport, DmarcRecord.report_id == DmarcReport.id)
        .where(
            DmarcRecord.domain_id == domain_id,
            DmarcReport.period_begin >= start,
            DmarcReport.period_begin < end,
        )
    )
    row = (await db.execute(stmt)).one()
    if not row.total:
        return None
    return round(row.passed / row.total * 100, 1)


async def _dmarc_sources(db: AsyncSession, domain_id: uuid.UUID, since: datetime) -> list[SourceVolumeInput]:
    """
    Per-source volume from DmarcAggregate, windowed to `since` — feeds both
    the regression gate in _evaluate_dmarc() and the dry-run simulation in
    simulate_advance(). Both need a rolling window, not all-time history: a
    source that failed months ago and has since been fixed shouldn't gate a
    stage advance forever, and the dry-run preview explicitly promises "the
    last 30 days of data" in its UI copy (RoadmapTrack.vue) — it must
    actually compute against that window, not silently sum everything ever
    ingested. See GUIDED_ONBOARDING_PLAN.md Part 3 #9.
    """
    stmt = (
        select(
            DmarcAggregate.source_org,
            DmarcAggregate.classification,
            func.sum(DmarcAggregate.total_count).label("total_count"),
            func.sum(DmarcAggregate.fail_count).label("fail_count"),
            func.sum(DmarcAggregate.unaligned_count).label("unaligned_count"),
        )
        .where(DmarcAggregate.domain_id == domain_id, DmarcAggregate.period_begin >= since)
        .group_by(DmarcAggregate.source_org, DmarcAggregate.classification)
    )
    rows = (await db.execute(stmt)).all()
    return [
        SourceVolumeInput(
            source_org=r.source_org,
            total_count=r.total_count or 0,
            fail_count=r.fail_count or 0,
            unaligned_count=r.unaligned_count or 0,
            classification=r.classification,
        )
        for r in rows
    ]


async def _tls_daily_pass_rates(db: AsyncSession, domain_id: uuid.UUID, since: datetime) -> list[tuple[datetime, float]]:
    """One (period_begin date, pass rate %) per TLS report period, most recent first."""
    stmt = (
        select(
            TlsReport.period_begin,
            func.sum(TlsPolicy.total_successful_session_count).label("ok"),
            func.sum(TlsPolicy.total_failure_session_count).label("fail"),
        )
        .join(TlsPolicy, TlsPolicy.report_id == TlsReport.id)
        .where(TlsReport.domain_id == domain_id, TlsReport.period_begin >= since)
        .group_by(TlsReport.period_begin)
        .order_by(TlsReport.period_begin.desc())
    )
    rows = (await db.execute(stmt)).all()
    out = []
    for r in rows:
        total = (r.ok or 0) + (r.fail or 0)
        rate = round((r.ok or 0) / total * 100, 2) if total else 0.0
        out.append((r.period_begin, rate))
    return out


def _tls_pass_pct_and_stable_days(daily_rates: list[tuple[datetime, float]]) -> tuple[float | None, int]:
    """
    Overall pass pct across the window, and the number of consecutive most-recent
    days (walking backward, no gaps) whose pass rate met the enforce gate.
    """
    if not daily_rates:
        return None, 0

    stable_days = 0
    expected_date = daily_rates[0][0].date()
    for period_begin, rate in daily_rates:
        if period_begin.date() != expected_date or rate < TLS_ENFORCE_GATE_PCT:
            break
        stable_days += 1
        expected_date -= timedelta(days=1)

    avg_rate = round(sum(r for _, r in daily_rates) / len(daily_rates), 2)
    return avg_rate, stable_days


async def _cert_health(db: AsyncSession, domain_id: uuid.UUID) -> tuple[int | None, bool]:
    stmt = select(SslCert.days_remaining, SslCert.status).where(
        SslCert.domain_id == domain_id, SslCert.host_type == "mx"
    )
    rows = (await db.execute(stmt)).all()
    if not rows:
        return None, False
    min_days = min((r.days_remaining for r in rows if r.days_remaining is not None), default=None)
    critical_or_expired = any(r.status in ("critical", "expired") for r in rows)
    return min_days, critical_or_expired


async def _undispositioned_mail_subdomains(db: AsyncSession, domain: Domain) -> list[str]:
    """
    PAIN_POINT_RESOLUTION_PLAN.md Pain 6's gate data. Deliberately uses only
    subdomain_discovery_service's DMARC-data-mining source (_from_dmarc) —
    not the full discover_subdomains(), which also hits crt.sh over the
    network. This function runs on every recommendation evaluation
    (background job + every Roadmap page load), so it must stay a pure
    local-DB query; the CT-log/active-probe sources stay opt-in via the
    dedicated discovery endpoint, not folded into this hot path.
    """
    from app.services.subdomain_discovery_service import _from_dmarc
    from app.models import SubdomainDisposition

    mail_subdomains = await _from_dmarc(db, domain)
    if not mail_subdomains:
        return []

    dispositioned = (await db.execute(
        select(SubdomainDisposition.hostname).where(SubdomainDisposition.domain_id == domain.id)
    )).scalars().all()
    dispositioned_set = {h.lower() for h in dispositioned}

    return sorted(h for h in mail_subdomains if h not in dispositioned_set)


async def build_domain_input(db: AsyncSession, domain: Domain) -> DomainRecommendationInput:
    now = datetime.now(timezone.utc)
    current_start = now - timedelta(days=_WINDOW_DAYS)
    prior_start = now - timedelta(days=_WINDOW_DAYS * 2)

    days_collected = await _dmarc_days_collected(db, domain.id)
    compliance_current = await _dmarc_window_compliance(db, domain.id, current_start, now)
    compliance_prior = await _dmarc_window_compliance(db, domain.id, prior_start, current_start)
    sources = await _dmarc_sources(db, domain.id, now - timedelta(days=_SOURCE_WINDOW_DAYS))

    tls_since = now - timedelta(days=TLS_ENFORCE_MIN_DAYS)
    daily_rates = await _tls_daily_pass_rates(db, domain.id, tls_since)
    tls_pass_pct, tls_pass_days_stable = _tls_pass_pct_and_stable_days(daily_rates)

    min_cert_days, cert_critical_or_expired = await _cert_health(db, domain.id)
    undispositioned_subdomains = await _undispositioned_mail_subdomains(db, domain)

    return DomainRecommendationInput(
        domain_id=str(domain.id),
        domain_name=domain.name,
        dmarc_stage=domain.dmarc_stage,
        dmarc_days_collected=days_collected,
        dmarc_compliance_pct=compliance_current,
        dmarc_compliance_pct_prior=compliance_prior,
        sources=sources,
        mta_sts_stage=domain.mta_sts_stage,
        tls_pass_pct=tls_pass_pct,
        tls_pass_days_stable=tls_pass_days_stable,
        min_cert_days=min_cert_days,
        cert_status_critical_or_expired=cert_critical_or_expired,
        undispositioned_subdomains=undispositioned_subdomains,
    )
