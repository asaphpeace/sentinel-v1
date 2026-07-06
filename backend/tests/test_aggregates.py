"""
B1 — rebuild_aggregates() correctness tests.

Verifies the critical bug fix: period_begin must come from DmarcReport,
not be hardcoded to datetime(2000,1,1).
"""
from datetime import datetime, timezone, timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dmarc_report import DmarcAggregate
from app.services.dmarc_service import rebuild_aggregates
from tests.factories import (
    make_tenant, make_domain, make_dmarc_report, make_dmarc_record
)


async def test_rebuild_sets_real_period_begin(db_session: AsyncSession):
    """Aggregates must use the DmarcReport period, not year 2000."""
    tenant = await make_tenant(db_session)
    domain = await make_domain(db_session, tenant)
    report = await make_dmarc_report(db_session, domain, days_ago=10, period_days=1)
    await make_dmarc_record(db_session, report, domain)
    await db_session.flush()

    await rebuild_aggregates(db_session, domain.id)

    result = await db_session.execute(
        select(DmarcAggregate).where(DmarcAggregate.domain_id == domain.id)
    )
    aggs = result.scalars().all()
    assert len(aggs) == 1

    agg = aggs[0]
    year_2000 = datetime(2000, 1, 1, tzinfo=timezone.utc)
    assert agg.period_begin != year_2000, "period_begin must not be hardcoded to year 2000"
    assert agg.period_begin == report.period_begin


async def test_rebuild_accumulates_counts(db_session: AsyncSession):
    """Multiple records in the same group must sum correctly."""
    tenant = await make_tenant(db_session)
    domain = await make_domain(db_session, tenant)
    report = await make_dmarc_report(db_session, domain)

    # Two records from the same IP with different counts
    await make_dmarc_record(db_session, report, domain, source_ip="1.2.3.4", count=60, dmarc_result="pass")
    await make_dmarc_record(db_session, report, domain, source_ip="1.2.3.4", count=40, dmarc_result="fail")
    await db_session.flush()

    await rebuild_aggregates(db_session, domain.id)

    result = await db_session.execute(
        select(DmarcAggregate).where(
            DmarcAggregate.domain_id == domain.id,
            DmarcAggregate.source_ip == "1.2.3.4",
        )
    )
    agg = result.scalar_one()
    assert agg.total_count == 100
    assert agg.pass_count == 60
    assert agg.fail_count == 40


async def test_rebuild_uses_most_recent_period(db_session: AsyncSession):
    """When the same source appears in multiple reports, the aggregate takes the most recent period."""
    tenant = await make_tenant(db_session)
    domain = await make_domain(db_session, tenant)

    old_report = await make_dmarc_report(db_session, domain, days_ago=30, period_days=1)
    new_report = await make_dmarc_report(db_session, domain, days_ago=5, period_days=1)

    # Same source IP in both reports
    await make_dmarc_record(db_session, old_report, domain, source_ip="5.5.5.5", count=10)
    await make_dmarc_record(db_session, new_report, domain, source_ip="5.5.5.5", count=20)
    await db_session.flush()

    await rebuild_aggregates(db_session, domain.id)

    result = await db_session.execute(
        select(DmarcAggregate).where(
            DmarcAggregate.domain_id == domain.id,
            DmarcAggregate.source_ip == "5.5.5.5",
        )
    )
    agg = result.scalar_one()
    # Period should be from the newer report
    assert agg.period_begin == new_report.period_begin
    assert agg.total_count == 30


async def test_rebuild_is_idempotent(db_session: AsyncSession):
    """Calling rebuild twice must not duplicate rows."""
    tenant = await make_tenant(db_session)
    domain = await make_domain(db_session, tenant)
    report = await make_dmarc_report(db_session, domain)
    await make_dmarc_record(db_session, report, domain)
    await db_session.flush()

    await rebuild_aggregates(db_session, domain.id)
    await rebuild_aggregates(db_session, domain.id)

    result = await db_session.execute(
        select(DmarcAggregate).where(DmarcAggregate.domain_id == domain.id)
    )
    assert len(result.scalars().all()) == 1


async def test_rebuild_empty_produces_no_aggregates(db_session: AsyncSession):
    """A domain with no DMARC records must produce zero aggregates."""
    tenant = await make_tenant(db_session)
    domain = await make_domain(db_session, tenant)
    await db_session.flush()

    await rebuild_aggregates(db_session, domain.id)

    result = await db_session.execute(
        select(DmarcAggregate).where(DmarcAggregate.domain_id == domain.id)
    )
    assert result.scalars().all() == []
