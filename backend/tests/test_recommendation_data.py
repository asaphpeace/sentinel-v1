"""
GUIDED_ONBOARDING_PLAN.md Part 3 #9 — the dry-run preview UI tells the user
the simulation is "based on the last 30 days of data" (RoadmapTrack.vue).
This locks in that _dmarc_sources() actually windows by that promise instead
of silently summing all-time history, which is what shipped originally.
"""
import pytest

from app.services.recommendation_data import build_domain_input, _SOURCE_WINDOW_DAYS
from tests.factories import make_tenant, make_domain, make_dmarc_aggregate


@pytest.mark.asyncio
async def test_dmarc_sources_excludes_aggregates_older_than_the_window(db_session):
    tenant = await make_tenant(db_session)
    domain = await make_domain(db_session, tenant)

    # Inside the window — should count.
    await make_dmarc_aggregate(
        db_session, domain, days_ago=5, source_org="Recent Sender",
        total_count=100, fail_count=10, classification="authorized",
    )
    # Outside the window — must NOT count, even though it's real historical data.
    await make_dmarc_aggregate(
        db_session, domain, days_ago=_SOURCE_WINDOW_DAYS + 30, source_org="Stale Sender",
        total_count=500, fail_count=500, classification="authorized",
    )
    await db_session.flush()

    domain_input = await build_domain_input(db_session, domain)
    orgs = {s.source_org for s in domain_input.sources}

    assert "Recent Sender" in orgs
    assert "Stale Sender" not in orgs
