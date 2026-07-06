"""
B6 — DNS timeline endpoint tests.
Pagination, change_type, is_security_alert fields.
"""
import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from tests.factories import make_tenant, make_user, make_domain, make_dns_record


# ── Helpers ───────────────────────────────────────────────────────────────────

async def _domain_for(client: AsyncClient, db_session: AsyncSession, tag: str):
    """Create a fresh tenant+domain and log the client in as that tenant."""
    tenant = await make_tenant(db_session, name=f"DNS Corp {tag}")
    user = await make_user(db_session, tenant, email=f"dns-{tag}@test.com", password="pass123")
    domain = await make_domain(db_session, tenant, name="example.com")
    await db_session.flush()

    resp = await client.post(
        "/auth/token",
        data={"username": user.email, "password": "pass123"},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    client.headers.update({"Authorization": f"Bearer {resp.json()['access_token']}"})
    return domain


# ── Pagination ─────────────────────────────────────────────────────────────────

async def test_dns_timeline_returns_list(client: AsyncClient, db_session: AsyncSession):
    domain = await _domain_for(client, db_session, "list")
    await make_dns_record(db_session, domain)
    await db_session.flush()

    resp = await client.get(f"/domains/{domain.id}/dns-timeline")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


async def test_dns_timeline_pagination_limit(client: AsyncClient, db_session: AsyncSession):
    domain = await _domain_for(client, db_session, "limit")
    for i in range(10):
        await make_dns_record(db_session, domain, record_host=f"_dmarc{i}", days_ago=i)
    await db_session.flush()

    resp = await client.get(f"/domains/{domain.id}/dns-timeline?limit=3&offset=0")
    assert resp.status_code == 200
    assert len(resp.json()) == 3


async def test_dns_timeline_pagination_offset(client: AsyncClient, db_session: AsyncSession):
    domain = await _domain_for(client, db_session, "offset")
    for i in range(6):
        await make_dns_record(db_session, domain, record_host=f"host{i}", days_ago=i)
    await db_session.flush()

    page1 = await client.get(f"/domains/{domain.id}/dns-timeline?limit=3&offset=0")
    page2 = await client.get(f"/domains/{domain.id}/dns-timeline?limit=3&offset=3")
    ids1 = {r["id"] for r in page1.json()}
    ids2 = {r["id"] for r in page2.json()}
    assert ids1.isdisjoint(ids2), "Pages must not overlap"


async def test_dns_timeline_count_endpoint(client: AsyncClient, db_session: AsyncSession):
    domain = await _domain_for(client, db_session, "count")
    for i in range(5):
        await make_dns_record(db_session, domain, record_host=f"cnt{i}", days_ago=i)
    await db_session.flush()

    resp = await client.get(f"/domains/{domain.id}/dns-timeline/count")
    assert resp.status_code == 200
    assert resp.json()["count"] >= 5


# ── change_type field ─────────────────────────────────────────────────────────

async def test_dns_timeline_change_type_added(client: AsyncClient, db_session: AsyncSession):
    domain = await _domain_for(client, db_session, "ct-added")
    await make_dns_record(db_session, domain, current_value="v=DMARC1; p=reject", previous_value=None)
    await db_session.flush()

    resp = await client.get(f"/domains/{domain.id}/dns-timeline")
    assert resp.json()[0]["change_type"] == "added"


async def test_dns_timeline_change_type_removed(client: AsyncClient, db_session: AsyncSession):
    domain = await _domain_for(client, db_session, "ct-removed")
    await make_dns_record(db_session, domain, current_value=None, previous_value="v=DMARC1; p=reject")
    await db_session.flush()

    resp = await client.get(f"/domains/{domain.id}/dns-timeline")
    assert resp.json()[0]["change_type"] == "removed"


# ── is_security_alert field ───────────────────────────────────────────────────

async def test_dns_timeline_security_alert_dmarc_downgrade(
    client: AsyncClient, db_session: AsyncSession
):
    domain = await _domain_for(client, db_session, "sa-dmarc")
    await make_dns_record(
        db_session, domain,
        record_type="DMARC",
        previous_value="v=DMARC1; p=reject",
        current_value="v=DMARC1; p=none",
    )
    await db_session.flush()

    resp = await client.get(f"/domains/{domain.id}/dns-timeline")
    assert resp.json()[0]["is_security_alert"] is True


async def test_dns_timeline_security_alert_spf_plus_all(
    client: AsyncClient, db_session: AsyncSession
):
    domain = await _domain_for(client, db_session, "sa-spf")
    await make_dns_record(
        db_session, domain,
        record_type="SPF",
        previous_value="v=spf1 include:google.com -all",
        current_value="v=spf1 include:google.com +all",
    )
    await db_session.flush()

    resp = await client.get(f"/domains/{domain.id}/dns-timeline")
    assert resp.json()[0]["is_security_alert"] is True


async def test_dns_timeline_no_alert_for_normal_change(
    client: AsyncClient, db_session: AsyncSession
):
    domain = await _domain_for(client, db_session, "sa-none")
    await make_dns_record(
        db_session, domain,
        record_type="DMARC",
        previous_value="v=DMARC1; p=none",
        current_value="v=DMARC1; p=reject",
    )
    await db_session.flush()

    resp = await client.get(f"/domains/{domain.id}/dns-timeline")
    assert resp.json()[0]["is_security_alert"] is False
