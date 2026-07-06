"""
Integration tests for two real bugs fixed this session:
  1. Deleting a domain used to permanently squat on its name (uq_domains_name
     is a global unique constraint) — delete_domain now renames the row so
     the name is released for re-use by any tenant.
  2. enforce_domain_limit used to count inactive (deleted) domains against
     the plan limit forever — it now only counts active ones.
"""
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.domain import Domain
from tests.factories import make_tenant, make_user, make_domain


async def _login(client: AsyncClient, email: str, password: str) -> str:
    resp = await client.post(
        "/auth/token",
        data={"username": email, "password": password},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    return resp.json()["access_token"]


async def test_deleting_domain_renames_row_and_releases_name(client: AsyncClient, db_session: AsyncSession):
    tenant = await make_tenant(db_session)
    await make_user(db_session, tenant, email="owner@example.com", password="pass123")
    domain = await make_domain(db_session, tenant, name="released.example.com")
    await db_session.flush()
    domain_id = domain.id

    token = await _login(client, "owner@example.com", "pass123")
    resp = await client.delete(f"/domains/{domain_id}", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200

    db_session.expire_all()
    row = (await db_session.execute(select(Domain).where(Domain.id == domain_id))).scalar_one()
    assert row.is_active is False
    assert row.name != "released.example.com"
    assert row.name.startswith("released.example.com~deleted~")

    # the literal name no longer matches any row — confirms it's free
    holder = (await db_session.execute(select(Domain).where(Domain.name == "released.example.com"))).scalar_one_or_none()
    assert holder is None


async def test_deleted_domain_name_reclaimable_by_different_tenant(client: AsyncClient, db_session: AsyncSession):
    """The actual bug report this session started from: domain deleted under
    one tenant could never be re-added by any tenant, ever, because the
    cross-tenant 'already claimed' check in wizard_start didn't account for
    inactive rows still holding the literal name."""
    tenant_a = await make_tenant(db_session, name="Tenant A")
    await make_user(db_session, tenant_a, email="a-admin@example.com", password="pass123")
    domain = await make_domain(db_session, tenant_a, name="contested.example.com")
    await db_session.flush()

    token_a = await _login(client, "a-admin@example.com", "pass123")
    await client.delete(f"/domains/{domain.id}", headers={"Authorization": f"Bearer {token_a}"})

    tenant_b = await make_tenant(db_session, name="Tenant B")
    await make_user(db_session, tenant_b, email="b-admin@example.com", password="pass123")
    await db_session.flush()
    token_b = await _login(client, "b-admin@example.com", "pass123")

    resp = await client.post(
        "/domains/wizard/start", json={"names": ["contested.example.com"]},
        headers={"Authorization": f"Bearer {token_b}"},
    )
    assert resp.status_code == 200
    body = resp.json()[0]
    assert body["domain"] == "contested.example.com"
    assert body["already_exists"] is False


async def test_deleted_domains_do_not_count_against_plan_limit(client: AsyncClient, db_session: AsyncSession):
    """free plan allows exactly 1 domain — add one, delete it, confirm a second can be added."""
    tenant = await make_tenant(db_session, plan="free")
    await make_user(db_session, tenant, email="limit-test@example.com", password="pass123")
    domain = await make_domain(db_session, tenant, name="first.example.com")
    await db_session.flush()

    token = await _login(client, "limit-test@example.com", "pass123")

    # at capacity — a second domain should be rejected
    blocked = await client.post(
        "/domains/wizard/start", json={"names": ["second.example.com"]},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert blocked.status_code == 403
    assert blocked.json()["detail"]["code"] == "domain_limit_reached"

    await client.delete(f"/domains/{domain.id}", headers={"Authorization": f"Bearer {token}"})

    # capacity freed up — now it should succeed
    allowed = await client.post(
        "/domains/wizard/start", json={"names": ["second.example.com"]},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert allowed.status_code == 200
