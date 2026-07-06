"""
Engagement lifecycle — the consent/scope gate every Sentinel Command scan
belongs to. See ARCHITECTURE.md Section 6 and BUILD_PLAN.md Phase 1's
"go on" addendum (engagement CRUD was a gap discovered while wiring the
scan passes, since they take an Engagement param with nowhere to create one).
"""
from sqlalchemy.ext.asyncio import AsyncSession

from tests.factories import make_tenant, make_user


async def test_create_engagement_starts_in_draft(auth_client):
    client, _tenant = auth_client
    resp = await client.post("/engagements", json={"tier": "cloud"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "draft"
    assert body["approved_at"] is None


async def test_create_engagement_rejects_unknown_tier(auth_client):
    client, _tenant = auth_client
    resp = await client.post("/engagements", json={"tier": "not-a-real-tier"})
    assert resp.status_code == 400


async def test_approve_engagement_activates_it(auth_client):
    client, _tenant = auth_client
    create_resp = await client.post("/engagements", json={"tier": "cloud"})
    engagement_id = create_resp.json()["id"]

    resp = await client.post(f"/engagements/{engagement_id}/approve")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "active"
    assert body["approved_at"] is not None


async def test_revoke_engagement_deactivates_it(auth_client):
    client, _tenant = auth_client
    create_resp = await client.post("/engagements", json={"tier": "cloud"})
    engagement_id = create_resp.json()["id"]
    await client.post(f"/engagements/{engagement_id}/approve")

    resp = await client.post(f"/engagements/{engagement_id}/revoke")
    assert resp.status_code == 200
    assert resp.json()["status"] == "revoked"


async def test_findings_and_priv_esc_paths_start_empty(auth_client):
    client, _tenant = auth_client
    create_resp = await client.post("/engagements", json={"tier": "cloud"})
    engagement_id = create_resp.json()["id"]

    findings_resp = await client.get(f"/engagements/{engagement_id}/findings")
    assert findings_resp.status_code == 200
    assert findings_resp.json() == []

    paths_resp = await client.get(f"/engagements/{engagement_id}/priv-esc-paths")
    assert paths_resp.status_code == 200
    assert paths_resp.json() == []


async def test_engagements_are_isolated_by_tenant(auth_client, client, db_session: AsyncSession):
    owner_client, _owner_tenant = auth_client
    create_resp = await owner_client.post("/engagements", json={"tier": "cloud"})
    engagement_id = create_resp.json()["id"]

    other_tenant = await make_tenant(db_session, name="Other Workspace")
    await make_user(db_session, other_tenant, email="other-eng@example.com", password="pass123")
    await db_session.flush()
    login = await client.post(
        "/auth/token",
        data={"username": "other-eng@example.com", "password": "pass123"},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    client.headers.update({"Authorization": f"Bearer {login.json()['access_token']}"})

    list_resp = await client.get("/engagements")
    assert list_resp.json() == []

    approve_resp = await client.post(f"/engagements/{engagement_id}/approve")
    assert approve_resp.status_code == 404
