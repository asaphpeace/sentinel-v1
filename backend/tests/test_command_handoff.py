"""
Sentinel Command auth handoff — /auth/handoff-code mints a short-lived
scoped token for an authenticated V1 user; /auth/handoff-code/exchange
trades it for a real session, without Command's frontend ever sharing
localStorage with V1's (different origins). See BUILD_PLAN.md Phase 0
step 3 and ARCHITECTURE.md Section 9.
"""
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from tests.factories import make_tenant, make_user


async def test_mint_requires_auth(client: AsyncClient):
    resp = await client.post("/auth/handoff-code")
    assert resp.status_code == 401


async def test_mint_then_exchange_returns_same_user_session(client: AsyncClient, auth_client):
    auth_c, tenant = auth_client

    mint_resp = await auth_c.post("/auth/handoff-code")
    assert mint_resp.status_code == 200
    body = mint_resp.json()
    assert "code" in body
    assert body["expires_in"] == 60

    # Exchange must work on a fresh, unauthenticated client — that's the
    # whole point: Command's frontend has no session of its own yet.
    exchange_resp = await client.post("/auth/handoff-code/exchange", json={"code": body["code"]})
    assert exchange_resp.status_code == 200
    session = exchange_resp.json()
    assert "access_token" in session
    assert session["tenant_id"] == str(tenant.id)


async def test_exchange_rejects_garbage_code(client: AsyncClient):
    resp = await client.post("/auth/handoff-code/exchange", json={"code": "not-a-real-token"})
    assert resp.status_code == 401


async def test_exchange_rejects_a_normal_session_token_wrong_scope(client: AsyncClient, db_session: AsyncSession):
    # A regular /auth/token session token has no "scope": "command_handoff"
    # claim — the exchange endpoint must reject it even though it's a
    # validly-signed token, otherwise any leaked session token doubles as
    # a handoff code.
    tenant = await make_tenant(db_session)
    await make_user(db_session, tenant, email="scope-check@example.com", password="pass123")
    await db_session.flush()

    login_resp = await client.post(
        "/auth/token",
        data={"username": "scope-check@example.com", "password": "pass123"},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    session_token = login_resp.json()["access_token"]

    resp = await client.post("/auth/handoff-code/exchange", json={"code": session_token})
    assert resp.status_code == 401
