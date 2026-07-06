"""
B5 — Auth endpoint tests.
Verifies login returns workspace_name and register creates tenant + returns workspace_name.
"""
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from tests.factories import make_tenant, make_user


async def test_login_returns_workspace_name(client: AsyncClient, db_session: AsyncSession):
    tenant = await make_tenant(db_session, name="Acme Corp")
    await make_user(db_session, tenant, email="acme@example.com", password="secret123")
    await db_session.flush()

    resp = await client.post(
        "/auth/token",
        data={"username": "acme@example.com", "password": "secret123"},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert "access_token" in body
    assert body["workspace_name"] == "Acme Corp"


async def test_login_wrong_password_returns_401(client: AsyncClient, db_session: AsyncSession):
    tenant = await make_tenant(db_session)
    await make_user(db_session, tenant, email="fail@example.com", password="correct")
    await db_session.flush()

    resp = await client.post(
        "/auth/token",
        data={"username": "fail@example.com", "password": "wrong"},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert resp.status_code == 401


async def test_login_unknown_user_returns_401(client: AsyncClient, db_session: AsyncSession):
    resp = await client.post(
        "/auth/token",
        data={"username": "nobody@example.com", "password": "pass"},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert resp.status_code == 401


async def test_register_creates_workspace_name(client: AsyncClient, db_session: AsyncSession):
    resp = await client.post("/auth/register", json={
        "email": "new@startup.io",
        "password": "password123",
        "workspace_name": "Startup Inc",
        "terms_accepted": True,
    })
    assert resp.status_code == 200
    body = resp.json()
    assert body["workspace_name"] == "Startup Inc"
    assert "access_token" in body


async def test_register_without_terms_accepted_returns_400(client: AsyncClient, db_session: AsyncSession):
    resp = await client.post("/auth/register", json={
        "email": "no-terms@startup.io",
        "password": "password123",
    })
    assert resp.status_code == 400


async def test_register_duplicate_email_returns_400(client: AsyncClient, db_session: AsyncSession):
    tenant = await make_tenant(db_session)
    await make_user(db_session, tenant, email="dup@example.com")
    await db_session.flush()

    resp = await client.post("/auth/register", json={
        "email": "dup@example.com",
        "password": "anotherpass",
        "terms_accepted": True,
    })
    assert resp.status_code == 400


async def test_register_workspace_name_defaults_from_email(client: AsyncClient, db_session: AsyncSession):
    resp = await client.post("/auth/register", json={
        "email": "alice@company.com",
        "password": "pass1234",
        "terms_accepted": True,
    })
    assert resp.status_code == 200
    body = resp.json()
    assert body["workspace_name"]  # non-empty


async def test_protected_route_requires_token(client: AsyncClient, db_session: AsyncSession):
    resp = await client.get("/overview")
    assert resp.status_code == 401


async def test_protected_route_accepts_valid_token(client: AsyncClient, db_session: AsyncSession):
    tenant = await make_tenant(db_session)
    await make_user(db_session, tenant, email="valid@example.com", password="pass")
    await db_session.flush()

    login = await client.post(
        "/auth/token",
        data={"username": "valid@example.com", "password": "pass"},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    token = login.json()["access_token"]
    resp = await client.get("/overview", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
