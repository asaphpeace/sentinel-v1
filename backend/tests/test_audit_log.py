"""
Integration tests for the audit log: the plan gate, admin-only access, and
that the explicit logging call sites (see audit_service.py's module
docstring on why these are explicit rather than middleware-driven) actually
produce a readable entry end to end.
"""
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from tests.factories import make_tenant, make_user


async def _login(client: AsyncClient, email: str, password: str) -> str:
    resp = await client.post(
        "/auth/token",
        data={"username": email, "password": password},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    return resp.json()["access_token"]


async def test_audit_log_blocked_on_free_plan(client: AsyncClient, db_session: AsyncSession):
    tenant = await make_tenant(db_session, plan="free")
    await make_user(db_session, tenant, email="free-admin@example.com", password="pass123")
    await db_session.flush()

    token = await _login(client, "free-admin@example.com", "pass123")
    resp = await client.get("/audit-log", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 403
    assert resp.json()["detail"]["code"] == "feature_not_available"


async def test_audit_log_accessible_on_enterprise_plan(client: AsyncClient, db_session: AsyncSession):
    tenant = await make_tenant(db_session, plan="enterprise")
    await make_user(db_session, tenant, email="ent-admin@example.com", password="pass123")
    await db_session.flush()

    token = await _login(client, "ent-admin@example.com", "pass123")
    resp = await client.get("/audit-log", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    assert resp.json() == []  # nothing logged yet for this fresh tenant


async def test_audit_log_requires_admin_role(client: AsyncClient, db_session: AsyncSession):
    tenant = await make_tenant(db_session, plan="enterprise")
    await make_user(db_session, tenant, email="viewer@example.com", password="pass123", role="viewer")
    await db_session.flush()

    token = await _login(client, "viewer@example.com", "pass123")
    resp = await client.get("/audit-log", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 403


async def test_password_change_produces_a_readable_audit_entry(client: AsyncClient, db_session: AsyncSession):
    """End-to-end: trigger a real audited action, then read it back through the actual endpoint."""
    tenant = await make_tenant(db_session, plan="enterprise")
    await make_user(db_session, tenant, email="audited@example.com", password="oldpass123")
    await db_session.flush()

    token = await _login(client, "audited@example.com", "oldpass123")
    await client.post(
        "/auth/change-password",
        json={"current_password": "oldpass123", "new_password": "newpass456"},
        headers={"Authorization": f"Bearer {token}"},
    )

    # change-password just invalidated this token (see test_token_revocation.py) —
    # log back in with the new password to read the audit trail.
    new_token = await _login(client, "audited@example.com", "newpass456")
    resp = await client.get("/audit-log", headers={"Authorization": f"Bearer {new_token}"})
    assert resp.status_code == 200
    entries = resp.json()
    assert any(e["action"] == "auth.password_changed" for e in entries)
    entry = next(e for e in entries if e["action"] == "auth.password_changed")
    assert entry["actor_email"] == "audited@example.com"
    assert entry["target_type"] == "user"


async def test_audit_log_filters_by_action(client: AsyncClient, db_session: AsyncSession):
    tenant = await make_tenant(db_session, plan="enterprise")
    await make_user(db_session, tenant, email="filter-admin@example.com", password="oldpass123")
    await db_session.flush()

    token = await _login(client, "filter-admin@example.com", "oldpass123")
    await client.post(
        "/auth/change-password",
        json={"current_password": "oldpass123", "new_password": "newpass456"},
        headers={"Authorization": f"Bearer {token}"},
    )
    new_token = await _login(client, "filter-admin@example.com", "newpass456")

    resp = await client.get("/audit-log?action=auth.password_changed", headers={"Authorization": f"Bearer {new_token}"})
    assert resp.status_code == 200
    assert all(e["action"] == "auth.password_changed" for e in resp.json())

    resp2 = await client.get("/audit-log?action=nonexistent.action", headers={"Authorization": f"Bearer {new_token}"})
    assert resp2.json() == []


async def test_audit_log_count_endpoint(client: AsyncClient, db_session: AsyncSession):
    tenant = await make_tenant(db_session, plan="enterprise")
    await make_user(db_session, tenant, email="count-admin@example.com", password="oldpass123")
    await db_session.flush()

    token = await _login(client, "count-admin@example.com", "oldpass123")
    before = await client.get("/audit-log/count", headers={"Authorization": f"Bearer {token}"})
    assert before.json()["count"] == 0

    await client.post(
        "/auth/change-password",
        json={"current_password": "oldpass123", "new_password": "newpass456"},
        headers={"Authorization": f"Bearer {token}"},
    )
    new_token = await _login(client, "count-admin@example.com", "newpass456")
    after = await client.get("/audit-log/count", headers={"Authorization": f"Bearer {new_token}"})
    assert after.json()["count"] == 1
