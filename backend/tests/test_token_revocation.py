"""
Integration tests for token_version-based JWT revocation. See User.token_version's
docstring in app/models/user.py — bumping it invalidates every previously-issued
token for that user without a server-side blacklist.
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
    assert resp.status_code == 200
    return resp.json()["access_token"]


async def test_token_works_before_password_change(client: AsyncClient, db_session: AsyncSession):
    tenant = await make_tenant(db_session)
    await make_user(db_session, tenant, email="revoke-1@example.com", password="oldpass123")
    await db_session.flush()

    token = await _login(client, "revoke-1@example.com", "oldpass123")
    resp = await client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200


async def test_old_token_rejected_after_password_change(client: AsyncClient, db_session: AsyncSession):
    tenant = await make_tenant(db_session)
    await make_user(db_session, tenant, email="revoke-2@example.com", password="oldpass123")
    await db_session.flush()

    old_token = await _login(client, "revoke-2@example.com", "oldpass123")

    change = await client.post(
        "/auth/change-password",
        json={"current_password": "oldpass123", "new_password": "newpass456"},
        headers={"Authorization": f"Bearer {old_token}"},
    )
    assert change.status_code == 204

    resp = await client.get("/auth/me", headers={"Authorization": f"Bearer {old_token}"})
    assert resp.status_code == 401


async def test_new_token_works_after_password_change(client: AsyncClient, db_session: AsyncSession):
    tenant = await make_tenant(db_session)
    await make_user(db_session, tenant, email="revoke-3@example.com", password="oldpass123")
    await db_session.flush()

    old_token = await _login(client, "revoke-3@example.com", "oldpass123")
    await client.post(
        "/auth/change-password",
        json={"current_password": "oldpass123", "new_password": "newpass456"},
        headers={"Authorization": f"Bearer {old_token}"},
    )

    new_token = await _login(client, "revoke-3@example.com", "newpass456")
    resp = await client.get("/auth/me", headers={"Authorization": f"Bearer {new_token}"})
    assert resp.status_code == 200


async def test_token_version_embedded_and_checked_on_every_request(client: AsyncClient, db_session: AsyncSession):
    """
    Directly exercises the `tv` claim mechanism rather than going through a
    specific endpoint that bumps it — a forged token with a stale/wrong tv
    value should be rejected even if the signature itself is valid.
    """
    import uuid as _uuid
    from datetime import datetime, timedelta, timezone
    from jose import jwt
    from app.config import settings
    from app.models.user import User
    from sqlalchemy import select

    tenant = await make_tenant(db_session)
    user = await make_user(db_session, tenant, email="revoke-4@example.com", password="pass123")
    await db_session.flush()

    stale_token = jwt.encode(
        {"sub": str(user.id), "tenant": str(tenant.id), "tv": user.token_version + 1, "exp": datetime.now(timezone.utc) + timedelta(minutes=5)},
        settings.secret_key, algorithm=settings.algorithm,
    )
    resp = await client.get("/auth/me", headers={"Authorization": f"Bearer {stale_token}"})
    assert resp.status_code == 401

    correct_token = jwt.encode(
        {"sub": str(user.id), "tenant": str(tenant.id), "tv": user.token_version, "exp": datetime.now(timezone.utc) + timedelta(minutes=5)},
        settings.secret_key, algorithm=settings.algorithm,
    )
    resp2 = await client.get("/auth/me", headers={"Authorization": f"Bearer {correct_token}"})
    assert resp2.status_code == 200


async def test_legacy_token_without_tv_claim_still_accepted(client: AsyncClient, db_session: AsyncSession):
    """
    A token issued before token_version existed has no `tv` claim at all —
    get_current_user treats an absent claim as "not applicable" rather than
    a mismatch, so already-active sessions aren't retroactively logged out
    when this feature ships. They naturally expire within the token's normal
    lifetime instead.
    """
    from datetime import datetime, timedelta, timezone
    from jose import jwt
    from app.config import settings

    tenant = await make_tenant(db_session)
    user = await make_user(db_session, tenant, email="revoke-5@example.com", password="pass123")
    await db_session.flush()

    legacy_token = jwt.encode(
        {"sub": str(user.id), "tenant": str(tenant.id), "exp": datetime.now(timezone.utc) + timedelta(minutes=5)},
        settings.secret_key, algorithm=settings.algorithm,
    )
    resp = await client.get("/auth/me", headers={"Authorization": f"Bearer {legacy_token}"})
    assert resp.status_code == 200
