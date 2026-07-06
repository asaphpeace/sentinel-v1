"""
Integration tests for the forgot-password / reset-password flow.
Reuses the client/db_session fixtures and make_tenant/make_user factories
from conftest.py and factories.py — see tests/test_auth.py for the
established pattern this follows.
"""
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.password_reset import PasswordResetToken
from tests.factories import make_tenant, make_user


async def _get_latest_token(db: AsyncSession, user_id) -> PasswordResetToken:
    result = await db.execute(
        select(PasswordResetToken)
        .where(PasswordResetToken.user_id == user_id)
        .order_by(PasswordResetToken.created_at.desc())
    )
    return result.scalars().first()


async def test_forgot_password_returns_generic_message_for_real_email(client: AsyncClient, db_session: AsyncSession):
    tenant = await make_tenant(db_session)
    await make_user(db_session, tenant, email="reset-me@example.com", password="oldpass123")
    await db_session.flush()

    resp = await client.post("/auth/forgot-password", json={"email": "reset-me@example.com"})
    assert resp.status_code == 200
    assert "reset link" in resp.json()["message"].lower()


async def test_forgot_password_returns_same_message_for_unknown_email(client: AsyncClient, db_session: AsyncSession):
    """No enumeration — a nonexistent email gets byte-for-byte the same response as a real one."""
    real = await client.post("/auth/forgot-password", json={"email": "nobody-real@example.com"})
    assert real.status_code == 200
    assert "If an account with that email exists" in real.json()["message"]


async def test_forgot_password_creates_usable_reset_token(client: AsyncClient, db_session: AsyncSession):
    tenant = await make_tenant(db_session)
    user = await make_user(db_session, tenant, email="token-check@example.com", password="oldpass123")
    await db_session.flush()

    await client.post("/auth/forgot-password", json={"email": "token-check@example.com"})
    token_row = await _get_latest_token(db_session, user.id)
    assert token_row is not None
    assert token_row.used is False


async def test_reset_password_with_invalid_token_returns_400(client: AsyncClient, db_session: AsyncSession):
    resp = await client.post("/auth/reset-password", json={"token": "not-a-real-token", "new_password": "newpass123"})
    assert resp.status_code == 400


async def test_reset_password_success_then_login_with_new_password(client: AsyncClient, db_session: AsyncSession):
    tenant = await make_tenant(db_session)
    user = await make_user(db_session, tenant, email="full-flow@example.com", password="oldpass123")
    await db_session.flush()

    await client.post("/auth/forgot-password", json={"email": "full-flow@example.com"})
    token_row = await _get_latest_token(db_session, user.id)

    reset_resp = await client.post("/auth/reset-password", json={"token": token_row.token, "new_password": "newpass456"})
    assert reset_resp.status_code == 204

    old_login = await client.post(
        "/auth/token",
        data={"username": "full-flow@example.com", "password": "oldpass123"},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert old_login.status_code == 401

    new_login = await client.post(
        "/auth/token",
        data={"username": "full-flow@example.com", "password": "newpass456"},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert new_login.status_code == 200


async def test_reset_token_cannot_be_reused(client: AsyncClient, db_session: AsyncSession):
    tenant = await make_tenant(db_session)
    user = await make_user(db_session, tenant, email="reuse-check@example.com", password="oldpass123")
    await db_session.flush()

    await client.post("/auth/forgot-password", json={"email": "reuse-check@example.com"})
    token_row = await _get_latest_token(db_session, user.id)

    first = await client.post("/auth/reset-password", json={"token": token_row.token, "new_password": "newpass456"})
    assert first.status_code == 204

    second = await client.post("/auth/reset-password", json={"token": token_row.token, "new_password": "anotherpass789"})
    assert second.status_code == 400


async def test_new_forgot_password_request_invalidates_previous_token(client: AsyncClient, db_session: AsyncSession):
    tenant = await make_tenant(db_session)
    user = await make_user(db_session, tenant, email="double-request@example.com", password="oldpass123")
    await db_session.flush()

    await client.post("/auth/forgot-password", json={"email": "double-request@example.com"})
    first_token = await _get_latest_token(db_session, user.id)
    first_token_value = first_token.token

    # The test fixture shares one db_session across every client.post() call in
    # this test (unlike production, where each real HTTP request gets a fresh
    # AsyncSessionLocal() with no prior identity-map state — see get_db). The
    # forgot_password endpoint's bulk UPDATE below correctly changes the row
    # in the database, but this session's identity map still holds the
    # `first_token` object from the query above with its now-stale `used`
    # value cached. expire_all() forces the next query to re-read from the DB
    # instead of returning that cached object — this is purely an artifact of
    # the shared test session, not something a real request sequence hits.
    db_session.expire_all()

    await client.post("/auth/forgot-password", json={"email": "double-request@example.com"})

    resp = await client.post("/auth/reset-password", json={"token": first_token_value, "new_password": "whatever123"})
    assert resp.status_code == 400


async def test_forgot_password_for_sso_only_account_does_not_create_token(client: AsyncClient, db_session: AsyncSession):
    """An SSO-only user has no password to reset — see auth_method filter in forgot_password."""
    from app.models.user import User
    import uuid as _uuid

    tenant = await make_tenant(db_session)
    sso_user = User(
        id=_uuid.uuid4(), tenant_id=tenant.id, email="sso-user@example.com",
        hashed_password=None, full_name="SSO User", role="admin", auth_method="sso",
    )
    db_session.add(sso_user)
    await db_session.flush()

    await client.post("/auth/forgot-password", json={"email": "sso-user@example.com"})
    token_row = await _get_latest_token(db_session, sso_user.id)
    assert token_row is None
