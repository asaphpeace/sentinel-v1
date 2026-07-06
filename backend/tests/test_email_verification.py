"""
Integration tests for the email verification flow: register() leaves a new
user unverified, /auth/verify-email confirms it, /auth/resend-verification
re-issues a token. Reuses client/db_session/auth_client fixtures.
"""
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.email_verification import EmailVerificationToken
from app.models.user import User
from tests.factories import make_tenant, make_user


async def _get_latest_token(db: AsyncSession, user_id) -> EmailVerificationToken:
    """
    The "active" token — not just "most recently created". Postgres's
    func.now() (used by created_at's server_default) returns one fixed value
    per transaction, not per statement — since a whole test runs inside one
    SAVEPOINT-wrapped transaction, two tokens created moments apart in real
    wall-clock time can end up with an identical created_at, making "order by
    created_at desc" non-deterministic between them. Filtering on used=False
    sidesteps that entirely: exactly one row should ever be unused at a time.
    """
    result = await db.execute(
        select(EmailVerificationToken)
        .where(EmailVerificationToken.user_id == user_id, EmailVerificationToken.used == False)
    )
    return result.scalars().one()


async def test_register_creates_unverified_user(client: AsyncClient, db_session: AsyncSession):
    resp = await client.post("/auth/register", json={
        "email": "unverified@example.com", "password": "pass12345", "terms_accepted": True,
    })
    assert resp.status_code == 200
    token = resp.json()["access_token"]

    me = await client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me.json()["email_verified"] is False


async def test_existing_users_created_via_factory_default_to_verified(client: AsyncClient, db_session: AsyncSession):
    """
    email_verified defaults to True at the model level (server_default) —
    only register() explicitly overrides it. Every other creation path
    (invite accept, MSP direct-create, and this factory) should come in
    verified by default.
    """
    tenant = await make_tenant(db_session)
    user = await make_user(db_session, tenant, email="grandfathered@example.com")
    await db_session.flush()
    assert user.email_verified is True


async def test_verify_email_with_valid_token_succeeds(client: AsyncClient, db_session: AsyncSession):
    register = await client.post("/auth/register", json={
        "email": "verify-me@example.com", "password": "pass12345", "terms_accepted": True,
    })
    access_token = register.json()["access_token"]
    user = (await db_session.execute(select(User).where(User.email == "verify-me@example.com"))).scalar_one()
    vtoken = await _get_latest_token(db_session, user.id)

    resp = await client.post("/auth/verify-email", json={"token": vtoken.token})
    assert resp.status_code == 204

    me = await client.get("/auth/me", headers={"Authorization": f"Bearer {access_token}"})
    assert me.json()["email_verified"] is True


async def test_verify_email_with_invalid_token_returns_400(client: AsyncClient, db_session: AsyncSession):
    resp = await client.post("/auth/verify-email", json={"token": "garbage-token-value"})
    assert resp.status_code == 400


async def test_verify_email_token_cannot_be_reused(client: AsyncClient, db_session: AsyncSession):
    await client.post("/auth/register", json={
        "email": "reuse-verify@example.com", "password": "pass12345", "terms_accepted": True,
    })
    user = (await db_session.execute(select(User).where(User.email == "reuse-verify@example.com"))).scalar_one()
    vtoken = await _get_latest_token(db_session, user.id)

    first = await client.post("/auth/verify-email", json={"token": vtoken.token})
    assert first.status_code == 204

    second = await client.post("/auth/verify-email", json={"token": vtoken.token})
    assert second.status_code == 400


async def test_resend_verification_issues_new_token(client: AsyncClient, db_session: AsyncSession):
    register = await client.post("/auth/register", json={
        "email": "resend-me@example.com", "password": "pass12345", "terms_accepted": True,
    })
    access_token = register.json()["access_token"]
    user = (await db_session.execute(select(User).where(User.email == "resend-me@example.com"))).scalar_one()

    old_token = await _get_latest_token(db_session, user.id)
    old_token_value = old_token.token
    db_session.expire_all()  # see test_password_reset.py's note on shared test-session identity-map staleness

    resend = await client.post("/auth/resend-verification", headers={"Authorization": f"Bearer {access_token}"})
    assert resend.status_code == 204

    # old token is now invalidated
    old_attempt = await client.post("/auth/verify-email", json={"token": old_token_value})
    assert old_attempt.status_code == 400

    # the newly issued token works
    new_token = await _get_latest_token(db_session, user.id)
    new_attempt = await client.post("/auth/verify-email", json={"token": new_token.token})
    assert new_attempt.status_code == 204


async def test_resend_verification_when_already_verified_returns_400(client: AsyncClient, db_session: AsyncSession):
    register = await client.post("/auth/register", json={
        "email": "already-verified@example.com", "password": "pass12345", "terms_accepted": True,
    })
    access_token = register.json()["access_token"]
    user = (await db_session.execute(select(User).where(User.email == "already-verified@example.com"))).scalar_one()
    vtoken = await _get_latest_token(db_session, user.id)
    await client.post("/auth/verify-email", json={"token": vtoken.token})

    resp = await client.post("/auth/resend-verification", headers={"Authorization": f"Bearer {access_token}"})
    assert resp.status_code == 400


async def test_resend_verification_requires_auth(client: AsyncClient, db_session: AsyncSession):
    resp = await client.post("/auth/resend-verification")
    assert resp.status_code == 401
