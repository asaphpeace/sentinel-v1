"""
"Email these instructions to my team" was a mailto: link, which only works
if the person clicking it has a desktop mail client configured as the
OS/browser default — silently does nothing otherwise (webmail-only setups,
mobile, locked-down corporate machines). Fixed to send server-side via
Sentinel's own email service, same pattern as domains.py's existing
email_dns_instructions. This test exercises the real endpoint against the
real dev DB (dev-mode email logging, no SENDGRID_API_KEY needed).
"""
import pytest

from app.database import AsyncSessionLocal
from app.models import Domain, User
from sqlalchemy import select


@pytest.mark.asyncio
async def test_email_platform_instructions_succeeds_in_dev_mode():
    from app.routers.platforms import email_platform_setup_instructions, PlatformEmailIn

    async with AsyncSessionLocal() as db:
        domain = (await db.execute(select(Domain).limit(1))).scalars().first()
        if domain is None:
            pytest.skip("no domain in dev DB to test against")
        user = (await db.execute(select(User).where(User.tenant_id == domain.tenant_id))).scalars().first()

        result = await email_platform_setup_instructions(
            str(domain.id), "sendgrid", PlatformEmailIn(to_email="dev@example.com"), db, user,
        )
        assert result == {"ok": True}


@pytest.mark.asyncio
async def test_email_platform_instructions_404s_for_unknown_platform():
    from fastapi import HTTPException
    from app.routers.platforms import email_platform_setup_instructions, PlatformEmailIn

    async with AsyncSessionLocal() as db:
        domain = (await db.execute(select(Domain).limit(1))).scalars().first()
        if domain is None:
            pytest.skip("no domain in dev DB to test against")
        user = (await db.execute(select(User).where(User.tenant_id == domain.tenant_id))).scalars().first()

        with pytest.raises(HTTPException) as exc_info:
            await email_platform_setup_instructions(
                str(domain.id), "not_a_real_platform", PlatformEmailIn(to_email="dev@example.com"), db, user,
            )
        assert exc_info.value.status_code == 404
