"""Run once to create the initial tenant + admin user."""
import asyncio
from passlib.context import CryptContext
from sqlalchemy.ext.asyncio import AsyncSession
from app.database import AsyncSessionLocal, engine, Base
from app.models.user import Tenant, User

pwd = CryptContext(schemes=["bcrypt"])

async def seed():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with AsyncSessionLocal() as db:
        tenant = Tenant(name="My Workspace", plan="premium")
        db.add(tenant)
        await db.flush()

        user = User(
            tenant_id=tenant.id,
            email="admin@mailsentry.co.za",
            hashed_password=pwd.hash("sentinel123"),
            role="admin",
        )
        db.add(user)
        await db.commit()
        print("OK tenant:", tenant.name)
        print("OK user:   admin@mailsentry.co.za")
        print("OK pass:   sentinel123")

asyncio.run(seed())
