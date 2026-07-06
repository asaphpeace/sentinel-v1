"""One-off script: mint a service account API key for another portfolio
product (e.g. Workspace OS) to read this tenant's data via /service/v1/*.
Run once per product, paste the printed key into that product's .env - it
is shown here once, the DB only ever stores its bcrypt hash.

Usage: python create_service_account.py <tenant_email> <service_name>
Example: python create_service_account.py chairman@example.com workspace-os
"""
import asyncio
import sys
import uuid

from sqlalchemy import select

from app.database import AsyncSessionLocal
from app.models.service_account import ServiceAccount
from app.models.user import User
from app.services.service_auth import generate_service_key, hash_service_key

DEFAULT_SCOPES = ["overview:read", "alerts:read", "audit:read"]


async def main(tenant_email: str, service_name: str) -> None:
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(User).where(User.email == tenant_email))
        user = result.scalar_one_or_none()
        if not user:
            print(f"No user found with email {tenant_email}")
            return

        key = generate_service_key()
        account = ServiceAccount(
            id=uuid.uuid4(),
            tenant_id=user.tenant_id,
            service_name=service_name,
            key_hash=hash_service_key(key),
            scopes=DEFAULT_SCOPES,
        )
        db.add(account)
        await db.commit()

        print(f"Service account '{service_name}' created for tenant {user.tenant_id}")
        print(f"Scopes: {DEFAULT_SCOPES}")
        print(f"Key (shown once - paste into the other product's .env now):\n{key}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python create_service_account.py <tenant_email> <service_name>")
        sys.exit(1)
    asyncio.run(main(sys.argv[1], sys.argv[2]))
