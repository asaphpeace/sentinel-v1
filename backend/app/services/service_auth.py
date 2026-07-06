import secrets
from datetime import datetime, timezone

from fastapi import Depends, Header, HTTPException, status
from passlib.context import CryptContext
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.service_account import ServiceAccount

pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")


def generate_service_key() -> str:
    return f"wos_{secrets.token_urlsafe(32)}"


def hash_service_key(key: str) -> str:
    return pwd_ctx.hash(key)


def verify_service_key(key: str, key_hash: str) -> bool:
    return pwd_ctx.verify(key, key_hash)


async def get_service_account(
    x_service_key: str | None = Header(default=None),
    db: AsyncSession = Depends(get_db),
) -> ServiceAccount:
    if not x_service_key:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="X-Service-Key header required")

    # bcrypt hashes aren't lookup-able by value, so this checks every
    # non-revoked account. Fine at the handful of service accounts this is
    # meant for (one per portfolio product); if that ever grows, prefix the
    # key with the account id so this becomes a direct lookup instead of a
    # scan.
    result = await db.execute(select(ServiceAccount).where(ServiceAccount.revoked_at.is_(None)))
    for account in result.scalars().all():
        if verify_service_key(x_service_key, account.key_hash):
            account.last_used_at = datetime.now(timezone.utc)
            await db.commit()
            return account

    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or revoked service key")


def require_scope(account: ServiceAccount, scope: str) -> None:
    if scope not in account.scopes:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=f"Service account missing scope: {scope}")
