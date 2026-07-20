from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import AuditLogEntry
from app.models.user import Tenant, User
from app.routers.auth import get_current_user
from app.schemas.audit import AuditLogEntryOut
from app.services.plan_limits import require_feature

router = APIRouter(prefix="/audit-log", tags=["audit"])


def _require_admin(user: User) -> None:
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin role required")


@router.get("", response_model=list[AuditLogEntryOut])
async def list_audit_log(
    limit: int = Query(50, le=200),
    offset: int = Query(0, ge=0),
    days: int = Query(30, ge=1, le=365),
    action: str | None = Query(None, description="Filter by exact action, e.g. team.role_changed"),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    _require_admin(user)
    tenant_result = await db.execute(select(Tenant).where(Tenant.id == user.tenant_id))
    tenant = tenant_result.scalar_one()
    require_feature(tenant, "audit_log")

    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    stmt = (
        select(AuditLogEntry)
        .where(AuditLogEntry.tenant_id == user.tenant_id, AuditLogEntry.created_at >= cutoff)
        .order_by(AuditLogEntry.created_at.desc())
        .offset(offset)
        .limit(limit)
    )
    if action:
        stmt = stmt.where(AuditLogEntry.action == action)

    entries = (await db.execute(stmt)).scalars().all()
    return [
        AuditLogEntryOut(
            id=str(e.id), actor_email=e.actor_email, action=e.action,
            target_type=e.target_type, target_id=e.target_id, target_label=e.target_label,
            before=e.before, after=e.after, ip_address=e.ip_address, created_at=e.created_at,
        )
        for e in entries
    ]


@router.get("/count")
async def count_audit_log(
    days: int = Query(30, ge=1, le=365),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    _require_admin(user)
    tenant_result = await db.execute(select(Tenant).where(Tenant.id == user.tenant_id))
    tenant = tenant_result.scalar_one()
    require_feature(tenant, "audit_log")

    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    count = (
        await db.execute(
            select(func.count()).select_from(AuditLogEntry).where(
                AuditLogEntry.tenant_id == user.tenant_id,
                AuditLogEntry.created_at >= cutoff,
            )
        )
    ).scalar()
    return {"count": count}
