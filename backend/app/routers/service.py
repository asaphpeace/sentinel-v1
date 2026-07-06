"""Read-only surface for other portfolio products (Workspace OS) to pull
Sentinel status via a service key - see app/services/service_auth.py.
Deliberately separate from the user-facing overview/alerts/audit-log
routes rather than retrofitting them: narrower payloads, no admin/plan
gating to reconcile with a non-user principal, and zero risk to the
existing tested paths."""
from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import Alert, AuditLogEntry, Domain, SentinelSnapshot
from app.models.service_account import ServiceAccount
from app.services.service_auth import get_service_account, require_scope

router = APIRouter(prefix="/service/v1", tags=["service"])


@router.get("/overview")
async def service_overview(
    db: AsyncSession = Depends(get_db),
    account: ServiceAccount = Depends(get_service_account),
):
    require_scope(account, "overview:read")

    domain_count = (await db.execute(
        select(func.count()).select_from(Domain)
        .where(Domain.tenant_id == account.tenant_id, Domain.is_active == True)
    )).scalar()

    latest_snap = (await db.execute(
        select(SentinelSnapshot)
        .where(SentinelSnapshot.tenant_id == account.tenant_id)
        .order_by(SentinelSnapshot.week.desc())
        .limit(1)
    )).scalar_one_or_none()

    return {
        "domain_count": domain_count,
        "score": latest_snap.score if latest_snap else None,
        "week": str(latest_snap.week) if latest_snap else None,
    }


@router.get("/alerts")
async def service_alerts(
    limit: int = 20,
    db: AsyncSession = Depends(get_db),
    account: ServiceAccount = Depends(get_service_account),
):
    require_scope(account, "alerts:read")

    result = await db.execute(
        select(Alert)
        .where(Alert.tenant_id == account.tenant_id, Alert.is_read == False)
        .order_by(Alert.created_at.desc())
        .limit(limit)
    )
    return [
        {
            "id": str(a.id), "severity": a.severity, "category": a.category,
            "title": a.title, "created_at": a.created_at.isoformat(),
        }
        for a in result.scalars().all()
    ]


@router.get("/audit-log")
async def service_audit_log(
    limit: int = 20,
    db: AsyncSession = Depends(get_db),
    account: ServiceAccount = Depends(get_service_account),
):
    require_scope(account, "audit:read")

    result = await db.execute(
        select(AuditLogEntry)
        .where(AuditLogEntry.tenant_id == account.tenant_id)
        .order_by(AuditLogEntry.created_at.desc())
        .limit(limit)
    )
    return [
        {
            "id": str(e.id), "action": e.action, "target_type": e.target_type,
            "target_label": e.target_label, "created_at": e.created_at.isoformat(),
        }
        for e in result.scalars().all()
    ]
