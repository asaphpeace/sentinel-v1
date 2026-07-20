from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import Domain, DnsRecord
from app.models.user import User
from app.routers.auth import get_current_user
from app.schemas.dns import DnsTimelineEntryOut, _change_type, _is_security_alert

router = APIRouter(tags=["dns"])


def _serialize(r: DnsRecord, domain_name: str | None) -> DnsTimelineEntryOut:
    return DnsTimelineEntryOut(
        id=str(r.id),
        domain_id=str(r.domain_id),
        domain_name=domain_name,
        record_type=r.record_type,
        record_host=r.record_host,
        previous_value=r.previous_value,
        current_value=r.current_value,
        change_summary=r.change_summary,
        change_type=_change_type(r.previous_value, r.current_value),
        is_security_alert=_is_security_alert(r.record_type, r.previous_value, r.current_value),
        detected_at=r.detected_at,
        risk_severity=r.risk_severity,
        risk_explanation=r.risk_explanation,
        risk_action=r.risk_action,
        risk_is_ai=r.risk_is_ai,
    )


@router.get("/domains/{domain_id}/dns-timeline", response_model=list[DnsTimelineEntryOut])
async def get_domain_dns_timeline(
    domain_id: str,
    limit: int = Query(50, le=200),
    offset: int = Query(0, ge=0),
    days: int | None = Query(None, ge=1, le=3650),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    result = await db.execute(select(Domain).where(Domain.id == domain_id, Domain.tenant_id == user.tenant_id))
    domain = result.scalar_one_or_none()
    if not domain:
        raise HTTPException(status_code=404, detail="Domain not found")

    where = [DnsRecord.domain_id == domain.id]
    if days is not None:
        where.append(DnsRecord.detected_at >= datetime.now(timezone.utc) - timedelta(days=days))
    stmt = (
        select(DnsRecord)
        .where(*where)
        .order_by(DnsRecord.detected_at.desc())
        .offset(offset)
        .limit(limit)
    )
    records = (await db.execute(stmt)).scalars().all()
    return [_serialize(r, domain.name) for r in records]


@router.get("/domains/{domain_id}/dns-timeline/count")
async def get_domain_dns_timeline_count(
    domain_id: str,
    days: int | None = Query(None, ge=1, le=3650),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    result = await db.execute(select(Domain).where(Domain.id == domain_id, Domain.tenant_id == user.tenant_id))
    domain = result.scalar_one_or_none()
    if not domain:
        raise HTTPException(status_code=404, detail="Domain not found")
    where = [DnsRecord.domain_id == domain.id]
    if days is not None:
        where.append(DnsRecord.detected_at >= datetime.now(timezone.utc) - timedelta(days=days))
    count = (await db.execute(
        select(func.count()).where(*where)
    )).scalar()
    return {"count": count}


@router.get("/tenant/dns-timeline", response_model=list[DnsTimelineEntryOut])
async def get_tenant_dns_timeline(
    limit: int = Query(100, le=500),
    offset: int = Query(0, ge=0),
    days: int | None = Query(None, ge=1, le=3650),
    record_type: str | None = Query(None),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Timeline across all tenant domains."""
    domains_result = await db.execute(
        select(Domain).where(Domain.tenant_id == user.tenant_id, Domain.is_active == True)
    )
    domains = {str(d.id): d.name for d in domains_result.scalars().all()}

    where = [DnsRecord.domain_id.in_(list(domains.keys()))]
    if days is not None:
        where.append(DnsRecord.detected_at >= datetime.now(timezone.utc) - timedelta(days=days))
    stmt = (
        select(DnsRecord)
        .where(*where)
        .order_by(DnsRecord.detected_at.desc())
        .offset(offset)
        .limit(limit)
    )
    if record_type:
        stmt = stmt.where(DnsRecord.record_type == record_type)

    records = (await db.execute(stmt)).scalars().all()
    return [_serialize(r, domains.get(str(r.domain_id))) for r in records]


@router.get("/tenant/dns-timeline/count")
async def get_tenant_dns_timeline_count(
    days: int | None = Query(None, ge=1, le=3650),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    domains_result = await db.execute(
        select(Domain).where(Domain.tenant_id == user.tenant_id, Domain.is_active == True)
    )
    domain_ids = [str(d.id) for d in domains_result.scalars().all()]
    where = [DnsRecord.domain_id.in_(domain_ids)]
    if days is not None:
        where.append(DnsRecord.detected_at >= datetime.now(timezone.utc) - timedelta(days=days))
    count = (await db.execute(
        select(func.count()).where(*where)
    )).scalar()
    return {"count": count}
