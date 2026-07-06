from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import Domain, SslCert
from app.models.user import User
from app.routers.auth import get_current_user
from app.schemas.cert import CertOut
from app.services.cert_service import probe_domain_certs

router = APIRouter(prefix="/domains/{domain_id}/certs", tags=["certs"])


@router.get("", response_model=list[CertOut])
async def get_certs(
    domain_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    result = await db.execute(select(Domain).where(Domain.id == domain_id, Domain.tenant_id == user.tenant_id))
    domain = result.scalar_one_or_none()
    if not domain:
        raise HTTPException(status_code=404, detail="Domain not found")

    certs_result = await db.execute(
        select(SslCert).where(SslCert.domain_id == domain.id).order_by(SslCert.host)
    )
    certs = certs_result.scalars().all()

    return [
        CertOut(
            id=str(c.id), host=c.host, host_type=c.host_type,
            subject_cn=c.subject_cn, issuer=c.issuer, san=c.san,
            not_after=c.not_after, days_remaining=c.days_remaining,
            tls_version=c.tls_version, starttls_supported=c.starttls_supported,
            hostname_valid=c.hostname_valid, status=c.status,
            probe_error=c.probe_error, probed_at=c.probed_at,
        )
        for c in certs
    ]


@router.post("/probe")
async def trigger_probe(
    domain_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    result = await db.execute(select(Domain).where(Domain.id == domain_id, Domain.tenant_id == user.tenant_id))
    domain = result.scalar_one_or_none()
    if not domain:
        raise HTTPException(status_code=404, detail="Domain not found")
    certs = await probe_domain_certs(db, domain)
    return {"probed": len(certs)}
