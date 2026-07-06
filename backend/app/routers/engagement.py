import uuid as _uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import CloudPrivEscPath, Engagement, Finding
from app.models.user import User
from app.routers.auth import get_current_user
from app.schemas.engagement import EngagementCreate, EngagementOut
from app.schemas.finding import CloudPrivEscPathOut, FindingOut

router = APIRouter(prefix="/engagements", tags=["engagements"])

_VALID_TIERS = {"cloud", "exposure", "credential", "phishing", "reachability", "exploit"}


def _to_out(e: Engagement) -> EngagementOut:
    return EngagementOut(
        id=str(e.id), tier=e.tier, domain_id=str(e.domain_id) if e.domain_id else None,
        scope=e.scope, status=e.status,
        approved_at=e.approved_at.isoformat() if e.approved_at else None,
        expires_at=e.expires_at.isoformat() if e.expires_at else None,
        created_at=e.created_at.isoformat(),
    )


async def _get_engagement(engagement_id: str, db: AsyncSession, user: User) -> Engagement:
    result = await db.execute(
        select(Engagement).where(Engagement.id == engagement_id, Engagement.tenant_id == user.tenant_id)
    )
    engagement = result.scalar_one_or_none()
    if not engagement:
        raise HTTPException(status_code=404, detail="Engagement not found")
    return engagement


@router.get("", response_model=list[EngagementOut])
async def list_engagements(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(Engagement).where(Engagement.tenant_id == user.tenant_id).order_by(Engagement.created_at.desc())
    )
    return [_to_out(e) for e in result.scalars().all()]


@router.post("", response_model=EngagementOut)
async def create_engagement(
    payload: EngagementCreate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    if payload.tier not in _VALID_TIERS:
        raise HTTPException(status_code=400, detail=f"Unknown tier '{payload.tier}'")

    engagement = Engagement(
        id=_uuid.uuid4(),
        tenant_id=user.tenant_id,
        domain_id=payload.domain_id,
        tier=payload.tier,
        scope=payload.scope,
        status="draft",
    )
    db.add(engagement)
    await db.commit()
    return _to_out(engagement)


@router.post("/{engagement_id}/approve", response_model=EngagementOut)
async def approve_engagement(
    engagement_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """
    TEMPORARY: flips status straight to 'active'.

    ARCHITECTURE.md Section 9 calls for this to require a completed Dropbox
    Sign e-signature on the rules-of-engagement document, not a bare API
    call — that integration doesn't exist yet (separate task from Tier 0's
    scan pipeline). Direct approval exists only so the Tier 0 pipeline is
    testable end-to-end locally; treat any engagement approved this way as
    dev/test-only, never as a real customer authorization.
    """
    engagement = await _get_engagement(engagement_id, db, user)
    engagement.status = "active"
    engagement.approved_by_user_id = user.id
    engagement.approved_at = datetime.now(timezone.utc)
    await db.commit()
    return _to_out(engagement)


@router.post("/{engagement_id}/revoke", response_model=EngagementOut)
async def revoke_engagement(
    engagement_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    engagement = await _get_engagement(engagement_id, db, user)
    engagement.status = "revoked"
    await db.commit()
    return _to_out(engagement)


@router.get("/{engagement_id}/findings", response_model=list[FindingOut])
async def list_findings(
    engagement_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    engagement = await _get_engagement(engagement_id, db, user)
    result = await db.execute(
        select(Finding).where(Finding.engagement_id == engagement.id).order_by(Finding.discovered_at.desc())
    )
    return [
        FindingOut(
            id=str(f.id), engagement_id=str(f.engagement_id), asset_id=str(f.asset_id) if f.asset_id else None,
            tier=f.tier, severity=f.severity, title=f.title, status=f.status,
            check_id=f.check_id, detail=f.detail, remediation_guidance=f.remediation_guidance,
            discovered_at=f.discovered_at.isoformat(),
        )
        for f in result.scalars().all()
    ]


@router.get("/{engagement_id}/priv-esc-paths", response_model=list[CloudPrivEscPathOut])
async def list_priv_esc_paths(
    engagement_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    engagement = await _get_engagement(engagement_id, db, user)
    result = await db.execute(
        select(CloudPrivEscPath)
        .where(CloudPrivEscPath.engagement_id == engagement.id)
        .order_by(CloudPrivEscPath.discovered_at.desc())
    )
    return [
        CloudPrivEscPathOut(
            id=str(p.id), engagement_id=str(p.engagement_id),
            source_principal_arn=p.source_principal_arn, target_principal_arn=p.target_principal_arn,
            technique_chain=p.technique_chain, severity=p.severity,
            discovered_at=p.discovered_at.isoformat(),
        )
        for p in result.scalars().all()
    ]
