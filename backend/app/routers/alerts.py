from fastapi import APIRouter, Depends
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import Alert, Domain
from app.models.user import User
from app.routers.auth import get_current_user
from app.schemas.alert import AlertOut

router = APIRouter(prefix="/alerts", tags=["alerts"])


@router.get("", response_model=list[AlertOut])
async def get_alerts(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(Alert)
        .where(Alert.tenant_id == user.tenant_id)
        .order_by(Alert.created_at.desc())
        .limit(50)
    )
    alerts = result.scalars().all()
    return [
        AlertOut(
            id=str(a.id), domain_id=str(a.domain_id) if a.domain_id else None,
            severity=a.severity, category=a.category, title=a.title,
            body=a.body, action=a.action, narration=a.narration, is_read=a.is_read, created_at=a.created_at,
        )
        for a in alerts
    ]


@router.post("/{alert_id}/read")
async def mark_read(
    alert_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    await db.execute(
        update(Alert)
        .where(Alert.id == alert_id, Alert.tenant_id == user.tenant_id)
        .values(is_read=True)
    )
    await db.commit()
    return {"ok": True}
