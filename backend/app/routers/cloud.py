import secrets
import uuid as _uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import CloudAccountConnection
from app.models.user import User
from app.routers.auth import get_current_user
from app.schemas.cloud import (
    CloudConnectionCreate, CloudConnectionSetupOut,
    CloudConnectionOut, CloudConnectionVerifyRequest,
)
from app.services import cloud_scan_service

router = APIRouter(prefix="/cloud-connections", tags=["cloud"])

_SUPPORTED_PROVIDERS = {"aws"}  # azure, gcp follow once AWS proves the pipeline — BUILD_PLAN.md Phase 1 step 11


def _to_out(c: CloudAccountConnection) -> CloudConnectionOut:
    return CloudConnectionOut(
        id=str(c.id), provider=c.provider, status=c.status, role_arn=c.role_arn,
        connected_at=c.connected_at.isoformat() if c.connected_at else None,
        last_scanned_at=c.last_scanned_at.isoformat() if c.last_scanned_at else None,
        created_at=c.created_at.isoformat(),
    )


@router.get("", response_model=list[CloudConnectionOut])
async def list_connections(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(CloudAccountConnection)
        .where(CloudAccountConnection.tenant_id == user.tenant_id)
        .order_by(CloudAccountConnection.created_at.desc())
    )
    return [_to_out(c) for c in result.scalars().all()]


@router.post("", response_model=CloudConnectionSetupOut)
async def create_connection(
    payload: CloudConnectionCreate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    if payload.provider not in _SUPPORTED_PROVIDERS:
        raise HTTPException(status_code=400, detail=f"Provider '{payload.provider}' is not yet supported")

    external_id = secrets.token_urlsafe(24)
    connection = CloudAccountConnection(
        id=_uuid.uuid4(),
        tenant_id=user.tenant_id,
        provider=payload.provider,
        external_id=external_id,
        status="pending_verification",
        connected_by_user_id=user.id,
    )
    db.add(connection)
    await db.commit()

    setup = cloud_scan_service.generate_aws_connection_setup(external_id)
    return CloudConnectionSetupOut(
        id=str(connection.id), provider=connection.provider, status=connection.status,
        external_id=external_id, **setup,
    )


async def _get_connection(connection_id: str, db: AsyncSession, user: User) -> CloudAccountConnection:
    result = await db.execute(
        select(CloudAccountConnection).where(
            CloudAccountConnection.id == connection_id,
            CloudAccountConnection.tenant_id == user.tenant_id,
        )
    )
    connection = result.scalar_one_or_none()
    if not connection:
        raise HTTPException(status_code=404, detail="Cloud connection not found")
    return connection


@router.post("/{connection_id}/verify", response_model=CloudConnectionOut)
async def verify_connection(
    connection_id: str,
    payload: CloudConnectionVerifyRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    connection = await _get_connection(connection_id, db, user)
    connection.role_arn = payload.role_arn
    await db.commit()

    ok = await cloud_scan_service.verify_aws_connection(db, connection)
    if not ok:
        raise HTTPException(status_code=400, detail="Could not assume the provided role — check the role ARN and trust policy")
    return _to_out(connection)


@router.post("/{connection_id}/revoke", response_model=CloudConnectionOut)
async def revoke_connection(
    connection_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    connection = await _get_connection(connection_id, db, user)
    connection.status = "revoked"
    await db.commit()
    return _to_out(connection)
