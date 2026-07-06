"""
MSP sub-tenant management.
Only accessible to tenants on the 'msp' or 'enterprise' plan.

Endpoints:
  GET  /msp/clients              — list all client tenants with summary scores
  POST /msp/clients              — create a new client tenant
  GET  /msp/clients/{id}         — full detail for one client
  PATCH /msp/clients/{id}        — update client name / billing email
  DELETE /msp/clients/{id}       — remove a client tenant (and all its data)
  POST /msp/clients/{id}/invite  — invite a user directly into a client tenant
"""
from __future__ import annotations

import uuid as _uuid
import secrets

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import Domain, User
from app.models.invite import Invite
from app.models.user import Tenant
from app.routers.auth import get_current_user, _hash
from app.services.plan_limits import PLAN_LIMITS, check_feature, require_feature, enforce_tenant_limit
from app.services import audit_service, email_service
from app.routers.billing import cancel_tenant_subscription
from app.services.posture_service import (
    compute_posture, compute_sentinel_score, DomainSentinelInput,
)
from app.models import DmarcAggregate, TlsAggregate, SslCert
from app.config import settings

router = APIRouter(prefix="/msp", tags=["msp"])

MSP_PLANS = {"msp", "enterprise"}


# ── Schemas ───────────────────────────────────────────────────────────────────

class ClientSummaryOut(BaseModel):
    id: str
    name: str
    plan: str
    domain_count: int
    sentinel_score: int
    sentinel_grade: str
    sentinel_grade_color: str
    cert_alerts: int
    dmarc_reject_count: int
    dmarc_none_count: int
    created_at: str


class ClientDetailOut(ClientSummaryOut):
    billing_email: str | None
    brand_name: str | None
    brand_logo_url: str | None
    user_count: int
    domains: list[dict]


class CreateClientRequest(BaseModel):
    name: str
    billing_email: str | None = None
    brand_name: str | None = None


class UpdateClientRequest(BaseModel):
    name: str | None = None
    billing_email: str | None = None
    brand_name: str | None = None
    brand_logo_url: str | None = None


class ClientInviteRequest(BaseModel):
    email: str
    full_name: str
    role: str = "admin"
    send_invite: bool = True   # False = create account directly (MSP onboarding flow)
    password: str | None = None  # required when send_invite=False


# ── Guards ────────────────────────────────────────────────────────────────────

def _require_msp(tenant: Tenant) -> None:
    if tenant.plan not in MSP_PLANS:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "code": "msp_plan_required",
                "message": "Sub-tenant management requires the MSP or Enterprise plan.",
                "upgrade_required": True,
            },
        )


# ── Internal helpers ──────────────────────────────────────────────────────────

async def _client_summary(client: Tenant, db: AsyncSession) -> ClientSummaryOut:
    domains_result = await db.execute(
        select(Domain).where(Domain.tenant_id == client.id, Domain.is_active == True)
    )
    domains = domains_result.scalars().all()

    sentinel_inputs = []
    cert_alerts = 0
    dmarc_reject = 0
    dmarc_none   = 0

    for d in domains:
        da = await db.execute(
            select(func.sum(DmarcAggregate.total_count), func.sum(DmarcAggregate.pass_count))
            .where(DmarcAggregate.domain_id == d.id)
        )
        da_row = da.one()
        vol = int(da_row[0] or 0)
        comp = round(int(da_row[1] or 0) / vol * 100, 1) if vol else None

        ta = await db.execute(
            select(func.sum(TlsAggregate.total_sessions), func.sum(TlsAggregate.successful_sessions))
            .where(TlsAggregate.domain_id == d.id)
        )
        ta_row = ta.one()
        tls_total = int(ta_row[0] or 0)
        tls_pct = round(int(ta_row[1] or 0) / tls_total * 100, 1) if tls_total else None

        certs = (await db.execute(select(SslCert).where(SslCert.domain_id == d.id))).scalars().all()
        min_days = min((c.days_remaining for c in certs if c.days_remaining is not None), default=None)
        worst_cert = None
        for c in certs:
            if c.status == "expired": worst_cert = "expired"; break
            elif c.status == "critical" and worst_cert != "expired": worst_cert = "critical"
            elif c.status == "expiring_soon" and worst_cert not in ("expired", "critical"): worst_cert = "expiring_soon"

        if worst_cert in ("expired", "critical", "expiring_soon"):
            cert_alerts += 1

        stage = d.dmarc_stage or "none"
        if stage == "reject": dmarc_reject += 1
        if stage in ("none",) and not d.dmarc_record_published: dmarc_none += 1

        sentinel_inputs.append(DomainSentinelInput(
            dmarc_stage=d.dmarc_stage or "none",
            tls_stage=d.mta_sts_stage or "none",
            tls_pass_pct=tls_pct,
            min_cert_days=min_days,
            cert_status=worst_cert,
            volume=vol,
        ))

    sentinel = compute_sentinel_score(sentinel_inputs)

    return ClientSummaryOut(
        id=str(client.id),
        name=client.name,
        plan=client.plan,
        domain_count=len(domains),
        sentinel_score=sentinel.score,
        sentinel_grade=sentinel.grade,
        sentinel_grade_color=sentinel.grade_color,
        cert_alerts=cert_alerts,
        dmarc_reject_count=dmarc_reject,
        dmarc_none_count=dmarc_none,
        created_at=client.created_at.isoformat(),
    )


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/clients", response_model=list[ClientSummaryOut])
async def list_clients(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    tenant_result = await db.execute(select(Tenant).where(Tenant.id == user.tenant_id))
    tenant = tenant_result.scalar_one()
    _require_msp(tenant)

    clients_result = await db.execute(
        select(Tenant)
        .where(Tenant.parent_tenant_id == tenant.id)
        .order_by(Tenant.name)
    )
    clients = clients_result.scalars().all()

    import asyncio
    summaries = await asyncio.gather(*[_client_summary(c, db) for c in clients])
    return list(summaries)


@router.post("/clients", response_model=ClientDetailOut, status_code=201)
async def create_client(
    payload: CreateClientRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    tenant_result = await db.execute(select(Tenant).where(Tenant.id == user.tenant_id))
    msp_tenant = tenant_result.scalar_one()
    _require_msp(msp_tenant)
    await enforce_tenant_limit(msp_tenant, db)

    client = Tenant(
        id=_uuid.uuid4(),
        name=payload.name,
        plan="free",           # clients start on free; MSP manages upgrading
        parent_tenant_id=msp_tenant.id,
        billing_email=payload.billing_email,
        brand_name=payload.brand_name,
    )
    db.add(client)
    await audit_service.log(
        db, tenant_id=msp_tenant.id, actor=user, action="msp.client_created",
        target_type="tenant", target_id=str(client.id), target_label=client.name,
    )
    await db.commit()

    summary = await _client_summary(client, db)
    return ClientDetailOut(
        **summary.model_dump(),
        billing_email=client.billing_email,
        brand_name=client.brand_name,
        brand_logo_url=client.brand_logo_url,
        user_count=0,
        domains=[],
    )


@router.get("/clients/{client_id}", response_model=ClientDetailOut)
async def get_client(
    client_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    tenant_result = await db.execute(select(Tenant).where(Tenant.id == user.tenant_id))
    msp_tenant = tenant_result.scalar_one()
    _require_msp(msp_tenant)

    client = await _get_client_or_404(client_id, msp_tenant.id, db)

    domains_result = await db.execute(
        select(Domain).where(Domain.tenant_id == client.id, Domain.is_active == True)
    )
    domains = domains_result.scalars().all()

    users_count = (await db.execute(
        select(func.count()).select_from(User).where(User.tenant_id == client.id)
    )).scalar_one()

    summary = await _client_summary(client, db)
    return ClientDetailOut(
        **summary.model_dump(),
        billing_email=client.billing_email,
        brand_name=client.brand_name,
        brand_logo_url=client.brand_logo_url,
        user_count=users_count,
        domains=[
            {
                "id": str(d.id),
                "name": d.name,
                "dmarc_stage": d.dmarc_stage,
                "mta_sts_stage": d.mta_sts_stage,
                "ownership_verified": d.ownership_verified,
            }
            for d in domains
        ],
    )


@router.patch("/clients/{client_id}", response_model=ClientDetailOut)
async def update_client(
    client_id: str,
    payload: UpdateClientRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    tenant_result = await db.execute(select(Tenant).where(Tenant.id == user.tenant_id))
    msp_tenant = tenant_result.scalar_one()
    _require_msp(msp_tenant)

    client = await _get_client_or_404(client_id, msp_tenant.id, db)

    if payload.name is not None:         client.name = payload.name
    if payload.billing_email is not None: client.billing_email = payload.billing_email
    if payload.brand_name is not None:   client.brand_name = payload.brand_name
    if payload.brand_logo_url is not None: client.brand_logo_url = payload.brand_logo_url

    await db.commit()
    return await get_client(client_id, db=db, user=user)


@router.delete("/clients/{client_id}", status_code=204)
async def delete_client(
    client_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    tenant_result = await db.execute(select(Tenant).where(Tenant.id == user.tenant_id))
    msp_tenant = tenant_result.scalar_one()
    _require_msp(msp_tenant)

    client = await _get_client_or_404(client_id, msp_tenant.id, db)

    # Client tenants can self-upgrade to their own independent Stripe
    # subscription (see billing.py) — deleting the row without cancelling
    # that subscription first would orphan it: Stripe keeps charging the
    # card with no application account left behind it for anyone to cancel.
    had_subscription = bool(client.stripe_subscription_id)
    await cancel_tenant_subscription(client)

    # Logged against the MSP's own tenant (not the client's, which is about
    # to be deleted) — same reasoning as auth.py's tenant-deletion case: an
    # audit row scoped to the tenant being deleted would cascade-delete with it.
    await audit_service.log(
        db, tenant_id=msp_tenant.id, actor=user, action="msp.client_deleted",
        target_type="tenant", target_id=str(client.id), target_label=client.name,
        after={"had_active_subscription": had_subscription},
    )
    await db.delete(client)
    await db.commit()


@router.post("/clients/{client_id}/invite", status_code=201)
async def invite_to_client(
    client_id: str,
    payload: ClientInviteRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """
    Two modes:
    - send_invite=True  → create an Invite token and return the URL (email sent externally)
    - send_invite=False → create the account directly with the given password (MSP onboarding)
    """
    tenant_result = await db.execute(select(Tenant).where(Tenant.id == user.tenant_id))
    msp_tenant = tenant_result.scalar_one()
    _require_msp(msp_tenant)

    client = await _get_client_or_404(client_id, msp_tenant.id, db)

    if payload.role not in ("admin", "viewer"):
        raise HTTPException(status_code=400, detail="Role must be admin or viewer")

    # Mirrors the uniqueness rule from auth.py's accept_invite: a password
    # account with this email anywhere blocks a new password account; any
    # account (password or SSO) with this email in *this* tenant blocks it
    # too. A global "any auth_method, any tenant" check would incorrectly
    # reject this when the only collision is an unrelated SSO identity.
    password_conflict = await db.execute(
        select(User).where(User.email == payload.email.lower(), User.auth_method == "password")
    )
    same_tenant_conflict = await db.execute(
        select(User).where(User.email == payload.email.lower(), User.tenant_id == client.id)
    )
    if password_conflict.scalar_one_or_none() or same_tenant_conflict.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="This email already has an account")

    if payload.send_invite:
        token = secrets.token_urlsafe(32)
        invite = Invite(
            id=_uuid.uuid4(),
            tenant_id=client.id,
            invited_by_id=user.id,
            email=payload.email.lower(),
            role=payload.role,
            token=token,
            expires_at=datetime.now(timezone.utc) + timedelta(days=7),
        )
        db.add(invite)
        await audit_service.log(
            db, tenant_id=msp_tenant.id, actor=user, action="msp.client_invite_sent",
            target_type="invite", target_id=str(invite.id), target_label=f"{payload.email} -> {client.name}",
        )
        await db.commit()

        import html
        safe_inviter = html.escape(user.full_name or user.email)
        safe_client = html.escape(client.name)

        invite_url = f"{settings.app_base_url}/accept-invite?token={token}"
        await email_service.send_email(
            to=invite.email,
            subject=f"You've been invited to {client.name} on Sentinel",
            title=f"You've been invited to {client.name}",
            body_html=(
                f"<p>{safe_inviter} has invited you to join "
                f"<strong>{safe_client}</strong> on Sentinel as a {invite.role}.</p>"
                f"<p style=\"margin: 24px 0;\">"
                f"<a href=\"{invite_url}\" style=\"background:#5b6ef5;color:#fff;padding:10px 20px;"
                f"border-radius:8px;text-decoration:none;font-weight:600;\">Accept invite</a></p>"
                f"<p style=\"color:#888;font-size:12px;\">This link expires in 7 days. "
                f"If you weren't expecting this, you can ignore it.</p>"
            ),
            text_body=f"{user.full_name or user.email} has invited you to join {client.name} on Sentinel. Accept: {invite_url}",
        )
        return {
            "mode": "invite",
            "email": payload.email,
            "invite_url": invite_url,
            "expires_at": invite.expires_at.isoformat(),
        }
    else:
        if not payload.password:
            raise HTTPException(status_code=400, detail="password required when send_invite=False")
        new_user = User(
            id=_uuid.uuid4(),
            tenant_id=client.id,
            email=payload.email.lower(),
            hashed_password=_hash(payload.password),
            full_name=payload.full_name,
            role=payload.role,
            auth_method="password",
        )
        db.add(new_user)
        await audit_service.log(
            db, tenant_id=msp_tenant.id, actor=user, action="msp.client_user_created",
            target_type="user", target_id=str(new_user.id), target_label=f"{payload.email} -> {client.name}",
        )
        await db.commit()
        return {
            "mode": "direct",
            "user_id": str(new_user.id),
            "email": new_user.email,
            "tenant_id": str(client.id),
        }


async def _get_client_or_404(client_id: str, msp_tenant_id, db: AsyncSession) -> Tenant:
    result = await db.execute(
        select(Tenant).where(
            Tenant.id == client_id,
            Tenant.parent_tenant_id == msp_tenant_id,
        )
    )
    client = result.scalar_one_or_none()
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")
    return client
