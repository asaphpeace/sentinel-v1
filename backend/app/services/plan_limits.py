"""
Plan definitions and limit enforcement for Sentinel billing tiers.
All limits are checked here — routers import and call enforce_*.
"""
from __future__ import annotations

from fastapi import HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Domain, User
from app.models.user import Tenant


# ── Plan definitions ──────────────────────────────────────────────────────────

PLAN_LIMITS: dict[str, dict] = {
    "free": {
        "domains":      1,
        "users":        1,
        "tenants":      1,       # only relevant for MSP
        "history_days": 30,
        "pdf_report":   False,
        "recommendations": False,
        "api_access":   False,
        "white_label":  False,
        "scheduled_reports": False,
        "audit_log":    False,
    },
    "starter": {
        "domains":      5,
        "users":        3,
        "tenants":      1,
        "history_days": 90,
        "pdf_report":   True,
        "recommendations": True,
        "api_access":   False,
        "white_label":  False,
        "scheduled_reports": False,
        "audit_log":    False,
    },
    "pro": {
        "domains":      20,
        "users":        None,    # unlimited
        "tenants":      1,
        "history_days": 180,
        "pdf_report":   True,
        "recommendations": True,
        "api_access":   True,
        "white_label":  False,
        "scheduled_reports": True,
        "audit_log":    False,
    },
    "msp": {
        "domains":      150,     # across all tenants
        "users":        None,
        "tenants":      None,    # unlimited sub-tenants
        "history_days": 365,
        "pdf_report":   True,
        "recommendations": True,
        "api_access":   True,
        "white_label":  True,
        "scheduled_reports": True,
        "audit_log":    False,
    },
    "enterprise": {
        "domains":      None,
        "users":        None,
        "tenants":      None,
        "history_days": 365,
        "pdf_report":   True,
        "recommendations": True,
        "api_access":   True,
        "white_label":  True,
        "scheduled_reports": True,
        "audit_log":    True,
    },
}

PLAN_DISPLAY: dict[str, dict] = {
    "free":       {"label": "Free",       "price_zar": 0,    "annual_price_zar": 0},
    "starter":    {"label": "Starter",    "price_zar": 349,  "annual_price_zar": 3490},
    "pro":        {"label": "Pro",        "price_zar": 899,  "annual_price_zar": 8990},
    "msp":        {"label": "MSP",        "price_zar": 2499, "annual_price_zar": 24990},
    "enterprise": {"label": "Enterprise", "price_zar": None, "annual_price_zar": None},
}


def get_limits(plan: str) -> dict:
    return PLAN_LIMITS.get(plan, PLAN_LIMITS["free"])


def check_feature(tenant: Tenant, feature: str) -> bool:
    return bool(get_limits(tenant.plan).get(feature, False))


def require_feature(tenant: Tenant, feature: str) -> None:
    if not check_feature(tenant, feature):
        plan_label = PLAN_DISPLAY.get(tenant.plan, {}).get("label", tenant.plan)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "code": "feature_not_available",
                "message": f"'{feature}' is not available on the {plan_label} plan.",
                "current_plan": tenant.plan,
                "upgrade_required": True,
            },
        )


async def enforce_domain_limit(tenant: Tenant, db: AsyncSession) -> None:
    limits = get_limits(tenant.plan)
    max_domains = limits["domains"]
    if max_domains is None:
        return

    result = await db.execute(
        select(func.count()).select_from(Domain).where(
            Domain.tenant_id == tenant.id, Domain.is_active == True
        )
    )
    current = result.scalar_one()
    if current >= max_domains:
        plan_label = PLAN_DISPLAY.get(tenant.plan, {}).get("label", tenant.plan)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "code": "domain_limit_reached",
                "message": f"Your {plan_label} plan allows {max_domains} domain{'s' if max_domains != 1 else ''}. "
                           f"You have {current}. Upgrade to add more.",
                "current_plan": tenant.plan,
                "limit": max_domains,
                "current_count": current,
                "upgrade_required": True,
            },
        )


async def enforce_tenant_limit(msp_tenant: Tenant, db: AsyncSession) -> None:
    """Only meaningful for MSP plan — limits how many client sub-tenants can be created."""
    from app.models.user import Tenant as _Tenant  # avoid circular at module level
    limits = get_limits(msp_tenant.plan)
    max_tenants = limits["tenants"]
    if max_tenants is None:
        return

    result = await db.execute(
        select(func.count()).select_from(_Tenant).where(
            _Tenant.parent_tenant_id == msp_tenant.id
        )
    )
    current = result.scalar_one()
    if current >= max_tenants:
        plan_label = PLAN_DISPLAY.get(msp_tenant.plan, {}).get("label", msp_tenant.plan)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "code": "tenant_limit_reached",
                "message": f"Your {plan_label} plan allows {max_tenants} client tenant{'s' if max_tenants != 1 else ''}. "
                           f"You have {current}. Upgrade to add more.",
                "current_plan": msp_tenant.plan,
                "limit": max_tenants,
                "current_count": current,
                "upgrade_required": True,
            },
        )


async def enforce_user_limit(tenant: Tenant, db: AsyncSession) -> None:
    limits = get_limits(tenant.plan)
    max_users = limits["users"]
    if max_users is None:
        return

    result = await db.execute(
        select(func.count()).select_from(User).where(User.tenant_id == tenant.id)
    )
    current = result.scalar_one()
    if current >= max_users:
        plan_label = PLAN_DISPLAY.get(tenant.plan, {}).get("label", tenant.plan)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "code": "user_limit_reached",
                "message": f"Your {plan_label} plan allows {max_users} user{'s' if max_users != 1 else ''}. "
                           f"You have {current}. Upgrade to add more.",
                "current_plan": tenant.plan,
                "limit": max_users,
                "current_count": current,
                "upgrade_required": True,
            },
        )
