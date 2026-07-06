"""
Runs the recommendation engine across domains and persists actionable results
as Alert rows — the same notification channel cert/DNS alerts already use.

Only ADVANCE and REGRESSION recommendations become alerts. HOLD is status, not
news: surfacing "still not ready" every day in the notification bell would
train users to ignore it. Holds are available to callers (e.g. a roadmap
view) via evaluate_domain() directly; they just don't ring the bell.
"""
from __future__ import annotations

import logging
import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import AsyncSessionLocal
from app.models import Alert, Domain
from app.services.recommendation_data import build_domain_input
from app.services.recommendation_engine import Direction, Recommendation, evaluate_domain

log = logging.getLogger(__name__)

_ALERTABLE = (Direction.ADVANCE, Direction.REGRESSION)


def _action_for(rec: Recommendation) -> str:
    """
    Paired "what to do" — Part 3 #5. Kept separate from rec.body (the rule's
    factual outcome) rather than parsed out of it, so the engine's pure
    output stays untouched and this mapping can evolve independently.
    """
    if rec.direction == Direction.ADVANCE:
        return "Open the Roadmap for this domain and review the proposed DNS record before publishing."
    if rec.direction == Direction.REGRESSION:
        if rec.category == "cert":
            return "Renew the certificate on the affected MX host — this is actively risking delivery."
        return "Open the Roadmap for this domain to see which source is failing, then fix its DKIM/SPF setup. Do not loosen the policy to work around it."
    return ""


async def _persist(db: AsyncSession, domain: Domain, rec: Recommendation) -> None:
    existing = await db.execute(
        select(Alert).where(
            Alert.domain_id == domain.id,
            Alert.category == rec.category,
            Alert.title == rec.title,
        )
    )
    if existing.scalar_one_or_none():
        return  # already surfaced — same dedup rule cert_service.py uses

    db.add(Alert(
        id=uuid.uuid4(),
        domain_id=domain.id,
        tenant_id=domain.tenant_id,
        severity=rec.severity,
        category=rec.category,
        title=rec.title,
        body=rec.body,
        action=_action_for(rec),
    ))


async def evaluate_and_alert_domain(db: AsyncSession, domain: Domain) -> list[Recommendation]:
    """Evaluate one domain, persist alertable outcomes, return all outcomes (including holds)."""
    domain_input = await build_domain_input(db, domain)
    recommendations = evaluate_domain(domain_input)
    for rec in recommendations:
        if rec.direction in _ALERTABLE:
            await _persist(db, domain, rec)
    await db.commit()
    return recommendations


async def evaluate_all_domains() -> None:
    """Background job: evaluate every active domain and raise alerts for advances/regressions."""
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(Domain).where(Domain.is_active == True))
        domains = result.scalars().all()
        for domain in domains:
            try:
                await evaluate_and_alert_domain(db, domain)
            except Exception:
                log.exception("Recommendation evaluation failed for %s", domain.name)
