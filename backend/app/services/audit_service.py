"""
Explicit audit logging — called at the specific mutation points that matter
for a security questionnaire (auth, billing, domain lifecycle, MSP client
management), not via a generic request middleware.

Why explicit rather than a decorator/middleware hook: a middleware that logs
every mutating request is easy to get "complete" coverage from, but it logs
at the HTTP layer, where you don't yet have human-readable before/after
state (you'd be logging "PATCH /domains/abc123", not "advanced example.com
from quarantine to reject"). Explicit calls at ~15 known points cost more
to write once, but the result is something a non-engineer reviewing the log
can actually read, and a code reviewer can verify "yes, every place that
matters calls this" by checking a short, named list — not by trusting that
a middleware's request-path matching never misses a route.

Caller is expected to have already done domain/business logic; log() does
not commit on its own — it's added to the same session/transaction as the
mutation it's describing, so the audit entry and the change it records are
atomic (either both land or neither does).
"""
from __future__ import annotations

import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from app.models import AuditLogEntry
from app.models.user import User


async def log(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    action: str,
    actor: User | None = None,
    target_type: str | None = None,
    target_id: str | None = None,
    target_label: str | None = None,
    before: dict | None = None,
    after: dict | None = None,
    ip_address: str | None = None,
) -> None:
    db.add(AuditLogEntry(
        id=uuid.uuid4(),
        tenant_id=tenant_id,
        actor_user_id=actor.id if actor else None,
        actor_email=actor.email if actor else None,
        action=action,
        target_type=target_type,
        target_id=target_id,
        target_label=target_label,
        before=before,
        after=after,
        ip_address=ip_address,
    ))
