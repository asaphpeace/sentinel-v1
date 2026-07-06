from __future__ import annotations
from pydantic import BaseModel


class TlsFailGroupOut(BaseModel):
    mx_host: str
    reporter_org: str
    failed_sessions: int
    successful_sessions: int
    total_sessions: int
    top_failure_reason: str | None
    failure_explanation: str
    severity: str  # critical | warning | info


class TlsFailTypeOut(BaseModel):
    reason: str
    label: str
    count: int
    pct: float


class TlsMxHostOut(BaseModel):
    mx_host: str
    total_sessions: int
    successful_sessions: int
    failed_sessions: int
    pass_pct: float
    top_failure_reason: str | None
    failure_explanation: str | None
    severity: str  # ok | warning | critical
    # PAIN_POINT_RESOLUTION_PLAN.md Pain 5 — "Fix this" must branch by
    # category: a cert/server issue routes to mail-server guidance, a
    # genuinely DNS-related code routes to the registrar hand-holding flow.
    # Both None when there's no failure to fix.
    fix_action: str | None = None
    fix_category: str | None = None   # "dns" | "server"


class TlsOverviewOut(BaseModel):
    domain: str
    mta_sts_stage: str
    total_sessions: int
    successful_sessions: int
    failed_sessions: int
    pass_pct: float
    fail_groups: list[TlsFailGroupOut]
    fail_types: list[TlsFailTypeOut]
    mx_hosts: list[TlsMxHostOut]


class TlsDomainSummaryOut(BaseModel):
    domain_id: str
    domain: str
    mta_sts_stage: str
    total_sessions: int
    pass_pct: float
    failed_sessions: int
