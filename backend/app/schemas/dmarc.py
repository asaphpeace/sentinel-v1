from __future__ import annotations
from datetime import datetime
from pydantic import BaseModel


class DmarcAuthDetailOut(BaseModel):
    """
    Deepest drill level: one auth-result group within an IP.
    Includes header-from, envelope-from, DKIM selector + d= + result,
    SPF domain + result, plain-English explanation, and structured verdict.
    """
    header_from: str
    envelope_from: str | None
    dkim_selector: str | None
    dkim_domain: str | None
    dkim_result: str | None
    dkim_aligned: bool
    spf_domain: str | None
    spf_result: str | None
    spf_aligned: bool
    dmarc_result: str
    disposition: str
    volume: int
    explanation: str

    # Verdict fields (computed by verdict_service)
    envelope_mismatch: bool = False
    known_esp: str | None = None
    verdict: str = "unauth"                # authorized | authorized_dkim | authorized_spf |
                                           # esp_bounce | esp_unauth | auth_failure |
                                           # likely_spoof | unauth
    verdict_label: str = ""
    verdict_color: str = "amber"           # good | warn | amber | bad
    verdict_detail: str = ""
    # PAIN_POINT_RESOLUTION_PLAN.md Pain 3 — populated only when verdict ==
    # "auth_failure"; ranked, evidence-based hypotheses, never a single
    # claimed-certain cause.
    dkim_failure_hypotheses: list[dict] = []


class DmarcIpOut(BaseModel):
    """Second drill level: one source IP with its auth details."""
    source_ip: str
    rdns: str | None
    asn: str | None
    volume: int
    spf_result: str | None
    dkim_result: str | None
    dmarc_result: str
    dkim_aligned: bool
    spf_aligned: bool
    # Envelope mismatch flag for the source table indicator
    envelope_mismatch: bool = False
    known_esp: str | None = None
    auth_details: list[DmarcAuthDetailOut]


class DmarcSourceOut(BaseModel):
    """Top-level sending source (org) grouping."""
    source_org: str
    volume: int
    spf_alignment: str      # ALIGNED | UNALIGNED | FAIL
    dkim_alignment: str
    dmarc_result: str       # PASS | FAIL
    classification: str     # authorized | forwarded | unauth | spoof | unknown
    classification_label: str
    classification_reason: str
    classification_confidence: int
    recommended_action: str
    ips: list[DmarcIpOut]
    # Period coverage — when this org's traffic was observed
    earliest_period: datetime | None = None
    latest_period: datetime | None = None
    report_count: int = 0


class DmarcComplianceOut(BaseModel):
    total: int
    pass_count: int
    fail_count: int
    unaligned_count: int
    compliance_pct: float | None
    dkim_pct: float | None = None   # % of messages where DKIM aligned
    spf_pct: float | None = None    # % of messages where SPF aligned


class SubdomainGroupOut(BaseModel):
    """
    Sources folded under the header-from domain that actually sent them.
    Per DMARC's tree-walk behaviour, a subdomain with no DMARC record of its
    own is evaluated against its organizational domain's record and its
    aggregate reports arrive at the *parent's* rua address — so this data
    exists for subdomains that were never separately added as a monitored
    Domain. is_monitored reflects whether it happens to be one anyway.
    """
    header_from: str
    is_primary: bool        # True when header_from == the domain being viewed
    is_monitored: bool
    volume: int
    sources: list[DmarcSourceOut]


class DmarcOverviewOut(BaseModel):
    domain: str
    policy: str | None
    pct: int
    compliance: DmarcComplianceOut
    sources: list[DmarcSourceOut]
    subdomain_groups: list[SubdomainGroupOut] = []


class RecordDiffOut(BaseModel):
    host: str
    current: str
    proposed: str
    why: str
    gates: list[dict]
    ready: bool
