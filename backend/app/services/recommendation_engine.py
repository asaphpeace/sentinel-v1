"""
Deterministic, rule-based recommendation engine.

Decides whether a domain is ready to advance its DMARC or MTA-STS enforcement
stage, should hold at its current stage, or has regressed and needs attention —
based on report volume, compliance history, and certificate health.

This module is intentionally free of any LLM call and free of any database
session. It takes plain dataclasses in and returns plain dataclasses out, so
the advancement logic itself can be unit-tested without a database or network
call. Natural-language explanation (the "narration") is layered on afterwards
by the caller, the same way advisor_service.py explains posture_service.py's
scores — the rules decide *what*, the narration explains *why* in prose.

Direction is structural, not incidental: a rule either tightens enforcement
(advance), holds it (no safe change), or flags a regression (something that
already happened and needs fixing) — never recommends loosening a policy as
a "fix". Loosening is something a human decides deliberately, not something
this engine suggests.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

# ── Thresholds ────────────────────────────────────────────────────────────────
# These mirror the gates already documented in the DMARC/MTA-STS guides
# (DocsView.vue sections 02/03) — keeping one set of numbers, not two.

DMARC_COMPLIANCE_GATE_PCT = 95.0      # min compliance to advance DMARC stage
DMARC_MIN_DAYS_COLLECTED = 30         # min days of aggregate data before advancing
DMARC_COMPLIANCE_DROP_PCT = 10.0      # week-over-week drop that blocks further advancement

TLS_ENFORCE_GATE_PCT = 99.0           # min TLS pass rate to advance to MTA-STS enforce
TLS_ENFORCE_MIN_DAYS = 14             # min consecutive days at that pass rate

# A source below this share of total domain volume cannot block or trigger
# a portfolio-level recommendation on its own — it's noted, not acted on.
SOURCE_VOLUME_FLOOR_PCT = 1.0

CERT_MIN_DAYS_FOR_ENFORCE = 30        # certs must have this much runway to advance to enforce


class Direction(str, Enum):
    ADVANCE = "advance"        # safe to tighten enforcement
    HOLD = "hold"               # gate not yet met — explicit, not silent
    REGRESSION = "regression"   # something that was working has broken


# ── Inputs ────────────────────────────────────────────────────────────────────

@dataclass
class SourceVolumeInput:
    """One DmarcAggregate rollup row, summed across the evaluation window."""
    source_org: str
    total_count: int
    fail_count: int
    unaligned_count: int
    classification: str  # authorized | forwarded | unauth | spoof | unknown


@dataclass
class DomainRecommendationInput:
    domain_id: str
    domain_name: str

    dmarc_stage: str                       # none | monitor | quarantine | reject
    dmarc_days_collected: int              # days since first aggregate report
    dmarc_compliance_pct: float | None     # current window compliance %
    dmarc_compliance_pct_prior: float | None  # prior window, for regression detection
    sources: list[SourceVolumeInput] = field(default_factory=list)

    mta_sts_stage: str = "none"            # none | testing | enforce
    tls_pass_pct: float | None = None      # current window TLS pass rate
    tls_pass_days_stable: int = 0          # consecutive days pass rate has held at/above gate

    min_cert_days: int | None = None       # min days-remaining across all MX certs
    cert_status_critical_or_expired: bool = False

    # PAIN_POINT_RESOLUTION_PLAN.md Pain 6 — mail-sending subdomains
    # discovered (subdomain_discovery_service.py) but with no recorded
    # disposition (subdomain_dispositions table) yet. Discovery alone is
    # passive; an undispositioned one is a hard advancement blocker, not
    # just a note, so it can't be silently missed the way it used to be.
    undispositioned_subdomains: list[str] = field(default_factory=list)


# ── Output ────────────────────────────────────────────────────────────────────

@dataclass
class Recommendation:
    domain_id: str
    direction: Direction
    severity: str          # info | warn | critical — matches Alert.severity
    category: str           # dmarc | tls | cert — matches Alert.category
    title: str
    body: str               # plain factual statement of the rule outcome
    blocking_reason: str | None = None  # set when direction == HOLD


_DMARC_NEXT_STAGE = {"none": "monitor", "monitor": "quarantine", "quarantine": "reject"}


def _significant_sources(sources: list[SourceVolumeInput]) -> list[SourceVolumeInput]:
    """Sources above the volume floor — the only ones that can gate or trigger a recommendation."""
    total = sum(s.total_count for s in sources) or 1
    return [s for s in sources if (s.total_count / total) * 100 >= SOURCE_VOLUME_FLOOR_PCT]


def _evaluate_dmarc(d: DomainRecommendationInput) -> list[Recommendation]:
    out: list[Recommendation] = []
    sig_sources = _significant_sources(d.sources)
    failing_authorized = [
        s for s in sig_sources
        if s.classification == "authorized" and s.fail_count > 0
    ]

    # Regression: a previously-authorized, significant-volume source has started failing.
    if failing_authorized and d.dmarc_stage in ("quarantine", "reject"):
        names = ", ".join(s.source_org for s in failing_authorized)
        out.append(Recommendation(
            domain_id=d.domain_id,
            direction=Direction.REGRESSION,
            severity="critical" if d.dmarc_stage == "reject" else "warn",
            category="dmarc",
            title=f"Authorized sender failing DMARC on {d.domain_name}",
            body=(
                f"{names} {'is' if len(failing_authorized) == 1 else 'are'} classified as authorized "
                f"but failing DMARC alignment while {d.domain_name} is at p={d.dmarc_stage}. "
                "Fix DKIM/SPF for this source — do not loosen the domain's policy."
            ),
        ))

    # Regression: compliance dropped sharply week-over-week.
    if (
        d.dmarc_compliance_pct is not None
        and d.dmarc_compliance_pct_prior is not None
        and d.dmarc_compliance_pct_prior - d.dmarc_compliance_pct >= DMARC_COMPLIANCE_DROP_PCT
        and d.dmarc_stage != "none"
    ):
        out.append(Recommendation(
            domain_id=d.domain_id,
            direction=Direction.REGRESSION,
            severity="warn",
            category="dmarc",
            title=f"DMARC compliance dropped on {d.domain_name}",
            body=(
                f"Compliance fell from {d.dmarc_compliance_pct_prior:.0f}% to {d.dmarc_compliance_pct:.0f}% "
                "week-over-week. Investigate before advancing this domain further."
            ),
        ))
        # A drop blocks advancement this cycle even if the gate numbers below would otherwise pass.
        return out

    # Advancement: only if there is a next stage to move to.
    next_stage = _DMARC_NEXT_STAGE.get(d.dmarc_stage)
    if next_stage is None:
        return out  # already at p=reject — nothing further to recommend here

    gate_days_ok = d.dmarc_days_collected >= DMARC_MIN_DAYS_COLLECTED
    gate_compliance_ok = (d.dmarc_compliance_pct or 0) >= DMARC_COMPLIANCE_GATE_PCT
    gate_no_failing_senders = len(failing_authorized) == 0
    gate_subdomains_resolved = len(d.undispositioned_subdomains) == 0

    if gate_days_ok and gate_compliance_ok and gate_no_failing_senders and gate_subdomains_resolved:
        out.append(Recommendation(
            domain_id=d.domain_id,
            direction=Direction.ADVANCE,
            severity="info",
            category="dmarc",
            title=f"{d.domain_name} is ready to advance to p={next_stage}",
            body=(
                f"{d.dmarc_compliance_pct:.0f}% compliance sustained over {d.dmarc_days_collected} days "
                f"with no authorized senders failing alignment. Safe to move from p={d.dmarc_stage} "
                f"to p={next_stage}."
            ),
        ))
    else:
        reasons = []
        if not gate_days_ok:
            reasons.append(f"only {d.dmarc_days_collected} of {DMARC_MIN_DAYS_COLLECTED} days collected")
        if not gate_compliance_ok:
            reasons.append(f"compliance at {(d.dmarc_compliance_pct or 0):.0f}%, needs {DMARC_COMPLIANCE_GATE_PCT:.0f}%")
        if not gate_no_failing_senders:
            reasons.append(f"{len(failing_authorized)} authorized sender(s) still failing alignment")
        if not gate_subdomains_resolved:
            names = ", ".join(d.undispositioned_subdomains)
            reasons.append(f"undecided mail-sending subdomain(s) need a disposition: {names}")
        out.append(Recommendation(
            domain_id=d.domain_id,
            direction=Direction.HOLD,
            severity="info",
            category="dmarc",
            title=f"{d.domain_name} holds at p={d.dmarc_stage}",
            body=f"Not yet ready to advance to p={next_stage}.",
            blocking_reason="; ".join(reasons),
        ))

    return out


def _evaluate_mta_sts(d: DomainRecommendationInput) -> list[Recommendation]:
    out: list[Recommendation] = []

    # Regression: certs went bad while already enforcing — this breaks live delivery now.
    if d.mta_sts_stage == "enforce" and d.cert_status_critical_or_expired:
        out.append(Recommendation(
            domain_id=d.domain_id,
            direction=Direction.REGRESSION,
            severity="critical",
            category="cert",
            title=f"Certificate risk while MTA-STS is enforcing on {d.domain_name}",
            body=(
                "An MX host certificate is critical or expired while MTA-STS is in enforce mode. "
                "MTA-STS-compliant senders may queue or fail to deliver until the certificate is replaced."
            ),
        ))

    if d.mta_sts_stage != "testing":
        return out  # only "testing -> enforce" is a recommendable advancement

    gate_pass_rate_ok = (d.tls_pass_pct or 0) >= TLS_ENFORCE_GATE_PCT
    gate_days_stable_ok = d.tls_pass_days_stable >= TLS_ENFORCE_MIN_DAYS
    gate_certs_ok = (d.min_cert_days is not None) and (d.min_cert_days >= CERT_MIN_DAYS_FOR_ENFORCE)

    if gate_pass_rate_ok and gate_days_stable_ok and gate_certs_ok:
        out.append(Recommendation(
            domain_id=d.domain_id,
            direction=Direction.ADVANCE,
            severity="info",
            category="tls",
            title=f"{d.domain_name} is ready for MTA-STS enforce",
            body=(
                f"TLS pass rate at {d.tls_pass_pct:.1f}% for {d.tls_pass_days_stable} consecutive days, "
                f"with all MX certificates valid for at least {CERT_MIN_DAYS_FOR_ENFORCE} days. "
                "Safe to move from testing to enforce."
            ),
        ))
    else:
        reasons = []
        if not gate_pass_rate_ok:
            reasons.append(f"pass rate at {(d.tls_pass_pct or 0):.1f}%, needs {TLS_ENFORCE_GATE_PCT:.0f}%")
        if not gate_days_stable_ok:
            reasons.append(f"only {d.tls_pass_days_stable} of {TLS_ENFORCE_MIN_DAYS} stable days")
        if not gate_certs_ok:
            reasons.append("MX certificate runway under the safety margin")
        out.append(Recommendation(
            domain_id=d.domain_id,
            direction=Direction.HOLD,
            severity="info",
            category="tls",
            title=f"{d.domain_name} holds at MTA-STS testing",
            body="Not yet ready to advance to enforce.",
            blocking_reason="; ".join(reasons),
        ))

    return out


def evaluate_domain(d: DomainRecommendationInput) -> list[Recommendation]:
    """Evaluate one domain against the DMARC and MTA-STS rule sets. Pure function, no I/O."""
    return _evaluate_dmarc(d) + _evaluate_mta_sts(d)


# ── Dry-run policy simulation ────────────────────────────────────────────────
# A source's fail_count is exactly the volume a stricter DMARC policy
# (quarantine/reject) would act on — p=none never touches mail regardless of
# pass/fail, so today's fail_count is already what tomorrow's enforcement
# would have blocked. This lets a user see the impact of advancing *before*
# they touch DNS, instead of trusting the recommendation blind.

@dataclass
class SourceImpact:
    source_org: str
    classification: str
    affected_count: int


@dataclass
class SourceReadiness:
    """
    PAIN_POINT_RESOLUTION_PLAN.md Pain 4 — the per-source checklist that
    turns "should I enforce" from one aggregate number into something
    actionable: every significant source, not just the ones that would be
    affected. status meanings:
      ready          — passing, or failing but below the volume floor
                       doesn't apply here (kept separate, see below_floor)
      blocking       — authorized AND failing — this is what actually
                       blocks advancement in evaluate_domain()'s real gate
      will_be_blocked — failing but NOT authorized — the intended outcome
                        of advancing, not a problem to fix
      below_floor    — too small a share of volume to gate on, shown for
                        transparency only (see SOURCE_VOLUME_FLOOR_PCT)
    """
    source_org: str
    classification: str
    total_count: int
    fail_count: int
    status: str


def _source_readiness(sources: list[SourceVolumeInput]) -> list[SourceReadiness]:
    sig_orgs = {s.source_org for s in _significant_sources(sources)}
    out: list[SourceReadiness] = []
    for s in sources:
        if s.source_org not in sig_orgs:
            status = "below_floor"
        elif s.fail_count <= 0:
            status = "ready"
        elif s.classification == "authorized":
            status = "blocking"
        else:
            status = "will_be_blocked"
        out.append(SourceReadiness(s.source_org, s.classification, s.total_count, s.fail_count, status))
    # Blocking sources first — that's the actual decision this should drive.
    order = {"blocking": 0, "will_be_blocked": 1, "ready": 2, "below_floor": 3}
    out.sort(key=lambda r: (order[r.status], -r.total_count))
    return out


@dataclass
class SimulationResult:
    domain_id: str
    target_stage: str
    total_volume: int
    affected_volume: int
    affected_pct: float
    safe: bool                                  # no authorized source would be affected
    by_classification: dict[str, int]
    authorized_sources_affected: list[SourceImpact]
    source_readiness: list[SourceReadiness] = field(default_factory=list)


def simulate_advance(d: DomainRecommendationInput) -> SimulationResult | None:
    """
    Simulate moving to the next DMARC stage against already-collected traffic.
    Returns None when there's nothing meaningful to simulate: no next stage
    (already at p=reject), or the next stage is "monitor" (enforces nothing,
    so there is no impact to preview).
    """
    next_stage = _DMARC_NEXT_STAGE.get(d.dmarc_stage)
    if next_stage is None or next_stage == "monitor":
        return None

    sig_sources = _significant_sources(d.sources)
    total_volume = sum(s.total_count for s in d.sources)
    by_classification: dict[str, int] = {}
    authorized_hit: list[SourceImpact] = []

    for s in sig_sources:
        if s.fail_count <= 0:
            continue
        by_classification[s.classification] = by_classification.get(s.classification, 0) + s.fail_count
        if s.classification == "authorized":
            authorized_hit.append(SourceImpact(s.source_org, s.classification, s.fail_count))

    affected_volume = sum(by_classification.values())

    return SimulationResult(
        domain_id=d.domain_id,
        target_stage=next_stage,
        total_volume=total_volume,
        affected_volume=affected_volume,
        affected_pct=round(affected_volume / total_volume * 100, 2) if total_volume else 0.0,
        safe=len(authorized_hit) == 0,
        by_classification=by_classification,
        authorized_sources_affected=authorized_hit,
        source_readiness=_source_readiness(d.sources),
    )
