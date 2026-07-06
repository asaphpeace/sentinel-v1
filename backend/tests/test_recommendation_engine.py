"""
Unit tests for recommendation_engine.py — deliberately no DB, no fixtures.
The engine is pure by design (see its module docstring): plain dataclasses
in, plain dataclasses out. These tests exploit exactly that — every case
here runs in microseconds with zero I/O.
"""
from app.services.recommendation_engine import (
    DomainRecommendationInput,
    SourceVolumeInput,
    Direction,
    evaluate_domain,
    simulate_advance,
)
from app.services.recommendation_engine import _source_readiness


def _base_input(**overrides) -> DomainRecommendationInput:
    defaults = dict(
        domain_id="d1",
        domain_name="example.com",
        dmarc_stage="none",
        dmarc_days_collected=0,
        dmarc_compliance_pct=None,
        dmarc_compliance_pct_prior=None,
        sources=[],
        mta_sts_stage="none",
        tls_pass_pct=None,
        tls_pass_days_stable=0,
        min_cert_days=None,
        cert_status_critical_or_expired=False,
    )
    defaults.update(overrides)
    return DomainRecommendationInput(**defaults)


# ── DMARC advancement ────────────────────────────────────────────────────────

def test_dmarc_advances_when_all_gates_pass():
    d = _base_input(
        dmarc_stage="quarantine", dmarc_days_collected=35,
        dmarc_compliance_pct=97.0, dmarc_compliance_pct_prior=96.0,
        sources=[SourceVolumeInput("Google Workspace", 10_000, 0, 0, "authorized")],
    )
    recs = evaluate_domain(d)
    dmarc_recs = [r for r in recs if r.category == "dmarc"]
    assert len(dmarc_recs) == 1
    assert dmarc_recs[0].direction == Direction.ADVANCE
    assert "reject" in dmarc_recs[0].title


# ── Subdomain disposition gate (PAIN_POINT_RESOLUTION_PLAN.md Pain 6) ────────

def test_undispositioned_subdomain_blocks_advancement_even_when_other_gates_pass():
    d = _base_input(
        dmarc_stage="quarantine", dmarc_days_collected=35,
        dmarc_compliance_pct=97.0, dmarc_compliance_pct_prior=96.0,
        sources=[SourceVolumeInput("Google Workspace", 10_000, 0, 0, "authorized")],
        undispositioned_subdomains=["mail.example.com"],
    )
    [rec] = [r for r in evaluate_domain(d) if r.category == "dmarc"]
    assert rec.direction == Direction.HOLD
    assert "mail.example.com" in rec.blocking_reason


def test_resolved_subdomains_do_not_block_advancement():
    """Once dispositioned (the list is empty, regardless of which
    disposition was chosen), the gate clears like nothing was ever there."""
    d = _base_input(
        dmarc_stage="quarantine", dmarc_days_collected=35,
        dmarc_compliance_pct=97.0, dmarc_compliance_pct_prior=96.0,
        sources=[SourceVolumeInput("Google Workspace", 10_000, 0, 0, "authorized")],
        undispositioned_subdomains=[],
    )
    [rec] = [r for r in evaluate_domain(d) if r.category == "dmarc"]
    assert rec.direction == Direction.ADVANCE


def test_multiple_undispositioned_subdomains_all_named_in_blocking_reason():
    d = _base_input(
        dmarc_stage="quarantine", dmarc_days_collected=35,
        dmarc_compliance_pct=97.0, dmarc_compliance_pct_prior=96.0,
        sources=[SourceVolumeInput("Google Workspace", 10_000, 0, 0, "authorized")],
        undispositioned_subdomains=["mail.example.com", "newsletter.example.com"],
    )
    [rec] = [r for r in evaluate_domain(d) if r.category == "dmarc"]
    assert "mail.example.com" in rec.blocking_reason
    assert "newsletter.example.com" in rec.blocking_reason


def test_dmarc_holds_when_insufficient_days_collected():
    d = _base_input(
        dmarc_stage="none", dmarc_days_collected=10,
        dmarc_compliance_pct=99.0, dmarc_compliance_pct_prior=99.0,
    )
    [rec] = [r for r in evaluate_domain(d) if r.category == "dmarc"]
    assert rec.direction == Direction.HOLD
    assert "10 of 30 days" in rec.blocking_reason


def test_dmarc_holds_when_compliance_below_gate():
    d = _base_input(
        dmarc_stage="monitor", dmarc_days_collected=40,
        dmarc_compliance_pct=80.0, dmarc_compliance_pct_prior=80.0,
    )
    [rec] = [r for r in evaluate_domain(d) if r.category == "dmarc"]
    assert rec.direction == Direction.HOLD
    assert "needs 95%" in rec.blocking_reason


def test_dmarc_no_recommendation_once_at_reject():
    """Already at the final stage — nothing further to recommend on this track."""
    d = _base_input(dmarc_stage="reject", dmarc_days_collected=400, dmarc_compliance_pct=100.0)
    assert [r for r in evaluate_domain(d) if r.category == "dmarc"] == []


# ── DMARC regression ─────────────────────────────────────────────────────────

def test_dmarc_regression_when_authorized_source_fails_at_reject():
    d = _base_input(
        dmarc_stage="reject", dmarc_days_collected=60,
        dmarc_compliance_pct=92.0, dmarc_compliance_pct_prior=92.0,
        sources=[
            SourceVolumeInput("Google Workspace", 8_000, 0, 0, "authorized"),
            SourceVolumeInput("Mailchimp", 2_000, 500, 500, "authorized"),
        ],
    )
    [rec] = [r for r in evaluate_domain(d) if r.category == "dmarc"]
    assert rec.direction == Direction.REGRESSION
    assert rec.severity == "critical"
    assert "Mailchimp" in rec.body


def test_low_volume_failing_source_does_not_trigger_regression():
    """A source under the 1% volume floor can't gate or trigger anything on its own."""
    d = _base_input(
        dmarc_stage="reject", dmarc_days_collected=60,
        dmarc_compliance_pct=99.5, dmarc_compliance_pct_prior=99.5,
        sources=[
            SourceVolumeInput("Google Workspace", 99_000, 0, 0, "authorized"),
            SourceVolumeInput("TinyTestSender", 50, 50, 50, "authorized"),  # 0.05% of volume
        ],
    )
    dmarc_recs = [r for r in evaluate_domain(d) if r.category == "dmarc"]
    assert all(r.direction != Direction.REGRESSION for r in dmarc_recs)


def test_dmarc_compliance_drop_blocks_advancement_even_if_gates_otherwise_pass():
    d = _base_input(
        dmarc_stage="quarantine", dmarc_days_collected=60,
        dmarc_compliance_pct=84.0, dmarc_compliance_pct_prior=96.0,  # 12-point drop
    )
    [rec] = [r for r in evaluate_domain(d) if r.category == "dmarc"]
    assert rec.direction == Direction.REGRESSION
    assert "84%" in rec.body and "96%" in rec.body


# ── MTA-STS advancement ──────────────────────────────────────────────────────

def test_mta_sts_advances_when_all_gates_pass():
    d = _base_input(
        mta_sts_stage="testing", tls_pass_pct=99.8, tls_pass_days_stable=20, min_cert_days=60,
    )
    [rec] = [r for r in evaluate_domain(d) if r.category == "tls"]
    assert rec.direction == Direction.ADVANCE


def test_mta_sts_holds_when_pass_rate_below_gate():
    d = _base_input(
        mta_sts_stage="testing", tls_pass_pct=92.0, tls_pass_days_stable=20, min_cert_days=60,
    )
    [rec] = [r for r in evaluate_domain(d) if r.category == "tls"]
    assert rec.direction == Direction.HOLD
    assert "92.0%" in rec.blocking_reason


def test_mta_sts_holds_when_cert_runway_too_short():
    d = _base_input(
        mta_sts_stage="testing", tls_pass_pct=99.9, tls_pass_days_stable=20, min_cert_days=10,
    )
    [rec] = [r for r in evaluate_domain(d) if r.category == "tls"]
    assert rec.direction == Direction.HOLD
    assert "safety margin" in rec.blocking_reason


def test_mta_sts_no_recommendation_for_none_stage():
    """testing->enforce is the only recommendable transition — none stage is the bootstrap case, handled elsewhere."""
    d = _base_input(mta_sts_stage="none")
    assert [r for r in evaluate_domain(d) if r.category == "tls"] == []


def test_mta_sts_no_recommendation_once_at_enforce_with_healthy_certs():
    d = _base_input(mta_sts_stage="enforce", cert_status_critical_or_expired=False)
    assert [r for r in evaluate_domain(d) if r.category in ("tls", "cert")] == []


# ── Cert regression while enforcing ──────────────────────────────────────────

def test_cert_regression_while_enforcing():
    d = _base_input(mta_sts_stage="enforce", cert_status_critical_or_expired=True)
    [rec] = [r for r in evaluate_domain(d) if r.category == "cert"]
    assert rec.direction == Direction.REGRESSION
    assert rec.severity == "critical"


def test_no_cert_regression_when_not_enforcing():
    """A bad cert while still in testing mode isn't yet breaking live delivery — no regression flag."""
    d = _base_input(mta_sts_stage="testing", cert_status_critical_or_expired=True, tls_pass_pct=50, tls_pass_days_stable=0)
    cert_recs = [r for r in evaluate_domain(d) if r.category == "cert"]
    assert cert_recs == []


# ── Dry-run policy simulation ─────────────────────────────────────────────────

def test_simulate_advance_safe_when_only_unauthorized_sources_fail():
    d = _base_input(
        dmarc_stage="quarantine",
        sources=[
            SourceVolumeInput("Google Workspace", 10_000, 0, 0, "authorized"),
            SourceVolumeInput("Unknown sender", 200, 200, 0, "spoof"),
        ],
    )
    sim = simulate_advance(d)
    assert sim is not None
    assert sim.target_stage == "reject"
    assert sim.safe is True
    assert sim.authorized_sources_affected == []
    assert sim.affected_volume == 200
    assert sim.total_volume == 10_200


def test_simulate_advance_unsafe_when_authorized_source_fails():
    d = _base_input(
        dmarc_stage="quarantine",
        sources=[
            SourceVolumeInput("HubSpot", 5_000, 500, 500, "authorized"),
        ],
    )
    sim = simulate_advance(d)
    assert sim is not None
    assert sim.safe is False
    assert len(sim.authorized_sources_affected) == 1
    assert sim.authorized_sources_affected[0].source_org == "HubSpot"
    assert sim.authorized_sources_affected[0].affected_count == 500


def test_simulate_advance_none_when_already_at_reject():
    d = _base_input(dmarc_stage="reject", sources=[SourceVolumeInput("Google", 100, 0, 0, "authorized")])
    assert simulate_advance(d) is None


def test_simulate_advance_none_when_moving_into_monitor():
    """p=none -> monitor enforces nothing — there's no impact to preview."""
    d = _base_input(dmarc_stage="none", sources=[SourceVolumeInput("Google", 100, 0, 0, "authorized")])
    assert simulate_advance(d) is None


def test_simulate_advance_ignores_sources_below_volume_floor():
    """A single stray failing message from a tiny, insignificant source shouldn't flag as unsafe."""
    d = _base_input(
        dmarc_stage="quarantine",
        sources=[
            SourceVolumeInput("Google Workspace", 99_000, 0, 0, "authorized"),
            SourceVolumeInput("Tiny vendor", 5, 5, 0, "authorized"),  # well under the 1% floor
        ],
    )
    sim = simulate_advance(d)
    assert sim.safe is True
    assert sim.authorized_sources_affected == []


# ── Per-source readiness checklist (PAIN_POINT_RESOLUTION_PLAN.md Pain 4) ────

def test_source_readiness_classifies_authorized_failing_source_as_blocking():
    sources = [SourceVolumeInput("HubSpot", 5000, 500, 500, "authorized")]
    [r] = _source_readiness(sources)
    assert r.status == "blocking"


def test_source_readiness_classifies_nonauthorized_failing_source_as_will_be_blocked():
    """A spoofer failing is the intended outcome of advancing, not a blocker to fix."""
    sources = [SourceVolumeInput("Spoofer", 5000, 5000, 0, "spoof")]
    [r] = _source_readiness(sources)
    assert r.status == "will_be_blocked"


def test_source_readiness_classifies_passing_source_as_ready():
    sources = [SourceVolumeInput("Google Workspace", 10000, 0, 0, "authorized")]
    [r] = _source_readiness(sources)
    assert r.status == "ready"


def test_source_readiness_classifies_tiny_source_as_below_floor_regardless_of_failure():
    sources = [
        SourceVolumeInput("Google Workspace", 99_000, 0, 0, "authorized"),
        SourceVolumeInput("Tiny vendor", 5, 5, 0, "authorized"),  # under the 1% floor, even though authorized+failing
    ]
    statuses = {r.source_org: r.status for r in _source_readiness(sources)}
    assert statuses["Tiny vendor"] == "below_floor"
    assert statuses["Google Workspace"] == "ready"


def test_source_readiness_sorts_blocking_sources_first():
    sources = [
        SourceVolumeInput("Google Workspace", 10000, 0, 0, "authorized"),
        SourceVolumeInput("Spoofer", 300, 300, 0, "spoof"),
        SourceVolumeInput("HubSpot", 500, 500, 500, "authorized"),
    ]
    statuses = [r.status for r in _source_readiness(sources)]
    assert statuses[0] == "blocking"


def test_simulate_advance_includes_full_source_readiness():
    d = _base_input(
        dmarc_stage="quarantine",
        sources=[
            SourceVolumeInput("Google Workspace", 10000, 0, 0, "authorized"),
            SourceVolumeInput("HubSpot", 500, 500, 500, "authorized"),
        ],
    )
    sim = simulate_advance(d)
    assert len(sim.source_readiness) == 2
    orgs = {r.source_org for r in sim.source_readiness}
    assert orgs == {"Google Workspace", "HubSpot"}
