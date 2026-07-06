"""
Unit tests for verdict_service.py's DKIM-failure sub-classification
(PAIN_POINT_RESOLUTION_PLAN.md Pain 3) — splitting "modified in transit"
vs "key/selector mismatch" into ranked, evidence-based hypotheses instead
of one lumped sentence.
"""
from app.services.verdict_service import compute_verdict, _diagnose_dkim_failure


def _dkim_fail_verdict(envelope_mismatch_envelope: str, header_from: str = "example.com"):
    return compute_verdict(
        header_from=header_from,
        envelope_from=envelope_mismatch_envelope,
        dkim_domain=header_from,
        dkim_result="fail",
        dkim_aligned=False,
        spf_domain=envelope_mismatch_envelope,
        spf_result="fail",
        spf_aligned=False,
        dmarc_result="fail",
    )


def test_auth_failure_verdict_includes_both_hypotheses():
    v = _dkim_fail_verdict("bounce.example.com")
    assert v["verdict"] == "auth_failure"
    ids = {h["id"] for h in v["dkim_failure_hypotheses"]}
    assert ids == {"transit_modification", "key_mismatch"}


def test_envelope_mismatch_ranks_transit_modification_higher():
    v = _dkim_fail_verdict("bounce.mailinglist.org")
    assert v["dkim_failure_hypotheses"][0]["id"] == "transit_modification"
    assert v["dkim_failure_hypotheses"][0]["confidence"] > v["dkim_failure_hypotheses"][1]["confidence"]


def test_no_envelope_mismatch_ranks_key_mismatch_higher():
    v = _dkim_fail_verdict("example.com")  # envelope matches header — no mismatch
    assert v["dkim_failure_hypotheses"][0]["id"] == "key_mismatch"
    assert v["dkim_failure_hypotheses"][0]["confidence"] > v["dkim_failure_hypotheses"][1]["confidence"]


def test_hypotheses_carry_distinct_fix_guidance():
    """The whole point of splitting these is that the fixes differ."""
    hyps = _diagnose_dkim_failure(envelope_mismatch=True, known_esp=None, dkim_domain="example.com", header_from="example.com")
    transit = next(h for h in hyps if h["id"] == "transit_modification")
    key = next(h for h in hyps if h["id"] == "key_mismatch")
    assert "ARC" in transit["fix"]
    assert "key" in key["fix"].lower()
    assert transit["fix"] != key["fix"]


def test_known_esp_referenced_in_key_mismatch_fix_when_present():
    hyps = _diagnose_dkim_failure(envelope_mismatch=False, known_esp="SendGrid", dkim_domain="example.com", header_from="example.com")
    key = next(h for h in hyps if h["id"] == "key_mismatch")
    assert "SendGrid" in key["fix"]


def test_other_verdicts_have_empty_hypotheses_list():
    """Only auth_failure (DKIM result == fail) should populate this — every
    other verdict path must default to an empty list, not omit the key."""
    v = compute_verdict(
        header_from="example.com", envelope_from="example.com",
        dkim_domain="example.com", dkim_result="pass", dkim_aligned=True,
        spf_domain="example.com", spf_result="pass", spf_aligned=True,
        dmarc_result="pass",
    )
    assert v["dkim_failure_hypotheses"] == []
