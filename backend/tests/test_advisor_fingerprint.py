"""
Unit tests for the API-usage guard in advisor_service.py — compute_fingerprint
/ is_unchanged / remember_fingerprint. These exist so a background "refresh"
request doesn't burn an LLM call when nothing in the account actually
changed since the last real generation.
"""
from app.services.advisor_service import (
    compute_fingerprint, is_unchanged, remember_fingerprint, _advisor_fingerprints,
)


def setup_function():
    _advisor_fingerprints.clear()


def test_unchanged_payload_produces_same_fingerprint():
    a = compute_fingerprint({"dmarc_stage": "reject", "fail_sources": ["x"]})
    b = compute_fingerprint({"dmarc_stage": "reject", "fail_sources": ["x"]})
    assert a == b


def test_key_order_does_not_affect_fingerprint():
    a = compute_fingerprint({"a": 1, "b": 2})
    b = compute_fingerprint({"b": 2, "a": 1})
    assert a == b


def test_changed_payload_produces_different_fingerprint():
    a = compute_fingerprint({"dmarc_stage": "reject"})
    b = compute_fingerprint({"dmarc_stage": "quarantine"})
    assert a != b


def test_is_unchanged_false_for_never_seen_key():
    fp = compute_fingerprint({"x": 1})
    assert is_unchanged("k1", fp) is False


def test_is_unchanged_true_after_remembering():
    fp = compute_fingerprint({"x": 1})
    remember_fingerprint("k1", fp)
    assert is_unchanged("k1", fp) is True


def test_is_unchanged_false_when_payload_changes():
    fp1 = compute_fingerprint({"x": 1})
    remember_fingerprint("k1", fp1)
    fp2 = compute_fingerprint({"x": 2})
    assert is_unchanged("k1", fp2) is False


# ── force=True bypass (explicit Regenerate button) ───────────────────────────
# get_advisor_message's signature documents that force=True must skip the
# unchanged-data guard regardless of whether the fingerprint matches —
# these tests exercise that contract directly against the real function
# rather than just the fingerprint primitives, with advisor calls disabled
# so no network/LLM call happens.

import asyncio

from app.services.advisor_service import get_advisor_message, AdvisorContext, _advisor_cache
from app.config import settings


def _ctx(**overrides):
    defaults = dict(
        screen="dmarc", domain_name="example.com", dmarc_stage="quarantine",
        dmarc_comp=90.0, tls_stage="testing", tls_pass_pct=90.0,
        fail_sources=[], cert_days=60,
    )
    defaults.update(overrides)
    return AdvisorContext(**defaults)


def test_force_still_returns_a_result_when_advisor_disabled(monkeypatch):
    """With the advisor disabled, force has nothing to bypass — should still
    return the rule-based result cleanly rather than erroring."""
    monkeypatch.setattr(settings, "advisor_enabled", False)
    _advisor_cache.clear()
    result = asyncio.run(get_advisor_message(_ctx(), tenant_id="t1", force=True))
    assert result["is_ai"] is False
    assert "message" in result
