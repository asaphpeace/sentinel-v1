"""
Unit tests for generate_tls_recommendation() — the explainability pipeline's
extension to TLS failures (GUIDED_ONBOARDING_PLAN.md Part 2, item 3).
Pure function, no DB, no network.
"""
from app.services.advisor_service import generate_tls_recommendation


def test_known_failure_type_returns_specific_action():
    result = generate_tls_recommendation("mx1.example.com", "certificate-expired", 12)
    assert result["classification"] == "tls_issue"
    assert "renew" in result["dns_fix"].lower()
    assert "mx1.example.com" in result["recommendation"]
    assert "12" in result["recommendation"]
    assert result["is_ai"] is False


def test_unknown_failure_type_has_a_generic_fallback():
    result = generate_tls_recommendation("mx2.example.com", "some-future-rfc-code", 3)
    assert result["classification"] == "tls_issue"
    assert result["dns_fix"]  # never empty, even for unrecognised codes


def test_singular_vs_plural_session_wording():
    one = generate_tls_recommendation("mx.example.com", "starttls-not-supported", 1)
    many = generate_tls_recommendation("mx.example.com", "starttls-not-supported", 5)
    assert "1 failed session)" in one["recommendation"]
    assert "5 failed sessions)" in many["recommendation"]
