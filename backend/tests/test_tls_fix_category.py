"""
Unit tests for the TLS fix-category branching (PAIN_POINT_RESOLUTION_PLAN.md
Pain 5) — a cert/server issue must never be routed to the DNS registrar
hand-holding flow, and vice versa.
"""
from app.services.advisor_service import _TLS_FIX_ACTIONS, _TLS_FIX_CATEGORY


def test_every_fix_action_has_a_category():
    for code in _TLS_FIX_ACTIONS:
        assert code in _TLS_FIX_CATEGORY, f"{code} has a fix action but no category"


def test_cert_issues_are_categorized_as_server_not_dns():
    for code in ("certificate-expired", "certificate-host-mismatch", "certificate-not-trusted", "starttls-not-supported"):
        assert _TLS_FIX_CATEGORY[code] == "server"


def test_genuinely_dns_related_codes_are_categorized_as_dns():
    for code in ("sts-policy-fetch-error", "dnssec-invalid", "tlsa-invalid", "no-policy-found"):
        assert _TLS_FIX_CATEGORY[code] == "dns"


def test_no_category_invents_a_third_value():
    assert set(_TLS_FIX_CATEGORY.values()) == {"dns", "server"}
