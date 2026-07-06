"""
Tests for managed MTA-STS hosting (PAIN_POINT_RESOLUTION_PLAN.md Pain 5):
the dynamic policy-serving endpoint and resolve_mx_hosts(). Exercises the
real ASGI app via httpx, not mocked, the same way the live verification
during the session was done.
"""
import pytest

from app.services.tls_service import generate_mta_sts_policy
from app.routers.mta_sts_hosting import _diagnose


def test_generate_mta_sts_policy_includes_real_mx_hosts():
    """Regression test for the bug where every call site passed an empty
    mx_hosts list — a policy with no mx: lines is a silent RFC 8461 no-op
    regardless of mode."""
    policy = generate_mta_sts_policy("example.com", ["mx1.example.com", "mx2.example.com"], mode="enforce")
    assert "mx: mx1.example.com" in policy
    assert "mx: mx2.example.com" in policy
    assert "mode: enforce" in policy


def test_generate_mta_sts_policy_with_no_mx_hosts_is_still_well_formed():
    """A domain with genuinely no MX yet should produce a syntactically
    valid (if empty) policy, not an error."""
    policy = generate_mta_sts_policy("example.com", [], mode="testing")
    assert "version: STSv1" in policy
    assert "mx:" not in policy


@pytest.mark.asyncio
async def test_policy_endpoint_404s_for_self_hosted_domain(monkeypatch):
    from httpx import AsyncClient, ASGITransport
    from app.main import app

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/.well-known/mta-sts.txt", headers={"Host": "mta-sts.thebmi.co.za"})
        assert resp.status_code == 404


@pytest.mark.asyncio
async def test_policy_endpoint_404s_for_wrong_host_prefix():
    from httpx import AsyncClient, ASGITransport
    from app.main import app

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/.well-known/mta-sts.txt", headers={"Host": "notmta-sts.example.com"})
        assert resp.status_code == 404


@pytest.mark.asyncio
async def test_policy_endpoint_404s_for_unknown_domain():
    from httpx import AsyncClient, ASGITransport
    from app.main import app

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/.well-known/mta-sts.txt", headers={"Host": "mta-sts.totally-unknown-domain-xyz.com"})
        assert resp.status_code == 404


# ── _diagnose() — pure classifier, no network needed ────────────────────────
# This is the actual gap raised in conversation: "mta-sts.<domain> has no
# subdomain at all" must be differentiated from "an IP/host exists there but
# nothing answers HTTPS" (the Mimecast-relay-but-no-web-server case), which
# must in turn be differentiated from "HTTPS answers but the cert covers
# someone else's domain" (a hard MTA-STS failure, unlike an MX/STARTTLS
# mismatch, which is merely informational).

def test_diagnose_no_dns_when_subdomain_does_not_resolve():
    diagnosis, message, san = _diagnose(dns_resolved=False, probe=None, policy_fetchable=False)
    assert diagnosis == "no_dns"
    assert san is None


def test_diagnose_dns_no_https_on_connection_refused():
    probe = {"error": "Connection refused", "error_kind": "refused"}
    diagnosis, message, san = _diagnose(dns_resolved=True, probe=probe, policy_fetchable=False)
    assert diagnosis == "dns_no_https"
    assert "SMTP/STARTTLS" in message  # must explicitly name the distinction
    assert san is None


def test_diagnose_dns_no_https_on_timeout():
    probe = {"error": "timed out", "error_kind": "timeout"}
    diagnosis, message, san = _diagnose(dns_resolved=True, probe=probe, policy_fetchable=False)
    assert diagnosis == "dns_no_https"


def test_diagnose_tls_untrusted_for_bad_cert_chain():
    probe = {"error": "certificate verify failed: self signed certificate", "error_kind": "tls"}
    diagnosis, message, san = _diagnose(dns_resolved=True, probe=probe, policy_fetchable=False)
    assert diagnosis == "tls_untrusted"


def test_diagnose_tls_wrong_host_reports_real_san_evidence():
    """The exact Mimecast scenario: TLS works, cert is real and trusted,
    but it covers someone else's domain."""
    probe = {"error": None, "hostname_valid": False, "san": "*.mimecast.com"}
    diagnosis, message, san = _diagnose(dns_resolved=True, probe=probe, policy_fetchable=False)
    assert diagnosis == "tls_wrong_host"
    assert san == "*.mimecast.com"
    assert "*.mimecast.com" in message
    assert "hard failure" in message


def test_diagnose_https_no_policy_when_cert_fine_but_content_wrong():
    probe = {"error": None, "hostname_valid": True, "san": "mta-sts.example.com"}
    diagnosis, message, san = _diagnose(dns_resolved=True, probe=probe, policy_fetchable=False)
    assert diagnosis == "https_no_policy"


def test_diagnose_live_when_everything_checks_out():
    probe = {"error": None, "hostname_valid": True, "san": "mta-sts.example.com"}
    diagnosis, message, san = _diagnose(dns_resolved=True, probe=probe, policy_fetchable=True)
    assert diagnosis == "live"
