"""
Managed MTA-STS hosting — PAIN_POINT_RESOLUTION_PLAN.md Pain 5.

A customer on hosting_mode="managed" publishes exactly one CNAME
(mta-sts.<their-domain> -> settings.mta_sts_hosting_cname_target) and
Sentinel serves the policy file dynamically, computed fresh from the
domain's real current MX hosts on every request — closing both the RFC
8461 hosting-location bug (see domains.py's policy_url fix) and the
"policy goes stale because nobody remembers to update the file" problem
that self-hosting carries.

TLS termination for arbitrary customer hostnames pointed at the CNAME
target is explicitly an infra-layer concern (e.g. Caddy or Traefik
configured for on-demand TLS, issuing a certificate per incoming SNI/Host)
— not application code. Hand-rolling a per-tenant ACME client inside this
service would be reinventing what a reverse proxy already does well, and
would need a publicly reachable production deployment to test for real,
which this local dev environment doesn't have. This module assumes that
layer exists and focuses on what IS testable here: serving the correct
policy content for whatever Host header arrives, and reporting whether a
given domain's CNAME/policy actually resolve correctly from the outside.
"""
from __future__ import annotations

import logging

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import Domain
from app.models.user import User
from app.routers.auth import get_current_user
from app.services.dns_resolver import resolver
from app.services.tls_service import generate_mta_sts_policy, resolve_mx_hosts
from app.services.cert_service import probe_tls
from app.config import settings

import dns.exception

log = logging.getLogger(__name__)


def _diagnose(dns_resolved: bool, probe: dict | None, policy_fetchable: bool | None) -> tuple[str, str, str | None]:
    """
    Pure classification, separated from the I/O above so it's unit-testable
    without a real network. Returns (diagnosis, message, cert_san).

    States, in the order a sender would actually hit them:
      no_dns        — mta-sts.<domain> has no A/AAAA/CNAME at all. Nothing
                       to query — the subdomain itself was never created.
      dns_no_https  — DNS resolves to something, but nothing answers on
                       port 443 there (connection refused/timeout). This is
                       the case that looks like it should work because an
                       MX or some other IP exists for the domain, but
                       that's a different, unrelated service (SMTP on port
                       25) — not an HTTPS web server.
      tls_untrusted — a TLS service answered, but its certificate chain
                      isn't trusted by a public CA (self-signed/expired CA
                      etc.) — distinct from a hostname mismatch.
      tls_wrong_host — a TLS service answered with a real, CA-trusted
                       cert, but it doesn't cover this hostname (e.g.
                       *.mimecast.com on shared gateway infrastructure).
                       Unlike an MX/STARTTLS hostname mismatch (informational
                       only — SMTP STARTTLS is opportunistic per RFC 3207),
                       this is a hard failure: RFC 8461 requires senders to
                       reject the policy fetch on a cert mismatch, so
                       MTA-STS protection silently does nothing.
      https_no_policy — HTTPS + cert are both fine, but the response isn't
                        a valid MTA-STS policy (wrong path/content/stale).
      live          — everything works.
    """
    if not dns_resolved:
        return (
            "no_dns",
            "mta-sts.<domain> doesn't exist in DNS yet — there's nothing to query. "
            "You need to create this subdomain before MTA-STS can work at all.",
            None,
        )

    if probe and probe.get("error"):
        kind = probe.get("error_kind", "other")
        if kind == "dns":
            return (
                "no_dns",
                "mta-sts.<domain> doesn't resolve — there's nothing to query.",
                None,
            )
        if kind in ("refused", "timeout"):
            return (
                "dns_no_https",
                "There's a host at this address, but nothing is listening for HTTPS (port 443) there. "
                "This is separate from your mail server's SMTP/STARTTLS support on port 25 — that's a "
                "different, unrelated service used for mail delivery, not for serving this policy file.",
                None,
            )
        if kind == "tls":
            return (
                "tls_untrusted",
                "A TLS service exists at this address, but its certificate chain isn't trusted by a "
                "public certificate authority — this needs a real, CA-issued certificate, not a "
                "self-signed one.",
                None,
            )
        return (
            "dns_no_https",
            f"Couldn't establish a working HTTPS connection here: {probe.get('error')}",
            None,
        )

    if probe and probe.get("hostname_valid") is False:
        san = probe.get("san") or "(no SAN reported)"
        return (
            "tls_wrong_host",
            f"HTTPS does work at this address, but the certificate presented covers \"{san}\", not "
            f"this domain — likely shared infrastructure (e.g. a mail security gateway) that isn't "
            f"configured to serve YOUR policy file specifically. Unlike an SMTP/STARTTLS mismatch, "
            f"this is a hard failure for MTA-STS: senders are required to reject a policy fetch when "
            f"the certificate doesn't match.",
            san,
        )

    if policy_fetchable:
        return ("live", "Live — the policy is being served correctly.", probe.get("san") if probe else None)

    return (
        "https_no_policy",
        "HTTPS and the certificate are both fine, but the response isn't a valid MTA-STS policy yet — "
        "check the exact path and content being served.",
        probe.get("san") if probe else None,
    )

# Public — no auth, no /domains/{id} prefix. The Host header on this
# request IS "mta-sts.<customer-domain>"; that's the only thing routing it.
public_router = APIRouter(tags=["mta-sts-hosting"])

# Authenticated — hosting-mode choice + status, scoped to one domain.
router = APIRouter(prefix="/domains/{domain_id}/mta-sts", tags=["mta-sts-hosting"])


class HostingModeIn(BaseModel):
    mode: str   # "self" | "managed"


class HostingStatusOut(BaseModel):
    hosting_mode: str
    cname_target: str
    cname_correct: bool
    policy_fetchable: bool
    detected_cname: str | None = None
    # See _diagnose() below for the full state list and why each exists.
    diagnosis: str = "no_dns"
    diagnosis_message: str = ""
    cert_san: str | None = None


async def _get_domain(domain_id: str, tenant_id, db: AsyncSession) -> Domain:
    result = await db.execute(select(Domain).where(Domain.id == domain_id, Domain.tenant_id == tenant_id))
    domain = result.scalar_one_or_none()
    if not domain:
        raise HTTPException(status_code=404, detail="Domain not found")
    return domain


@public_router.get("/.well-known/mta-sts.txt")
async def serve_managed_policy(request: Request, db: AsyncSession = Depends(get_db)):
    """
    Per RFC 8461 §3.2, a sender fetches this from https://mta-sts.<domain>
    directly — the Host header it sends IS "mta-sts.<domain>". Strip the
    "mta-sts." prefix to find which customer domain this is for.
    """
    host = (request.headers.get("host") or "").split(":")[0].lower()
    if not host.startswith("mta-sts."):
        raise HTTPException(status_code=404, detail="Not found")
    domain_name = host[len("mta-sts."):]

    result = await db.execute(select(Domain).where(Domain.name == domain_name, Domain.is_active == True))
    domain = result.scalar_one_or_none()
    if not domain or domain.mta_sts_hosting_mode != "managed":
        raise HTTPException(status_code=404, detail="Not found")

    mx_hosts = await resolve_mx_hosts(domain.name)
    policy = generate_mta_sts_policy(domain.name, mx_hosts, mode=domain.mta_sts_stage if domain.mta_sts_stage in ("testing", "enforce") else "testing")
    return Response(content=policy, media_type="text/plain")


@router.post("/hosting-mode")
async def set_hosting_mode(
    domain_id: str,
    payload: HostingModeIn,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    if payload.mode not in ("self", "managed"):
        raise HTTPException(status_code=400, detail="mode must be 'self' or 'managed'")
    domain = await _get_domain(domain_id, user.tenant_id, db)
    domain.mta_sts_hosting_mode = payload.mode
    await db.commit()
    return {"ok": True, "hosting_mode": payload.mode}


@router.get("/hosting-status", response_model=HostingStatusOut)
async def get_hosting_status(
    domain_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """
    Staged, evidence-based diagnosis, not one opaque pass/fail: (1) does
    mta-sts.<domain> resolve at all (CNAME, or A/AAAA for self-hosted IPs),
    (2) does a TLS probe of port 443 succeed and present a cert that
    actually covers this hostname, (3) does the policy content itself
    check out. Each stage can legitimately be false right after a DNS
    change is first published — that's propagation delay (see
    app/knowledge/dns.py's dns.propagation_delay fact), not necessarily a
    misconfiguration. See _diagnose() for the full state list.
    """
    domain = await _get_domain(domain_id, user.tenant_id, db)
    host = f"mta-sts.{domain.name}"

    detected_cname: str | None = None
    cname_correct = False
    dns_resolved = False
    try:
        answers = await resolver.resolve(host, "CNAME")
        detected_cname = str(answers[0].target).rstrip(".").lower()
        cname_correct = detected_cname == settings.mta_sts_hosting_cname_target.lower()
        dns_resolved = True
    except dns.exception.DNSException:
        pass

    if not dns_resolved:
        # No CNAME doesn't mean no DNS at all — plenty of self-hosted setups
        # point this subdomain at an A/AAAA record directly instead.
        for rdtype in ("A", "AAAA"):
            try:
                await resolver.resolve(host, rdtype)
                dns_resolved = True
                break
            except dns.exception.DNSException:
                continue

    probe: dict | None = None
    policy_fetchable = False
    if dns_resolved:
        probe = await probe_tls(host, 443, starttls=False)
        if not probe.get("error") and probe.get("hostname_valid"):
            # Cert layer is genuinely fine — only now is it worth checking
            # actual policy content. No point fetching content from a host
            # whose cert we already know senders would reject.
            try:
                async with httpx.AsyncClient(timeout=8) as client:
                    resp = await client.get(f"https://{host}/.well-known/mta-sts.txt")
                    policy_fetchable = resp.status_code == 200 and "version: STSv1" in resp.text
            except Exception:
                pass

    diagnosis, diagnosis_message, cert_san = _diagnose(dns_resolved, probe, policy_fetchable)

    return HostingStatusOut(
        hosting_mode=domain.mta_sts_hosting_mode,
        cname_target=settings.mta_sts_hosting_cname_target,
        cname_correct=cname_correct,
        policy_fetchable=policy_fetchable,
        detected_cname=detected_cname,
        diagnosis=diagnosis,
        diagnosis_message=diagnosis_message,
        cert_san=cert_san,
    )
