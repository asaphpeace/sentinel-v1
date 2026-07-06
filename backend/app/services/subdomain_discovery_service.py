"""
Passive subdomain discovery — Part 1 of GUIDED_ONBOARDING_PLAN.md (folded in
alongside DNS hand-holding). Three passive sources, ranked by signal:

  1. Sentinel's own ingested DMARC data — zero external calls, highest signal
     for "does this subdomain actually send mail" (the question that matters
     for deciding whether it needs its own DMARC alignment attention).
  2. Certificate Transparency logs via crt.sh — free, no API key, but can be
     slow or return 502 under load; degrades to an empty result, never
     blocks or raises.
  3. SAN fields on certificates Sentinel already probed (cert_service.py).

All three are safe to run even before ownership verification — they only
read public/already-owned data.

A fourth source, active DNS probing, is implemented here too but gated
hard: it only ever runs for ownership-verified domains, and is never wired
into the public no-auth /scan endpoint. Active probing on an unverified
domain would turn this into a free subdomain-enumeration tool against a
domain the requester doesn't necessarily own — the plan is explicit that
this distinction matters. Two checks, both deliberately small:
  - a short, curated wordlist of email-relevant candidates (not a generic
    brute-force — scoped to what's actually relevant to email security)
  - a one-line AXFR (zone transfer) attempt, which almost always fails on
    a correctly configured server and is free/instant either way
"""
from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass, field

import dns.exception
import dns.query
import dns.zone
import httpx
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Domain, DmarcAggregate, SslCert
from app.services.dns_resolver import resolver

log = logging.getLogger(__name__)

_CT_TIMEOUT = 8.0
_WILDCARD_PREFIX = re.compile(r"^\*\.")

# Deliberately short and scoped to email security — not a generic
# subdomain brute-force wordlist. Each candidate gets one A/CNAME lookup.
_ACTIVE_CANDIDATES = [
    "mail", "smtp", "webmail", "owa", "autodiscover",
    "mta-sts", "mx", "imap", "pop", "exchange",
]
_AXFR_TIMEOUT = 5.0


@dataclass
class DiscoveredSubdomain:
    hostname: str
    sources: list[str] = field(default_factory=list)
    sends_mail: bool = False
    mail_volume: int = 0
    already_monitored: bool = False


def _is_subdomain(hostname: str, root: str) -> bool:
    hostname = hostname.strip().lower().rstrip(".")
    root = root.strip().lower()
    return hostname.endswith("." + root) and hostname != root


async def _from_dmarc(db: AsyncSession, domain: Domain) -> dict[str, int]:
    """hostname -> total mail volume, for header_from values that are subdomains."""
    stmt = (
        select(DmarcAggregate.header_from, func.sum(DmarcAggregate.total_count))
        .where(DmarcAggregate.domain_id == domain.id)
        .group_by(DmarcAggregate.header_from)
    )
    rows = (await db.execute(stmt)).all()
    out: dict[str, int] = {}
    for header_from, total in rows:
        if header_from and _is_subdomain(header_from, domain.name):
            out[header_from.strip().lower()] = int(total or 0)
    return out


async def _from_certs(db: AsyncSession, domain: Domain) -> set[str]:
    """Sibling hostnames from SAN fields on certs Sentinel already probed."""
    stmt = select(SslCert.san).where(SslCert.domain_id == domain.id, SslCert.san.is_not(None))
    rows = (await db.execute(stmt)).scalars().all()
    out: set[str] = set()
    for san_field in rows:
        for entry in (san_field or "").split(","):
            entry = entry.strip().lower()
            if entry and not _WILDCARD_PREFIX.match(entry) and _is_subdomain(entry, domain.name):
                out.add(entry)
    return out


async def _from_ct_logs(domain_name: str) -> set[str]:
    """
    crt.sh JSON endpoint. No official rate limit, but response times of
    3-30s and occasional 502s under load are normal — this must never block
    the caller on a slow CT query, so any failure just yields an empty set.
    """
    url = f"https://crt.sh/?q=%25.{domain_name}&output=json"
    try:
        async with httpx.AsyncClient(timeout=_CT_TIMEOUT) as client:
            resp = await client.get(url)
            resp.raise_for_status()
            data = resp.json()
    except Exception:
        log.warning("CT log lookup failed or timed out for %s", domain_name)
        return set()

    out: set[str] = set()
    for entry in data:
        for raw in (entry.get("name_value") or "").split("\n"):
            host = raw.strip().lower()
            if host and not _WILDCARD_PREFIX.match(host) and _is_subdomain(host, domain_name):
                out.add(host)
    return out


async def _from_active_dns(domain_name: str) -> set[str]:
    """
    One A/CNAME lookup per curated candidate. Bounded (10 candidates), fast,
    and polite — never a brute-force sweep. Only called for ownership-
    verified domains; see discover_subdomains()'s allow_active gate.
    """
    out: set[str] = set()

    async def _check(candidate: str) -> None:
        host = f"{candidate}.{domain_name}"
        for rdtype in ("A", "CNAME"):
            try:
                await resolver.resolve(host, rdtype)
                out.add(host)
                return
            except dns.exception.DNSException:
                continue

    await asyncio.gather(*(_check(c) for c in _ACTIVE_CANDIDATES))
    return out


def _axfr_attempt_sync(domain_name: str, nameservers: list[str]) -> set[str]:
    """
    Zone transfer attempt — almost always refused by a correctly configured
    DNS server (that's the expected, common outcome, not an error). dnspython's
    xfr is synchronous, so this runs off the event loop via asyncio.to_thread.
    """
    out: set[str] = set()
    for ns in nameservers[:2]:  # at most 2 — this is a courtesy try, not a sweep
        try:
            zone = dns.zone.from_xfr(dns.query.xfr(ns, domain_name, timeout=_AXFR_TIMEOUT, lifetime=_AXFR_TIMEOUT))
            for name in zone.nodes.keys():
                host = f"{name}.{domain_name}".lower() if str(name) != "@" else domain_name.lower()
                if _is_subdomain(host, domain_name):
                    out.add(host)
            if out:
                break
        except Exception:
            continue
    return out


async def _from_axfr(domain_name: str, nameservers: list[str]) -> set[str]:
    if not nameservers:
        return set()
    try:
        return await asyncio.to_thread(_axfr_attempt_sync, domain_name, nameservers)
    except Exception:
        return set()


async def discover_subdomains(
    db: AsyncSession, domain: Domain, allow_active: bool = False
) -> list[DiscoveredSubdomain]:
    """
    allow_active gates the active-probing sources (wordlist + AXFR) — the
    caller must only pass True for ownership-verified domains, and must
    never pass True from the public /scan endpoint. Passive sources
    (dmarc/cert/ct) always run regardless.
    """
    dmarc_hits = await _from_dmarc(db, domain)
    cert_hits = await _from_certs(db, domain)
    ct_hits = await _from_ct_logs(domain.name)
    active_hits: set[str] = set()
    axfr_hits: set[str] = set()

    if allow_active:
        active_hits = await _from_active_dns(domain.name)
        try:
            answers = await resolver.resolve(domain.name, "NS")
            nameservers = [str(r.target).rstrip(".") for r in answers]
            axfr_hits = await _from_axfr(domain.name, nameservers)
        except dns.exception.DNSException:
            pass

    merged: dict[str, DiscoveredSubdomain] = {}

    def _get(hostname: str) -> DiscoveredSubdomain:
        return merged.setdefault(hostname, DiscoveredSubdomain(hostname=hostname))

    for hostname, volume in dmarc_hits.items():
        d = _get(hostname)
        d.sources.append("dmarc")
        d.sends_mail = True
        d.mail_volume = volume

    for hostname in cert_hits:
        _get(hostname).sources.append("cert")

    for hostname in ct_hits:
        _get(hostname).sources.append("ct")

    for hostname in active_hits:
        _get(hostname).sources.append("dns-active")

    for hostname in axfr_hits:
        _get(hostname).sources.append("axfr")

    if not merged:
        return []

    existing = (await db.execute(
        select(Domain.name).where(Domain.tenant_id == domain.tenant_id, Domain.is_active == True)
    )).scalars().all()
    existing_set = {n.lower() for n in existing}

    results = list(merged.values())
    for r in results:
        r.already_monitored = r.hostname in existing_set

    # Mail-sending subdomains first — this is meant to surface "what needs
    # DMARC attention", not just dump a flat list of hostnames found.
    results.sort(key=lambda r: (not r.sends_mail, -r.mail_volume, r.hostname))
    return results
