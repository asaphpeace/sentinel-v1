"""
Seed realistic mock data for sentinel.org so the dashboard is populated.
Run after seed.py:
    python seed_mock.py
"""
import asyncio
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import AsyncSessionLocal, engine, Base
from app.models.user import Tenant, User
from app.models.domain import Domain
from app.models.dmarc_report import DmarcAggregate
from app.models.tls_report import TlsAggregate
from app.models.ssl_cert import SslCert
from app.services.reporting_address import generate_slug

NOW = datetime.now(timezone.utc)

def dt(days_ago: int) -> datetime:
    return NOW - timedelta(days=days_ago)


DMARC_SOURCES = [
    # (source_org, source_ip, rdns, asn,
    #  dkim_aligned, spf_aligned, dkim_result, spf_result,
    #  envelope_from, dkim_domain, dkim_selector,
    #  volume, pass_count)
    (
        "Google Workspace", "209.85.220.41", "mail-sor-f41.google.com", "AS15169",
        True, True, "pass", "pass",
        "sentinel.org",          # envelope matches — clean
        "sentinel.org", "google",
        18420, 18420,
    ),
    (
        "Microsoft 365", "40.107.93.68", "mail-db8eur05on2068.out", "AS8075",
        True, True, "pass", "pass",
        "sentinel.org",          # envelope matches — clean
        "sentinel.org", "selector1",
        6843, 6843,
    ),
    (
        "Mailchimp", "198.2.130.143", "mail143.atl141.rsgsv.net", "AS26690",
        True, False, "pass", "fail",
        "bounce@mcsv.net",       # ESP bounce domain — known mismatch, legitimate
        "sentinel.org", "k1",
        2104, 2104,
    ),
    (
        "SendGrid", "167.89.121.199", "o1.em.example.com", "AS11377",
        False, True, "none", "pass",
        "bounces@sendgrid.net",  # SendGrid bounce routing — known ESP, needs DKIM setup
        None, None,
        931, 931,
    ),
    (
        "Unknown server", "185.220.101.15", None, "AS62217",
        False, False, "fail", "fail",
        "admin@185-220-101-15.host.ru",  # suspicious envelope — likely spoof
        None, None,
        312, 0,
    ),
    (
        "Forwarded mail", "78.47.91.200", "static.78-47-91-200.de", "AS24940",
        False, True, "none", "pass",
        "sentinel.org",          # forwarded — SPF pass via SRS
        None, None,
        158, 158,
    ),
]

TLS_SOURCES = [
    # (mx_host, reporter_org, total, successful, failed, top_failure)
    ("mx1.sentinel.org", "Google",    24800, 24785, 15, "certificate-not-trusted"),
    ("mx1.sentinel.org", "Microsoft", 8200,  8200,  0,  None),
    ("mx2.sentinel.org", "Google",    4300,  4295,  5,  "starttls-not-supported"),
]

CERTS = [
    # (host, host_type, port, subject_cn, issuer, days_remaining, tls_version, starttls, status)
    ("mx1.sentinel.org",      "mx",     25,  "*.sentinel.org",      "Let's Encrypt",  87,  "TLSv1.3", True,  "ok"),
    ("mx2.sentinel.org",      "mx",     25,  "mx2.sentinel.org",    "DigiCert Inc",   204, "TLSv1.3", True,  "ok"),
    ("mta-sts.sentinel.org",  "mta-sts",443, "mta-sts.sentinel.org","Let's Encrypt",  21,  "TLSv1.3", None,  "warning"),
]


async def seed():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with AsyncSessionLocal() as db:
        # Find the tenant from the seeded admin user
        result = await db.execute(select(User).where(User.email == "admin@sentinel.local"))
        admin = result.scalar_one_or_none()
        if not admin:
            print("ERROR: Run seed.py first to create admin@sentinel.local")
            return

        tenant_id = admin.tenant_id

        # ── sentinel.org domain ───────────────────────────────────────────────
        existing = await db.execute(
            select(Domain).where(Domain.name == "sentinel.org", Domain.tenant_id == tenant_id)
        )
        domain = existing.scalar_one_or_none()
        if not domain:
            domain = Domain(
                id=uuid.uuid4(),
                tenant_id=tenant_id,
                name="sentinel.org",
                reporting_slug=generate_slug(),
                dmarc_stage="quarantine",
                dmarc_policy="v=DMARC1; p=quarantine; pct=100; rua=mailto:dmarc-rua@foundationcraft.co.za",
                dmarc_pct=100,
                mta_sts_stage="testing",
                mta_sts_policy_id="20240117093042",
                dmarc_record_published=True,
                tlsrpt_record_published=True,
                mta_sts_published=True,
                is_active=True,
            )
            db.add(domain)
            await db.flush()
            print("Created domain: sentinel.org")
        else:
            # Update stage if already exists
            domain.dmarc_stage = "quarantine"
            domain.mta_sts_stage = "testing"
            domain.dmarc_record_published = True
            domain.tlsrpt_record_published = True
            domain.mta_sts_published = True
            print("Updated domain: sentinel.org")

        # ── DMARC aggregates (last 30 days, multiple periods) ─────────────────
        period_begin = dt(30)
        period_end   = dt(0)

        for (org, ip, rdns, asn,
             dkim_al, spf_al, dkim_res, spf_res,
             env_from, dkim_dom, dkim_sel,
             vol, pass_c) in DMARC_SOURCES:
            fail_c = vol - pass_c
            agg = DmarcAggregate(
                id=uuid.uuid4(),
                domain_id=domain.id,
                period_begin=period_begin,
                period_end=period_end,
                source_org=org,
                source_ip=ip,
                rdns=rdns,
                asn=asn,
                header_from="sentinel.org",
                envelope_from=env_from,
                dkim_domain=dkim_dom,
                dkim_selector=dkim_sel,
                dkim_result=dkim_res,
                dkim_aligned=dkim_al,
                spf_domain="sentinel.org" if spf_al else None,
                spf_result=spf_res,
                spf_aligned=spf_al,
                disposition="quarantine" if (not dkim_al and not spf_al) else "none",
                total_count=vol,
                pass_count=pass_c,
                fail_count=fail_c,
                unaligned_count=fail_c,
                classification="authorized" if (dkim_al or spf_al) else ("spoof" if not rdns else "unknown"),
                classification_reason="DKIM+SPF aligned to sentinel.org" if (dkim_al and spf_al) else "Failed alignment",
                classification_confidence=95 if (dkim_al or spf_al) else 40,
            )
            db.add(agg)

        print(f"Added {len(DMARC_SOURCES)} DMARC aggregate rows")

        # ── TLS aggregates ────────────────────────────────────────────────────
        for (mx, reporter, total, succ, failed, top_fail) in TLS_SOURCES:
            tls_agg = TlsAggregate(
                id=uuid.uuid4(),
                domain_id=domain.id,
                period_begin=period_begin,
                period_end=period_end,
                mx_host=mx,
                reporter_org=reporter,
                total_sessions=total,
                successful_sessions=succ,
                failed_sessions=failed,
                top_failure_reason=top_fail,
                top_failure_count=failed,
            )
            db.add(tls_agg)

        print(f"Added {len(TLS_SOURCES)} TLS aggregate rows")

        # ── SSL certs ─────────────────────────────────────────────────────────
        for (host, htype, port, cn, issuer, days, tls_ver, starttls, status) in CERTS:
            not_after = NOW + timedelta(days=days)
            not_before = not_after - timedelta(days=90)
            cert = SslCert(
                id=uuid.uuid4(),
                domain_id=domain.id,
                host=host,
                host_type=htype,
                port=port,
                subject_cn=cn,
                issuer=f"{issuer} Authority X3",
                san=f"{host},*.{host.split('.', 1)[1]}",
                not_before=not_before,
                not_after=not_after,
                days_remaining=days,
                tls_version=tls_ver,
                starttls_supported=starttls,
                hostname_valid=True,
                status=status,
            )
            db.add(cert)

        print(f"Added {len(CERTS)} SSL cert rows")

        await db.commit()
        print()
        print("OK  sentinel.org seeded with mock data")
        print("OK  28,768 DMARC messages across 6 sources")
        print("OK  37,300 TLS sessions (99.9% pass rate)")
        print("OK  3 certs (2 healthy, 1 warning - 21 days)")


asyncio.run(seed())
