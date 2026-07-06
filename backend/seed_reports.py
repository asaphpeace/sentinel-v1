"""
Ingest synthetic DMARC and TLS-RPT reports for mailsentry.co.za.

Creates the domain if it doesn't exist, then parses the two report
files exactly as the IMAP service would, then rebuilds aggregates.

Run from the backend/ directory:
    python seed_reports.py
"""
import asyncio
import uuid
from pathlib import Path

from sqlalchemy import select

from app.database import AsyncSessionLocal, engine, Base
from app.models.user import User
from app.models.domain import Domain
from app.services.reporting_address import generate_slug
from app.services.dmarc_parser import parse_dmarc_xml
from app.services.tls_parser import parse_tls_json
from app.services.dmarc_service import rebuild_aggregates
from app.services.tls_service import rebuild_tls_aggregates

REPORTS_DIR = Path(__file__).parent / "reports"
DMARC_FILE  = REPORTS_DIR / "dmarc_mailsentry.co.za.xml"
TLS_FILE    = REPORTS_DIR / "tls_mailsentry.co.za.json"


async def main():
    # Ensure tables exist
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with AsyncSessionLocal() as db:

        # ── Find admin tenant ─────────────────────────────────────────────
        result = await db.execute(select(User).where(User.email == "admin@mailsentry.co.za"))
        admin = result.scalar_one_or_none()
        if not admin:
            print("ERROR: admin@mailsentry.co.za not found — run seed.py first.")
            return
        tenant_id = admin.tenant_id
        print(f"Tenant: {tenant_id}")

        # ── Ensure mailsentry.co.za domain exists ───────────────────────────
        result = await db.execute(
            select(Domain).where(
                Domain.name == "mailsentry.co.za",
                Domain.tenant_id == tenant_id,
            )
        )
        domain = result.scalar_one_or_none()

        if not domain:
            domain = Domain(
                id=uuid.uuid4(),
                tenant_id=tenant_id,
                name="mailsentry.co.za",
                reporting_slug=generate_slug(),
                dmarc_stage="quarantine",
                dmarc_policy="v=DMARC1; p=quarantine; pct=100; rua=mailto:reports@mailsentry.co.za",
                dmarc_pct=100,
                mta_sts_stage="testing",
                dmarc_record_published=True,
                tlsrpt_record_published=True,
                mta_sts_published=True,
                is_active=True,
            )
            db.add(domain)
            await db.flush()
            print("Created domain: mailsentry.co.za")
        else:
            print("Domain already exists: mailsentry.co.za")

        # ── Ingest DMARC XML ──────────────────────────────────────────────
        dmarc_xml = DMARC_FILE.read_text(encoding="utf-8")
        dmarc_report = await parse_dmarc_xml(db, domain, dmarc_xml)
        print(f"Parsed DMARC report: {dmarc_report.report_id}")

        # Rebuild DMARC aggregates (groups raw records into DmarcAggregate rows)
        await rebuild_aggregates(db, domain.id)
        print("DMARC aggregates rebuilt")

        # ── Ingest TLS JSON ───────────────────────────────────────────────
        tls_json = TLS_FILE.read_text(encoding="utf-8")
        tls_report = await parse_tls_json(db, domain, tls_json)
        print(f"Parsed TLS report: {tls_report.report_id}")

        # Rebuild TLS aggregates
        await rebuild_tls_aggregates(db, domain.id)
        print("TLS aggregates rebuilt")

        await db.commit()

    print()
    print("OK  mailsentry.co.za seeded from synthetic reports")
    print("OK  DMARC: 12,896 messages across 6 sources (Google, M365, Mailchimp, survey tool, spoof)")
    print("OK  TLS:   22,315 sessions · 19 failures (cert-expired, cert-not-trusted, starttls)")


asyncio.run(main())
