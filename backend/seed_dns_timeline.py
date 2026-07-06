"""
Seed synthetic DNS change history for mailsentry.co.za.

Simulates a realistic 90-day history:
  - Domain first seen with no DMARC → monitor → quarantine → reject journey
  - SPF tightened over time
  - MTA-STS published and moved to enforce
  - TLS-RPT added alongside MTA-STS
  - DKIM selectors appearing as ESPs were onboarded
  - One suspicious SPF change (+all) that was quickly corrected
  - One MX record change (migration)

Run from the backend/ directory:
    python seed_dns_timeline.py
"""
import asyncio
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import select, delete

from app.database import AsyncSessionLocal, engine, Base
from app.models.user import User
from app.models.domain import Domain
from app.models.dns_record import DnsRecord


def dt(days_ago: float, hour: int = 9, minute: int = 0) -> datetime:
    """Return a UTC datetime N days in the past."""
    base = datetime.now(timezone.utc).replace(hour=hour, minute=minute, second=0, microsecond=0)
    return base - timedelta(days=days_ago)


EVENTS: list[dict] = [
    # ── 90 days ago: domain first enrolled, no records yet ────────────────
    {
        "when": dt(90, 8, 12),
        "type": "MX",
        "host": "mailsentry.co.za",
        "prev": None,
        "curr": "10 mail.mailsentry.co.za | 20 mail2.mailsentry.co.za",
        "summary": "MX record created",
    },
    {
        "when": dt(90, 8, 14),
        "type": "SPF",
        "host": "mailsentry.co.za",
        "prev": None,
        "curr": "v=spf1 include:_spf.google.com ~all",
        "summary": "SPF record created",
    },

    # ── 85 days ago: DMARC published at p=none ────────────────────────────
    {
        "when": dt(85, 10, 5),
        "type": "DMARC",
        "host": "_dmarc.mailsentry.co.za",
        "prev": None,
        "curr": "v=DMARC1; p=none; rua=mailto:reports@mailsentry.co.za; ruf=mailto:reports@mailsentry.co.za; fo=1",
        "summary": "DMARC record created",
    },

    # ── 80 days ago: DKIM selector for Google Workspace onboarded ─────────
    {
        "when": dt(80, 14, 22),
        "type": "DKIM",
        "host": "google._domainkey.mailsentry.co.za",
        "prev": None,
        "curr": "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC2a8dM7EXAMPLE1234567890abcdef",
        "summary": "DKIM selector google._domainkey added",
    },

    # ── 72 days ago: Microsoft 365 DKIM selectors added ──────────────────
    {
        "when": dt(72, 9, 30),
        "type": "DKIM",
        "host": "selector1._domainkey.mailsentry.co.za",
        "prev": None,
        "curr": "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3ABCDEF1234567890abcdefGHIJKLMNOP",
        "summary": "DKIM selector selector1._domainkey added",
    },
    {
        "when": dt(72, 9, 31),
        "type": "DKIM",
        "host": "selector2._domainkey.mailsentry.co.za",
        "prev": None,
        "curr": "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3QRSTUVWXYZ1234567890zyxwvutsrqp",
        "summary": "DKIM selector selector2._domainkey added",
    },

    # ── 65 days ago: Mailchimp added to SPF ──────────────────────────────
    {
        "when": dt(65, 11, 0),
        "type": "SPF",
        "host": "mailsentry.co.za",
        "prev": "v=spf1 include:_spf.google.com ~all",
        "curr": "v=spf1 include:_spf.google.com include:servers.mcsv.net ~all",
        "summary": "SPF record changed",
    },
    {
        "when": dt(65, 11, 2),
        "type": "DKIM",
        "host": "k1._domainkey.mailsentry.co.za",
        "prev": None,
        "curr": "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3MAILCHIMP1234567890abcdefmailchimp",
        "summary": "DKIM selector k1._domainkey added",
    },

    # ── 58 days ago: DMARC advanced to quarantine ─────────────────────────
    {
        "when": dt(58, 15, 45),
        "type": "DMARC",
        "host": "_dmarc.mailsentry.co.za",
        "prev": "v=DMARC1; p=none; rua=mailto:reports@mailsentry.co.za; ruf=mailto:reports@mailsentry.co.za; fo=1",
        "curr": "v=DMARC1; p=quarantine; pct=25; rua=mailto:reports@mailsentry.co.za; ruf=mailto:reports@mailsentry.co.za; fo=1",
        "summary": "DMARC record changed",
    },

    # ── 55 days ago: MTA-STS policy published in testing ─────────────────
    {
        "when": dt(55, 10, 0),
        "type": "MTA-STS",
        "host": "_mta-sts.mailsentry.co.za",
        "prev": None,
        "curr": "v=STSv1; id=20240401120000Z",
        "summary": "MTA-STS record created",
    },
    {
        "when": dt(55, 10, 1),
        "type": "TLS-RPT",
        "host": "_smtp._tls.mailsentry.co.za",
        "prev": None,
        "curr": "v=TLSRPTv1; rua=mailto:tlsrpt@mailsentry.co.za",
        "summary": "TLS-RPT record created",
    },

    # ── 50 days ago: DMARC pct raised to 100 ─────────────────────────────
    {
        "when": dt(50, 9, 15),
        "type": "DMARC",
        "host": "_dmarc.mailsentry.co.za",
        "prev": "v=DMARC1; p=quarantine; pct=25; rua=mailto:reports@mailsentry.co.za; ruf=mailto:reports@mailsentry.co.za; fo=1",
        "curr": "v=DMARC1; p=quarantine; pct=100; rua=mailto:reports@mailsentry.co.za; ruf=mailto:reports@mailsentry.co.za; fo=1",
        "summary": "DMARC record changed",
    },

    # ── 44 days ago: SUSPICIOUS — SPF briefly opened to +all (accident) ──
    {
        "when": dt(44, 2, 17),
        "type": "SPF",
        "host": "mailsentry.co.za",
        "prev": "v=spf1 include:_spf.google.com include:servers.mcsv.net ~all",
        "curr": "v=spf1 include:_spf.google.com include:servers.mcsv.net +all",
        "summary": "SPF record changed",
    },
    # ── 44 days ago + 40 min: SPF corrected ──────────────────────────────
    {
        "when": dt(44, 2, 57),
        "type": "SPF",
        "host": "mailsentry.co.za",
        "prev": "v=spf1 include:_spf.google.com include:servers.mcsv.net +all",
        "curr": "v=spf1 include:_spf.google.com include:servers.mcsv.net ~all",
        "summary": "SPF record changed",
    },

    # ── 38 days ago: MX migration to new provider ─────────────────────────
    {
        "when": dt(38, 7, 0),
        "type": "MX",
        "host": "mailsentry.co.za",
        "prev": "10 mail.mailsentry.co.za | 20 mail2.mailsentry.co.za",
        "curr": "10 aspmx.l.google.com | 20 alt1.aspmx.l.google.com | 30 alt2.aspmx.l.google.com",
        "summary": "MX record changed",
    },

    # ── 35 days ago: SPF updated to reflect new MX / remove stale include ─
    {
        "when": dt(35, 11, 20),
        "type": "SPF",
        "host": "mailsentry.co.za",
        "prev": "v=spf1 include:_spf.google.com include:servers.mcsv.net ~all",
        "curr": "v=spf1 include:_spf.google.com include:servers.mcsv.net include:spf.protection.outlook.com -all",
        "summary": "SPF record changed",
    },

    # ── 28 days ago: MTA-STS moved to enforce ────────────────────────────
    {
        "when": dt(28, 14, 0),
        "type": "MTA-STS",
        "host": "_mta-sts.mailsentry.co.za",
        "prev": "v=STSv1; id=20240401120000Z",
        "curr": "v=STSv1; id=20240501140000Z",
        "summary": "MTA-STS record changed",
    },

    # ── 21 days ago: DMARC advanced to reject ────────────────────────────
    {
        "when": dt(21, 10, 30),
        "type": "DMARC",
        "host": "_dmarc.mailsentry.co.za",
        "prev": "v=DMARC1; p=quarantine; pct=100; rua=mailto:reports@mailsentry.co.za; ruf=mailto:reports@mailsentry.co.za; fo=1",
        "curr": "v=DMARC1; p=reject; pct=100; rua=mailto:reports@mailsentry.co.za; ruf=mailto:reports@mailsentry.co.za; fo=1",
        "summary": "DMARC record changed",
    },

    # ── 14 days ago: SendGrid selector added for transactional mail ───────
    {
        "when": dt(14, 16, 5),
        "type": "DKIM",
        "host": "s1._domainkey.mailsentry.co.za",
        "prev": None,
        "curr": "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3SENDGRID1234567890abcdefsendgrid",
        "summary": "DKIM selector s1._domainkey added",
    },
    {
        "when": dt(14, 16, 6),
        "type": "SPF",
        "host": "mailsentry.co.za",
        "prev": "v=spf1 include:_spf.google.com include:servers.mcsv.net include:spf.protection.outlook.com -all",
        "curr": "v=spf1 include:_spf.google.com include:servers.mcsv.net include:spf.protection.outlook.com include:sendgrid.net -all",
        "summary": "SPF record changed",
    },

    # ── 7 days ago: TLS-RPT address updated ──────────────────────────────
    {
        "when": dt(7, 9, 0),
        "type": "TLS-RPT",
        "host": "_smtp._tls.mailsentry.co.za",
        "prev": "v=TLSRPTv1; rua=mailto:tlsrpt@mailsentry.co.za",
        "curr": "v=TLSRPTv1; rua=mailto:tlsrpt@mailsentry.co.za,https://tlsrpt.mailsentry.co.za/v1/reports",
        "summary": "TLS-RPT record changed",
    },

    # ── 3 days ago: old DKIM selector for a retired ESP removed ──────────
    {
        "when": dt(3, 11, 45),
        "type": "DKIM",
        "host": "mail._domainkey.mailsentry.co.za",
        "prev": "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3OLDRETIRED1234567890retired",
        "curr": None,
        "summary": "DKIM selector mail._domainkey removed",
    },

    # ── Yesterday: DMARC sp= sub-domain policy added ─────────────────────
    {
        "when": dt(1, 14, 10),
        "type": "DMARC",
        "host": "_dmarc.mailsentry.co.za",
        "prev": "v=DMARC1; p=reject; pct=100; rua=mailto:reports@mailsentry.co.za; ruf=mailto:reports@mailsentry.co.za; fo=1",
        "curr": "v=DMARC1; p=reject; sp=reject; pct=100; rua=mailto:reports@mailsentry.co.za; ruf=mailto:reports@mailsentry.co.za; fo=1",
        "summary": "DMARC record changed",
    },
]


async def main():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with AsyncSessionLocal() as db:
        # Find the domain
        result = await db.execute(select(User).where(User.email == "admin@mailsentry.co.za"))
        admin = result.scalar_one_or_none()
        if not admin:
            print("ERROR: admin@mailsentry.co.za not found — run seed.py first.")
            return

        result = await db.execute(
            select(Domain).where(Domain.name == "mailsentry.co.za", Domain.tenant_id == admin.tenant_id)
        )
        domain = result.scalar_one_or_none()
        if not domain:
            print("ERROR: mailsentry.co.za domain not found — run seed_reports.py first.")
            return

        print(f"Domain: {domain.id} ({domain.name})")

        # Clear existing DNS timeline for this domain
        await db.execute(delete(DnsRecord).where(DnsRecord.domain_id == domain.id))
        await db.flush()
        print("Cleared existing DNS records")

        # Insert events
        for ev in EVENTS:
            record = DnsRecord(
                id=uuid.uuid4(),
                domain_id=domain.id,
                record_type=ev["type"],
                record_host=ev["host"],
                previous_value=ev["prev"],
                current_value=ev["curr"],
                change_summary=ev["summary"],
                detected_at=ev["when"],
            )
            db.add(record)

        await db.commit()
        print(f"Inserted {len(EVENTS)} DNS change events")
        print()
        print("OK  90-day DNS history for mailsentry.co.za seeded")
        print("OK  Journey: none -> p=none -> p=quarantine (pct=25) -> (pct=100) -> p=reject -> sp=reject")
        print("OK  MTA-STS: testing -> enforce")
        print("OK  SPF: +all incident (40 min) auto-corrected, then -all hardened")
        print("OK  MX: migrated from self-hosted to Google Workspace")
        print("OK  DKIM: Google, M365, Mailchimp, SendGrid onboarded; stale selector removed")
        print("OK  Security alerts flagged: SPF +all, DMARC downgrade (none of these apply — all forward progress)")


asyncio.run(main())
