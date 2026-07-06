"""
Factory helpers — create model instances in the test DB.
Every factory commits via the provided session and returns the ORM object.
"""
import uuid
from datetime import datetime, timedelta, timezone

from passlib.context import CryptContext
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user import Tenant, User
from app.models.domain import Domain
from app.models.dmarc_report import DmarcReport, DmarcRecord, DmarcAggregate
from app.models.dns_record import DnsRecord

_pwd = CryptContext(schemes=["bcrypt"], deprecated="auto")


async def make_tenant(db: AsyncSession, *, name: str = "Test Workspace", plan: str = "free") -> Tenant:
    t = Tenant(id=uuid.uuid4(), name=name, plan=plan)
    db.add(t)
    await db.flush()
    return t


async def make_user(
    db: AsyncSession,
    tenant: Tenant,
    *,
    email: str = "test@example.com",
    password: str = "testpass123",
    role: str = "admin",
) -> User:
    u = User(
        id=uuid.uuid4(),
        tenant_id=tenant.id,
        email=email,
        hashed_password=_pwd.hash(password),
        full_name="Test User",
        role=role,
    )
    db.add(u)
    await db.flush()
    return u


async def make_domain(
    db: AsyncSession,
    tenant: Tenant,
    *,
    name: str = "example.com",
    dmarc_stage: str = "reject",
    mta_sts_stage: str = "enforce",
) -> Domain:
    d = Domain(
        id=uuid.uuid4(),
        tenant_id=tenant.id,
        name=name,
        reporting_slug=uuid.uuid4().hex[:8],
        dmarc_stage=dmarc_stage,
        mta_sts_stage=mta_sts_stage,
        is_active=True,
    )
    db.add(d)
    await db.flush()
    return d


async def make_dmarc_report(
    db: AsyncSession,
    domain: Domain,
    *,
    days_ago: int = 5,
    period_days: int = 1,
    org_name: str = "Google",
) -> DmarcReport:
    now = datetime.now(timezone.utc)
    begin = now - timedelta(days=days_ago + period_days)
    end = now - timedelta(days=days_ago)
    r = DmarcReport(
        id=uuid.uuid4(),
        domain_id=domain.id,
        report_id=str(uuid.uuid4()),
        org_name=org_name,
        org_email=f"noreply@{org_name.lower()}.com",
        period_begin=begin,
        period_end=end,
        raw_xml="<feedback/>",
    )
    db.add(r)
    await db.flush()
    return r


async def make_dmarc_record(
    db: AsyncSession,
    report: DmarcReport,
    domain: Domain,
    *,
    source_ip: str = "209.85.128.0",
    count: int = 100,
    dmarc_result: str = "pass",
    disposition: str = "none",
    dkim_aligned: bool = True,
    spf_aligned: bool = True,
) -> DmarcRecord:
    rec = DmarcRecord(
        id=uuid.uuid4(),
        report_id=report.id,
        domain_id=domain.id,
        source_ip=source_ip,
        count=count,
        disposition=disposition,
        dkim_aligned=dkim_aligned,
        spf_aligned=spf_aligned,
        dmarc_result=dmarc_result,
        header_from=domain.name,
    )
    db.add(rec)
    await db.flush()
    return rec


async def make_dmarc_aggregate(
    db: AsyncSession,
    domain: Domain,
    *,
    days_ago: int = 5,
    source_ip: str = "209.85.128.0",
    source_org: str = "Google",
    total_count: int = 100,
    pass_count: int = 80,
    fail_count: int = 20,
    disposition: str = "reject",
    classification: str = "spoof",
) -> DmarcAggregate:
    now = datetime.now(timezone.utc)
    begin = now - timedelta(days=days_ago + 1)
    end = now - timedelta(days=days_ago)
    agg = DmarcAggregate(
        id=uuid.uuid4(),
        domain_id=domain.id,
        period_begin=begin,
        period_end=end,
        source_ip=source_ip,
        source_org=source_org,
        header_from=domain.name,
        total_count=total_count,
        pass_count=pass_count,
        fail_count=fail_count,
        unaligned_count=fail_count,
        disposition=disposition,
        classification=classification,
    )
    db.add(agg)
    await db.flush()
    return agg


async def make_dns_record(
    db: AsyncSession,
    domain: Domain,
    *,
    record_type: str = "DMARC",
    record_host: str = "_dmarc",
    current_value: str = "v=DMARC1; p=reject; rua=mailto:dmarc@example.com",
    previous_value: str | None = None,
    days_ago: int = 3,
) -> DnsRecord:
    rec = DnsRecord(
        id=uuid.uuid4(),
        domain_id=domain.id,
        record_type=record_type,
        record_host=record_host,
        current_value=current_value,
        previous_value=previous_value,
        detected_at=datetime.now(timezone.utc) - timedelta(days=days_ago),
    )
    db.add(rec)
    await db.flush()
    return rec
