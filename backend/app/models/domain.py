import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class Domain(Base):
    __tablename__ = "domains"
    __table_args__ = (
        UniqueConstraint("name", name="uq_domains_name"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(253), index=True)  # e.g. example.com

    # Unique reporting address: <slug>@mailsentry.co.za
    # slug is a short uuid-derived token, e.g. d4a9f2b1
    reporting_slug: Mapped[str] = mapped_column(String(64), unique=True)

    # DMARC stage: none | monitor | quarantine | reject
    dmarc_stage: Mapped[str] = mapped_column(String(20), default="none")
    dmarc_policy: Mapped[str | None] = mapped_column(String(500), nullable=True)
    dmarc_pct: Mapped[int] = mapped_column(default=100)

    # MTA-STS stage: none | testing | enforce
    mta_sts_stage: Mapped[str] = mapped_column(String(20), default="none")
    mta_sts_policy_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # "self" (customer hosts mta-sts.<domain> themselves, today's only
    # option) | "managed" (Sentinel serves the policy dynamically via a
    # CNAME the customer publishes — see PAIN_POINT_RESOLUTION_PLAN.md
    # Pain 5; removes the "I need an HTTPS server" adoption barrier).
    mta_sts_hosting_mode: Mapped[str] = mapped_column(String(10), default="self")

    # Onboarding flags
    dmarc_record_published: Mapped[bool] = mapped_column(Boolean, default=False)
    tlsrpt_record_published: Mapped[bool] = mapped_column(Boolean, default=False)
    mta_sts_published: Mapped[bool] = mapped_column(Boolean, default=False)

    # Ownership verification — domain stays pending until slug confirmed in DNS
    ownership_verified: Mapped[bool] = mapped_column(Boolean, default=False)

    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    added_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    tenant: Mapped["Tenant"] = relationship(back_populates="domains")  # type: ignore[name-defined]
    dmarc_reports: Mapped[list["DmarcReport"]] = relationship(back_populates="domain")  # type: ignore[name-defined]
    tls_reports: Mapped[list["TlsReport"]] = relationship(back_populates="domain")  # type: ignore[name-defined]
    ssl_certs: Mapped[list["SslCert"]] = relationship(back_populates="domain")  # type: ignore[name-defined]
    dns_records: Mapped[list["DnsRecord"]] = relationship(back_populates="domain")  # type: ignore[name-defined]
    alerts: Mapped[list["Alert"]] = relationship(back_populates="domain")  # type: ignore[name-defined]
