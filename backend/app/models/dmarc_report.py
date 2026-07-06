import uuid
from datetime import datetime

from sqlalchemy import BigInteger, Boolean, DateTime, ForeignKey, Index, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class DmarcReport(Base):
    """Raw parsed DMARC aggregate report (one per XML report received)."""
    __tablename__ = "dmarc_reports"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    domain_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("domains.id", ondelete="CASCADE"), index=True)

    # Report metadata from the XML
    report_id: Mapped[str] = mapped_column(String(200))  # org-provided report ID
    org_name: Mapped[str] = mapped_column(String(200))
    org_email: Mapped[str] = mapped_column(String(320))
    period_begin: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    period_end: Mapped[datetime] = mapped_column(DateTime(timezone=True))

    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    raw_xml: Mapped[str] = mapped_column(Text)  # stored for re-parsing

    domain: Mapped["Domain"] = relationship(back_populates="dmarc_reports")  # type: ignore[name-defined]
    records: Mapped[list["DmarcRecord"]] = relationship(back_populates="report", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_dmarc_reports_domain_period", "domain_id", "period_begin", "period_end"),
    )


class DmarcRecord(Base):
    """One <record> element from a DMARC aggregate XML report."""
    __tablename__ = "dmarc_records"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    report_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("dmarc_reports.id", ondelete="CASCADE"), index=True)
    domain_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("domains.id", ondelete="CASCADE"), index=True)

    # Row identity
    source_ip: Mapped[str] = mapped_column(String(45))  # IPv4 or IPv6
    count: Mapped[int] = mapped_column(BigInteger)

    # Policy evaluated
    disposition: Mapped[str] = mapped_column(String(20))  # none | quarantine | reject
    dkim_aligned: Mapped[bool] = mapped_column(Boolean)
    spf_aligned: Mapped[bool] = mapped_column(Boolean)
    # Overall DMARC result: pass if dkim_aligned OR spf_aligned
    dmarc_result: Mapped[str] = mapped_column(String(10))  # pass | fail

    # Identifiers
    header_from: Mapped[str] = mapped_column(String(253))   # visible From: domain
    envelope_from: Mapped[str | None] = mapped_column(String(253), nullable=True)  # MAIL FROM domain
    envelope_to: Mapped[str | None] = mapped_column(String(253), nullable=True)

    # SPF auth result
    spf_domain: Mapped[str | None] = mapped_column(String(253), nullable=True)
    spf_result: Mapped[str | None] = mapped_column(String(20), nullable=True)  # pass|fail|softfail|neutral|none|permerror|temperror

    # DKIM auth result (first/primary signature)
    dkim_domain: Mapped[str | None] = mapped_column(String(253), nullable=True)  # d= value
    dkim_selector: Mapped[str | None] = mapped_column(String(200), nullable=True)
    dkim_result: Mapped[str | None] = mapped_column(String(20), nullable=True)  # pass|fail|none|...

    # Enrichment (populated async after ingestion)
    rdns: Mapped[str | None] = mapped_column(String(253), nullable=True)
    asn: Mapped[str | None] = mapped_column(String(30), nullable=True)
    org_name: Mapped[str | None] = mapped_column(String(200), nullable=True)  # resolved sending org

    report: Mapped[DmarcReport] = relationship(back_populates="records")

    __table_args__ = (
        Index("ix_dmarc_records_domain_ip", "domain_id", "source_ip"),
        Index("ix_dmarc_records_domain_result", "domain_id", "dmarc_result"),
    )


class DmarcAggregate(Base):
    """
    Pre-computed per-period rollup per (domain, source_org, source_ip).
    Rebuilt on every ingest run.  Used by all UI queries.
    """
    __tablename__ = "dmarc_aggregates"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    domain_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("domains.id", ondelete="CASCADE"), index=True)

    period_begin: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    period_end: Mapped[datetime] = mapped_column(DateTime(timezone=True))

    # Sending source grouping
    source_org: Mapped[str] = mapped_column(String(200))    # e.g. "Google Workspace"
    source_ip: Mapped[str] = mapped_column(String(45))
    rdns: Mapped[str | None] = mapped_column(String(253), nullable=True)
    asn: Mapped[str | None] = mapped_column(String(30), nullable=True)

    # Identity
    header_from: Mapped[str] = mapped_column(String(253))
    envelope_from: Mapped[str | None] = mapped_column(String(253), nullable=True)

    # Auth detail
    dkim_domain: Mapped[str | None] = mapped_column(String(253), nullable=True)
    dkim_selector: Mapped[str | None] = mapped_column(String(200), nullable=True)
    dkim_result: Mapped[str | None] = mapped_column(String(20), nullable=True)
    dkim_aligned: Mapped[bool] = mapped_column(Boolean, default=False)
    spf_domain: Mapped[str | None] = mapped_column(String(253), nullable=True)
    spf_result: Mapped[str | None] = mapped_column(String(20), nullable=True)
    spf_aligned: Mapped[bool] = mapped_column(Boolean, default=False)
    disposition: Mapped[str] = mapped_column(String(20), default="none")

    # Volume
    total_count: Mapped[int] = mapped_column(BigInteger, default=0)
    pass_count: Mapped[int] = mapped_column(BigInteger, default=0)
    fail_count: Mapped[int] = mapped_column(BigInteger, default=0)
    unaligned_count: Mapped[int] = mapped_column(BigInteger, default=0)

    # Classification: authorized | forwarded | unauth | spoof
    classification: Mapped[str] = mapped_column(String(20), default="unknown")
    classification_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    classification_confidence: Mapped[int] = mapped_column(Integer, default=0)

    computed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        Index("ix_dmarc_agg_domain_period", "domain_id", "period_begin", "period_end"),
        Index("ix_dmarc_agg_domain_org", "domain_id", "source_org"),
    )
