import uuid
from datetime import datetime

from sqlalchemy import BigInteger, DateTime, ForeignKey, Index, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class TlsReport(Base):
    """Raw parsed SMTP TLS report (RFC 8460 JSON)."""
    __tablename__ = "tls_reports"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    domain_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("domains.id", ondelete="CASCADE"), index=True)

    report_id: Mapped[str] = mapped_column(String(200))
    org_name: Mapped[str] = mapped_column(String(200))
    org_contact: Mapped[str] = mapped_column(String(320))
    period_begin: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    period_end: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    raw_json: Mapped[str] = mapped_column(Text)

    domain: Mapped["Domain"] = relationship(back_populates="tls_reports")  # type: ignore[name-defined]
    policies: Mapped[list["TlsPolicy"]] = relationship(back_populates="report", cascade="all, delete-orphan")


class TlsPolicy(Base):
    """One policy block within a TLS report."""
    __tablename__ = "tls_policies"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    report_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tls_reports.id", ondelete="CASCADE"), index=True)
    domain_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("domains.id", ondelete="CASCADE"), index=True)

    policy_type: Mapped[str] = mapped_column(String(30))   # sts | tlsa | no-policy-found
    policy_domain: Mapped[str] = mapped_column(String(253))
    policy_mx_host: Mapped[str | None] = mapped_column(String(253), nullable=True)
    policy_string: Mapped[str | None] = mapped_column(Text, nullable=True)

    total_successful_session_count: Mapped[int] = mapped_column(BigInteger, default=0)
    total_failure_session_count: Mapped[int] = mapped_column(BigInteger, default=0)

    report: Mapped[TlsReport] = relationship(back_populates="policies")
    failure_details: Mapped[list["TlsFailureDetail"]] = relationship(back_populates="policy", cascade="all, delete-orphan")


class TlsFailureDetail(Base):
    """One failure detail row within a TLS policy block."""
    __tablename__ = "tls_failure_details"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    policy_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tls_policies.id", ondelete="CASCADE"), index=True)
    domain_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("domains.id", ondelete="CASCADE"), index=True)

    result_type: Mapped[str] = mapped_column(String(60))   # e.g. starttls-not-supported, certificate-expired
    sending_mta_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    receiving_mx_hostname: Mapped[str | None] = mapped_column(String(253), nullable=True)
    receiving_mx_helo: Mapped[str | None] = mapped_column(String(253), nullable=True)
    receiving_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    failed_session_count: Mapped[int] = mapped_column(BigInteger, default=0)
    additional_information: Mapped[str | None] = mapped_column(Text, nullable=True)
    failure_reason_code: Mapped[str | None] = mapped_column(String(100), nullable=True)

    policy: Mapped[TlsPolicy] = relationship(back_populates="failure_details")


class TlsAggregate(Base):
    """Pre-computed TLS rollup per (domain, period, mx_host, result_type)."""
    __tablename__ = "tls_aggregates"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    domain_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("domains.id", ondelete="CASCADE"), index=True)

    period_begin: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    period_end: Mapped[datetime] = mapped_column(DateTime(timezone=True))

    mx_host: Mapped[str] = mapped_column(String(253))
    reporter_org: Mapped[str] = mapped_column(String(200))

    total_sessions: Mapped[int] = mapped_column(BigInteger, default=0)
    successful_sessions: Mapped[int] = mapped_column(BigInteger, default=0)
    failed_sessions: Mapped[int] = mapped_column(BigInteger, default=0)

    # Most common failure reason for this host in this period
    top_failure_reason: Mapped[str | None] = mapped_column(String(100), nullable=True)
    top_failure_count: Mapped[int] = mapped_column(BigInteger, default=0)

    computed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        Index("ix_tls_agg_domain_period", "domain_id", "period_begin", "period_end"),
    )
