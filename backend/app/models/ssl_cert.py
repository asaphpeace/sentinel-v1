import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, Integer, String, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class SslCert(Base):
    """Latest SSL certificate probe result per (domain, host)."""
    __tablename__ = "ssl_certs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    domain_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("domains.id", ondelete="CASCADE"), index=True)

    host: Mapped[str] = mapped_column(String(253))       # e.g. mx1.example.com
    host_type: Mapped[str] = mapped_column(String(30))   # mx | mta-sts | web
    port: Mapped[int] = mapped_column(Integer, default=25)

    # Certificate fields
    subject_cn: Mapped[str | None] = mapped_column(String(253), nullable=True)
    issuer: Mapped[str | None] = mapped_column(String(400), nullable=True)
    san: Mapped[str | None] = mapped_column(String(1000), nullable=True)  # comma-separated SANs
    fingerprint_sha256: Mapped[str | None] = mapped_column(String(95), nullable=True)
    not_before: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    not_after: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    days_remaining: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # Probe result
    tls_version: Mapped[str | None] = mapped_column(String(10), nullable=True)  # TLSv1.2 | TLSv1.3
    starttls_supported: Mapped[bool | None] = mapped_column(nullable=True)
    hostname_valid: Mapped[bool | None] = mapped_column(nullable=True)
    probe_error: Mapped[str | None] = mapped_column(String(500), nullable=True)
    # dns | refused | timeout | tls | other — see cert_service._classify_probe_exception
    error_kind: Mapped[str | None] = mapped_column(String(20), nullable=True)

    # Status derived: ok | expiring_soon | critical | expired | error
    status: Mapped[str] = mapped_column(String(20), default="unknown")

    probed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    domain: Mapped["Domain"] = relationship(back_populates="ssl_certs")  # type: ignore[name-defined]

    __table_args__ = (
        Index("ix_ssl_certs_domain_host", "domain_id", "host"),
    )
