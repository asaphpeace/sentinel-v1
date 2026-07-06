import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, String, Text, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class DnsRecord(Base):
    """
    DNS record snapshot + change log.
    Each row is a change event: previous_value → current_value.
    When there is no change the row is not written (idempotent polling).
    """
    __tablename__ = "dns_records"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    domain_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("domains.id", ondelete="CASCADE"), index=True)

    record_type: Mapped[str] = mapped_column(String(20))   # DMARC | SPF | MX | DKIM | MTA-STS | TLS-RPT
    record_host: Mapped[str] = mapped_column(String(253))  # e.g. _dmarc.example.com
    previous_value: Mapped[str | None] = mapped_column(Text, nullable=True)
    current_value: Mapped[str | None] = mapped_column(Text, nullable=True)
    change_summary: Mapped[str | None] = mapped_column(String(500), nullable=True)

    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    # AI risk assessment (generated async after record is written)
    risk_severity:    Mapped[str | None] = mapped_column(String(20), nullable=True)   # info | warn | critical
    risk_explanation: Mapped[str | None] = mapped_column(Text, nullable=True)
    risk_action:      Mapped[str | None] = mapped_column(Text, nullable=True)
    risk_is_ai:       Mapped[bool] = mapped_column(Boolean, default=False)

    domain: Mapped["Domain"] = relationship(back_populates="dns_records")  # type: ignore[name-defined]

    __table_args__ = (
        Index("ix_dns_records_domain_type", "domain_id", "record_type"),
        Index("ix_dns_records_detected_at", "detected_at"),
    )
