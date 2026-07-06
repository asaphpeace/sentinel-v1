import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class SubdomainDisposition(Base):
    """
    PAIN_POINT_RESOLUTION_PLAN.md Pain 6 — every discovered, mail-sending
    subdomain must have an explicit disposition before the parent domain
    can be considered enforcement-ready. Discovery alone (subdomain_
    discovery_service.py) is passive; this is what turns "found" into
    "decided," so a subdomain can't silently sit unacknowledged the way it
    did before — that's exactly the gap that bit people at enforce time.
    """
    __tablename__ = "subdomain_dispositions"
    __table_args__ = (
        UniqueConstraint("domain_id", "hostname", name="uq_subdomain_disposition_domain_hostname"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    domain_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("domains.id", ondelete="CASCADE"), index=True)
    hostname: Mapped[str] = mapped_column(String(253))

    # monitor | exclude | inherited_sp
    disposition: Mapped[str] = mapped_column(String(20))
    # Required when disposition == "exclude" — never silently dropped.
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
