import uuid
from datetime import date, datetime

from sqlalchemy import Boolean, Date, DateTime, Float, ForeignKey, Integer, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class SentinelSnapshot(Base):
    """Weekly portfolio health score per tenant. One row per tenant per week."""
    __tablename__ = "sentinel_snapshots"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    week: Mapped[date] = mapped_column(Date, index=True)   # Monday of the ISO week

    score: Mapped[int] = mapped_column(Integer)
    pillar_dmarc: Mapped[float] = mapped_column(Float)
    pillar_tls: Mapped[float] = mapped_column(Float)
    pillar_certs: Mapped[float] = mapped_column(Float)

    # AI narrative (generated once per week, stored here)
    narrative_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    narrative_threats: Mapped[str | None] = mapped_column(Text, nullable=True)
    narrative_actions: Mapped[str | None] = mapped_column(Text, nullable=True)
    narrative_generated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    narrative_is_ai: Mapped[bool] = mapped_column(Boolean, default=False)
