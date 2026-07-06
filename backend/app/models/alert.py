import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, String, Text, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    domain_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("domains.id", ondelete="CASCADE"), nullable=True, index=True)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)

    # severity: info | warn | critical
    severity: Mapped[str] = mapped_column(String(20), default="info")
    category: Mapped[str] = mapped_column(String(50))   # cert | dmarc | tls | dns | spoof
    title: Mapped[str] = mapped_column(String(300))
    body: Mapped[str] = mapped_column(Text)               # what this means
    action: Mapped[str | None] = mapped_column(Text, nullable=True)  # what to do — kept separate, not mixed into body
    narration: Mapped[str | None] = mapped_column(Text, nullable=True)  # AI-generated plain-English

    is_read: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    domain: Mapped["Domain"] = relationship(back_populates="alerts")  # type: ignore[name-defined]

    __table_args__ = (
        Index("ix_alerts_tenant_unread", "tenant_id", "is_read"),
    )
