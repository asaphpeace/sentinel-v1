import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class SenderRecommendation(Base):
    __tablename__ = "sender_recommendations"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    domain_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("domains.id", ondelete="CASCADE"), index=True)

    source_org: Mapped[str] = mapped_column(String(500))
    source_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    classification: Mapped[str] = mapped_column(String(50))   # known_esp | unknown | suspicious | declared_platform | tls_issue
    # Set only for classification == "declared_platform" — the
    # app.knowledge.platforms key, so the setup card can look the profile up
    # directly instead of re-matching source_org by name. NULL for
    # passively-detected sources (those still match by name, as before).
    platform_key: Mapped[str | None] = mapped_column(String(50), nullable=True)
    recommendation: Mapped[str | None] = mapped_column(Text, nullable=True)
    dns_fix: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_ai: Mapped[bool] = mapped_column(Boolean, default=False)
    dismissed: Mapped[bool] = mapped_column(Boolean, default=False)
    # Part 3 #15: a third state between act-now and dismiss-forever — "not now,
    # remind me later" without losing the recommendation. NULL means not snoozed.
    snoozed_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
