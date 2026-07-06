import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, String, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class Finding(Base):
    """Envelope shared across every Sentinel Command tier. check_id/detail/
    remediation_guidance cover Tier 0 (a Prowler check result) inline;
    later tiers get their own dedicated proof tables (ExposureProof,
    CredentialProof, ...) referenced by proof_ref instead of adding more
    nullable columns here, since proof shape differs enough per tier that
    a single shared table would mostly be empty per row."""

    __tablename__ = "findings"
    __table_args__ = (
        Index("ix_findings_engagement_status", "engagement_id", "status"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    engagement_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("engagements.id", ondelete="CASCADE"), index=True)

    # Nullable — a CloudPrivEscPath-backed finding may not map to a single
    # discrete CloudAsset the way a per-resource Prowler check does.
    asset_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("cloud_assets.id", ondelete="SET NULL"), nullable=True
    )

    tier: Mapped[str] = mapped_column(String(20))  # mirrors Engagement.tier
    severity: Mapped[str] = mapped_column(String(20))  # critical | high | medium | low
    title: Mapped[str] = mapped_column(String(500))

    status: Mapped[str] = mapped_column(String(20), default="open")
    # open | acknowledged | remediated | retest_closed

    check_id: Mapped[str | None] = mapped_column(String(200), nullable=True)  # e.g. a Prowler check id
    detail: Mapped[str | None] = mapped_column(String, nullable=True)
    remediation_guidance: Mapped[str | None] = mapped_column(String, nullable=True)
    proof_ref: Mapped[str | None] = mapped_column(String(200), nullable=True)

    discovered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    engagement: Mapped["Engagement"] = relationship()  # type: ignore[name-defined]
    asset: Mapped["CloudAsset | None"] = relationship()  # type: ignore[name-defined]
