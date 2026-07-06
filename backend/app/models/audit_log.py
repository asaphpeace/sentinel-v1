import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class AuditLogEntry(Base):
    """
    Append-only record of security/admin-relevant actions for a tenant.
    Written explicitly at the call sites that matter (auth, billing, domain
    lifecycle, MSP client management) rather than via a generic middleware
    hook — see audit_service.py for the rationale.
    """
    __tablename__ = "audit_log_entries"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)

    # Null when the action was performed by a background job, not a user
    # (e.g. the recommendation engine's scheduled evaluation never logs here —
    # it writes Alert rows — but a future system action could).
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    actor_email: Mapped[str | None] = mapped_column(String(320), nullable=True)  # denormalized — survives user deletion

    action: Mapped[str] = mapped_column(String(100), index=True)  # e.g. "domain.deleted", "team.role_changed"
    target_type: Mapped[str | None] = mapped_column(String(50), nullable=True)  # e.g. "domain", "user", "invite"
    target_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    target_label: Mapped[str | None] = mapped_column(String(300), nullable=True)  # human-readable, e.g. domain name

    before: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    after: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    tenant: Mapped["Tenant"] = relationship()  # type: ignore[name-defined]

    __table_args__ = (
        Index("ix_audit_log_tenant_created", "tenant_id", "created_at"),
    )
