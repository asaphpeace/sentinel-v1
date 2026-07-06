import uuid
from datetime import datetime

from sqlalchemy import JSON, DateTime, ForeignKey, String, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class ServiceAccount(Base):
    """A machine identity distinct from a User - for other products in the
    portfolio (Workspace OS today) reading Sentinel data without a human
    login. Scoped to one tenant, narrow read-only scopes, revocable without
    a blacklist table (checked per request, fine at this volume - see
    get_service_account in app/services/service_auth.py)."""

    __tablename__ = "service_accounts"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    service_name: Mapped[str] = mapped_column(String(100))  # e.g. "workspace-os"
    key_hash: Mapped[str] = mapped_column(String)
    scopes: Mapped[list[str]] = mapped_column(JSON, default=list)  # e.g. ["overview:read", "alerts:read"]
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
