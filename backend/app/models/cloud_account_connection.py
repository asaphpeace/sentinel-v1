import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, String, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class CloudAccountConnection(Base):
    """Read-only access into a customer's cloud account (AWS/Azure/GCP) for
    Sentinel Command's Tier 0 cloud posture scanning. Distinct consent model
    from Domain/Engagement scope — the customer grants account access
    directly rather than authorizing scans against a CIDR/domain.

    AWS uses cross-account role assumption (role_arn + external_id) so no
    customer credential is ever stored here. Azure/GCP fall back to
    encrypted_credentials only when workload-identity federation isn't set
    up — encrypted at rest, same `cryptography` usage already established
    elsewhere in this codebase (cert_service.py)."""

    __tablename__ = "cloud_account_connections"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)

    provider: Mapped[str] = mapped_column(String(20))  # aws | azure | gcp

    # AWS — cross-account role assumption, no stored secret
    role_arn: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    external_id: Mapped[str | None] = mapped_column(String(128), nullable=True)

    # Azure — service principal; tenant/client id are not secret, only the
    # client secret needs encryption (nullable once federation is used)
    azure_tenant_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    azure_client_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    azure_subscription_id: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # GCP — service account; project id / SA email are not secret
    gcp_project_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    gcp_service_account_email: Mapped[str | None] = mapped_column(String(320), nullable=True)

    # Fernet-encrypted blob for whichever secret the provider needs (Azure
    # client secret, GCP key file) when federation isn't in use. Null for
    # AWS (never needed) and for federated Azure/GCP connections.
    encrypted_credentials: Mapped[str | None] = mapped_column(String, nullable=True)
    uses_federation: Mapped[bool] = mapped_column(Boolean, default=False)

    status: Mapped[str] = mapped_column(String(20), default="pending_verification")
    # pending_verification | connected | revoked | error

    connected_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    connected_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_scanned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    tenant: Mapped["Tenant"] = relationship()  # type: ignore[name-defined]
