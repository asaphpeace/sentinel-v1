import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, func
from sqlalchemy.dialects.postgresql import ARRAY, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class CloudPrivEscPath(Base):
    """One discovered IAM privilege-escalation chain from Cloudsplaining/
    PMapper analysis — the cloud-account counterpart to Tier 4's network
    reachability edges. Append-only per scan: a path that disappears on
    re-scan (remediated) is left in place and a corresponding Finding is
    marked retest_closed, rather than deleting the historical record —
    mirrors how DmarcRecord/TlsReport keep history instead of overwriting."""

    __tablename__ = "cloud_priv_esc_paths"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    engagement_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("engagements.id", ondelete="CASCADE"), index=True)
    cloud_account_connection_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("cloud_account_connections.id", ondelete="CASCADE"), index=True
    )

    source_principal_arn: Mapped[str] = mapped_column(String(2048))
    target_principal_arn: Mapped[str] = mapped_column(String(2048))  # often the account's admin role/user
    technique_chain: Mapped[list[str]] = mapped_column(ARRAY(String), default=list)
    # e.g. ["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"]

    severity: Mapped[str] = mapped_column(String(20))  # critical | high | medium | low
    discovered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    engagement: Mapped["Engagement"] = relationship()  # type: ignore[name-defined]
    connection: Mapped["CloudAccountConnection"] = relationship()  # type: ignore[name-defined]
