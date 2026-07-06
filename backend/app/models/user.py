import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import UUID, ARRAY
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class Tenant(Base):
    __tablename__ = "tenants"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(200))
    plan: Mapped[str] = mapped_column(String(50), default="free")  # free | starter | pro | msp | enterprise
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    # MSP hierarchy — client tenants point to their MSP parent
    parent_tenant_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("tenants.id", ondelete="SET NULL"), nullable=True, index=True
    )

    # Billing
    billing_email: Mapped[str | None] = mapped_column(String(320), nullable=True)
    stripe_customer_id: Mapped[str | None] = mapped_column(String(200), nullable=True)
    stripe_subscription_id: Mapped[str | None] = mapped_column(String(200), nullable=True)

    # MSP white-label
    brand_name: Mapped[str | None] = mapped_column(String(200), nullable=True)
    brand_logo_url: Mapped[str | None] = mapped_column(String(500), nullable=True)

    # Scheduled PDF report delivery — gated by plan_limits.scheduled_reports.
    # "off" by default: nobody gets emailed a report until they opt in.
    report_schedule: Mapped[str] = mapped_column(String(20), default="off")  # off | weekly | monthly
    last_report_sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    users: Mapped[list["User"]] = relationship(back_populates="tenant")
    domains: Mapped[list["Domain"]] = relationship(back_populates="tenant")  # type: ignore[name-defined]
    clients: Mapped[list["Tenant"]] = relationship(
        "Tenant", foreign_keys="Tenant.parent_tenant_id", back_populates="parent"
    )
    parent: Mapped["Tenant | None"] = relationship(
        "Tenant", foreign_keys="[Tenant.parent_tenant_id]", back_populates="clients", remote_side="Tenant.id"
    )


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"))
    email: Mapped[str] = mapped_column(String(320), index=True)
    hashed_password: Mapped[str | None] = mapped_column(String(200), nullable=True)
    full_name: Mapped[str] = mapped_column(String(200), default="")
    role: Mapped[str] = mapped_column(String(50), default="admin")  # admin | viewer

    # password | sso — controls which uniqueness rule applies to `email`.
    # Password accounts must be globally unique (one signup per email across
    # all tenants). SSO accounts are only unique per-tenant, since the same
    # corporate email can legitimately be an SSO identity in multiple
    # customer tenants (e.g. an MSP contractor) — see uq_users_tenant_email
    # and ix_users_email_password_unique in the schema.
    auth_method: Mapped[str] = mapped_column(String(20), default="password")

    totp_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    totp_secret: Mapped[str | None] = mapped_column(String(64), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)

    # Defaults True at the DB level (server_default) so every existing row and
    # every other creation path (invite accept, MSP direct-create — both
    # already prove email ownership via the invite link or admin trust) comes
    # in verified. register() is the one path that explicitly overrides this
    # to False, since that's the only signup path where the email is unproven.
    email_verified: Mapped[bool] = mapped_column(Boolean, default=True)

    # Bumped on password change, password reset, and 2FA enable/disable.
    # Embedded in every issued JWT as "tv" and checked in get_current_user —
    # bumping this instantly invalidates every previously-issued token for
    # this user without needing a server-side token blacklist. Tokens are
    # otherwise stateless, so this is the cheapest way to get "log out
    # everywhere" semantics on the events that actually call for it.
    token_version: Mapped[int] = mapped_column(Integer, default=0)

    # Null means never accepted — only register() and accept_invite() set
    # these, since those are the two paths where an individual is creating
    # their own account and agreeing to terms on their own behalf. MSP
    # direct-create (invite_to_client with send_invite=False) creates a
    # password for someone else without them seeing a form at all, so it
    # can't capture consent — a known gap, not something this field papers over.
    terms_accepted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    terms_version: Mapped[str | None] = mapped_column(String(20), nullable=True)

    # PAIN_POINT_RESOLUTION_PLAN.md Pain 2 — which Concept Card ids this
    # user has dismissed, so cards fade out for someone who's clearly
    # learned the term without ever fully disappearing (still reachable via
    # the glossary). Plain ARRAY, not a join table — this is small,
    # per-user, append-only-ish data with no need for its own table.
    concepts_seen: Mapped[list[str]] = mapped_column(ARRAY(String), default=list, server_default="{}")

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    tenant: Mapped[Tenant] = relationship(back_populates="users")

    __table_args__ = (
        UniqueConstraint("tenant_id", "email", name="uq_users_tenant_email"),
    )
