"""Persistent platform authority, bootstrap history, entitlements, and audit."""

from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Uuid,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from editingtab_core.identity.models import Base


class PlatformAdminGrant(Base):
    __tablename__ = "core_platform_admin_grants"
    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    user_id: Mapped[UUID] = mapped_column(
        ForeignKey("core_users.id", ondelete="RESTRICT"), unique=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class BootstrapState(Base):
    __tablename__ = "core_platform_bootstrap"
    __table_args__ = (CheckConstraint("id = 1", name="ck_platform_bootstrap_singleton"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class ModuleEntitlement(Base):
    __tablename__ = "core_module_entitlements"
    __table_args__ = (
        CheckConstraint(
            "module_code IN ('booking', 'pos', 'unified_inbox', 'chatbot')",
            name="ck_module_catalog",
        ),
        CheckConstraint("NOT enabled OR module_code = 'booking'", name="ck_module_supported"),
    )
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("core_organizations.id", ondelete="RESTRICT"), primary_key=True
    )
    module_code: Mapped[str] = mapped_column(String(32), primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class PlatformAudit(Base):
    __tablename__ = "core_platform_audit"
    __table_args__ = (
        CheckConstraint(
            "(actor_kind = 'operator_bootstrap' AND actor_id IS NULL) OR "
            "(actor_kind = 'authenticated_user' AND actor_id IS NOT NULL)",
            name="ck_platform_audit_actor",
        ),
        Index("ix_platform_audit_organization_time", "organization_id", "created_at"),
    )
    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    organization_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("core_organizations.id", ondelete="RESTRICT")
    )
    actor_id: Mapped[UUID | None] = mapped_column(ForeignKey("core_users.id", ondelete="RESTRICT"))
    actor_kind: Mapped[str] = mapped_column(String(32))
    action: Mapped[str] = mapped_column(String(40))
    target_id: Mapped[UUID] = mapped_column(Uuid)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    before: Mapped[dict] = mapped_column(JSONB)
    after: Mapped[dict] = mapped_column(JSONB)
