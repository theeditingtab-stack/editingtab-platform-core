"""Credential, session, and rate-limit storage owned by Core authentication."""

from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    String,
    UniqueConstraint,
    Uuid,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from editingtab_core.identity.models import Base


class PasswordCredential(Base):
    __tablename__ = "core_password_credentials"
    user_id: Mapped[UUID] = mapped_column(
        ForeignKey("core_users.id", ondelete="RESTRICT"), primary_key=True
    )
    password_hash: Mapped[str] = mapped_column(String(512))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class LoginSession(Base):
    __tablename__ = "core_login_sessions"
    __table_args__ = (
        CheckConstraint("expires_at > created_at", name="ck_core_login_sessions_expiry"),
        CheckConstraint("token_digest ~ '^[0-9a-f]{64}$'", name="ck_core_login_sessions_digest"),
        Index("ix_core_login_sessions_user_id", "user_id"),
        Index("ix_core_login_sessions_expires_at", "expires_at"),
    )
    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    user_id: Mapped[UUID] = mapped_column(ForeignKey("core_users.id", ondelete="RESTRICT"))
    token_digest: Mapped[str] = mapped_column(String(64), unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class LoginThrottle(Base):
    __tablename__ = "core_login_throttles"
    __table_args__ = (
        CheckConstraint("attempts > 0", name="ck_core_login_throttles_attempts"),
        Index("ix_core_login_throttles_expires_at", "expires_at"),
    )
    key: Mapped[str] = mapped_column(String(66), primary_key=True)
    attempts: Mapped[int] = mapped_column(Integer)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class OrganizationInvitation(Base):
    __tablename__ = "core_organization_invitations"
    __table_args__ = (
        UniqueConstraint("id", "organization_id", name="uq_core_invitations_id_organization"),
        CheckConstraint("expires_at > created_at", name="ck_core_invitations_expiry"),
        CheckConstraint("token_digest ~ '^[0-9a-f]{64}$'", name="ck_core_invitations_digest"),
        Index("ix_core_invitations_organization", "organization_id", "created_at"),
        Index("ix_core_invitations_expiry", "expires_at"),
    )
    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("core_organizations.id", ondelete="RESTRICT")
    )
    normalized_email: Mapped[str] = mapped_column(String(254))
    inviter_id: Mapped[UUID] = mapped_column(ForeignKey("core_users.id", ondelete="RESTRICT"))
    token_digest: Mapped[str] = mapped_column(String(64), unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    accepted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class InvitationRole(Base):
    __tablename__ = "core_invitation_roles"
    __table_args__ = (
        ForeignKeyConstraint(
            ["invitation_id", "organization_id"],
            ["core_organization_invitations.id", "core_organization_invitations.organization_id"],
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["role_id", "organization_id"],
            ["core_roles.id", "core_roles.organization_id"],
            ondelete="RESTRICT",
        ),
    )
    organization_id: Mapped[UUID] = mapped_column(Uuid, primary_key=True)
    invitation_id: Mapped[UUID] = mapped_column(Uuid, primary_key=True)
    role_id: Mapped[UUID] = mapped_column(Uuid, primary_key=True)


class PasswordResetToken(Base):
    __tablename__ = "core_password_reset_tokens"
    __table_args__ = (
        CheckConstraint("expires_at > created_at", name="ck_core_password_resets_expiry"),
        CheckConstraint("token_digest ~ '^[0-9a-f]{64}$'", name="ck_core_password_resets_digest"),
        Index("ix_core_password_resets_user", "user_id", "created_at"),
        Index("ix_core_password_resets_expiry", "expires_at"),
    )
    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    user_id: Mapped[UUID] = mapped_column(ForeignKey("core_users.id", ondelete="RESTRICT"))
    token_digest: Mapped[str] = mapped_column(String(64), unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class SecurityAudit(Base):
    __tablename__ = "core_security_audit"
    __table_args__ = (Index("ix_core_security_audit_time", "created_at"),)
    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    organization_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("core_organizations.id", ondelete="RESTRICT")
    )
    actor_id: Mapped[UUID | None] = mapped_column(ForeignKey("core_users.id", ondelete="RESTRICT"))
    action: Mapped[str] = mapped_column(String(40))
    target_id: Mapped[UUID] = mapped_column(Uuid)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    details: Mapped[dict[str, object]] = mapped_column(JSONB)
