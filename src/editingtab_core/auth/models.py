"""Credential, session, and rate-limit storage owned by Core authentication."""

from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, Integer, String, Uuid, func
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
