"""Core owns these tables; other modules must use its service boundary."""

from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    String,
    UniqueConstraint,
    Uuid,
    func,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class _Record:
    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Organization(_Record, Base):
    __tablename__ = "core_organizations"
    __table_args__ = (
        UniqueConstraint("slug", name="uq_core_organizations_slug"),
        CheckConstraint("char_length(btrim(name)) > 0", name="ck_core_organizations_name"),
        CheckConstraint("slug ~ '^[a-z0-9]+(-[a-z0-9]+)*$'", name="ck_core_organizations_slug"),
    )

    name: Mapped[str] = mapped_column(String(200))
    slug: Mapped[str] = mapped_column(String(63))


class User(_Record, Base):
    __tablename__ = "core_users"
    __table_args__ = (
        UniqueConstraint("normalized_email", name="uq_core_users_normalized_email"),
        CheckConstraint(
            """normalized_email = lower(email COLLATE "C")""",
            name="ck_core_users_normalized_email",
        ),
        CheckConstraint(
            "email ~ '^[!-~]+@[!-~]+$' AND "
            "char_length(email) - char_length(replace(email, '@', '')) = 1",
            name="ck_core_users_email",
        ),
        CheckConstraint("char_length(btrim(display_name)) > 0", name="ck_core_users_display_name"),
    )

    email: Mapped[str] = mapped_column(String(254))
    normalized_email: Mapped[str] = mapped_column(String(254))
    display_name: Mapped[str] = mapped_column(String(200))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true")


class Membership(_Record, Base):
    __tablename__ = "core_memberships"
    __table_args__ = (
        UniqueConstraint(
            "organization_id", "user_id", name="uq_core_memberships_organization_user"
        ),
        Index("ix_core_memberships_user_id", "user_id"),
        UniqueConstraint("id", "organization_id", name="uq_core_memberships_id_organization"),
    )

    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("core_organizations.id", ondelete="RESTRICT")
    )
    user_id: Mapped[UUID] = mapped_column(ForeignKey("core_users.id", ondelete="RESTRICT"))
