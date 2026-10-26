"""Organization-scoped branding, logo metadata, and immutable audit events."""

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


class OrganizationBrandAsset(Base):
    __tablename__ = "core_organization_brand_assets"
    __table_args__ = (
        UniqueConstraint("organization_id", "id", name="uq_core_brand_assets_organization_id"),
        CheckConstraint("byte_size > 0", name="ck_core_brand_assets_byte_size"),
        CheckConstraint("width > 0 AND height > 0", name="ck_core_brand_assets_dimensions"),
        CheckConstraint(
            "media_type IN ('image/png', 'image/jpeg', 'image/webp')",
            name="ck_core_brand_assets_media_type",
        ),
        CheckConstraint(
            "content_sha256 ~ '^[0-9a-f]{64}$'", name="ck_core_brand_assets_content_sha256"
        ),
        Index("ix_core_brand_assets_organization", "organization_id", "created_at"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("core_organizations.id", ondelete="RESTRICT"), nullable=False
    )
    storage_key: Mapped[str] = mapped_column(String(200), unique=True, nullable=False)
    media_type: Mapped[str] = mapped_column(String(50), nullable=False)
    byte_size: Mapped[int] = mapped_column(Integer, nullable=False)
    width: Mapped[int] = mapped_column(Integer, nullable=False)
    height: Mapped[int] = mapped_column(Integer, nullable=False)
    content_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    created_by: Mapped[UUID] = mapped_column(
        ForeignKey("core_users.id", ondelete="RESTRICT"), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    retired_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class OrganizationBranding(Base):
    __tablename__ = "core_organization_branding"
    __table_args__ = (
        ForeignKeyConstraint(
            ["organization_id", "logo_asset_id"],
            [
                "core_organization_brand_assets.organization_id",
                "core_organization_brand_assets.id",
            ],
            ondelete="RESTRICT",
            name="fk_core_branding_organization_logo",
        ),
        CheckConstraint("primary_color ~ '^#[0-9A-F]{6}$'", name="ck_core_branding_primary_color"),
        CheckConstraint("accent_color ~ '^#[0-9A-F]{6}$'", name="ck_core_branding_accent_color"),
        CheckConstraint("version > 0", name="ck_core_branding_version"),
    )

    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("core_organizations.id", ondelete="RESTRICT"), primary_key=True
    )
    primary_color: Mapped[str] = mapped_column(
        String(7), nullable=False, default="#183C2B", server_default="#183C2B"
    )
    accent_color: Mapped[str] = mapped_column(
        String(7), nullable=False, default="#D4A853", server_default="#D4A853"
    )
    logo_asset_id: Mapped[UUID | None] = mapped_column(Uuid)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1, server_default="1")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )


class OrganizationBrandingAudit(Base):
    __tablename__ = "core_organization_branding_audit"
    __table_args__ = (
        Index("ix_core_branding_audit_organization_time", "organization_id", "created_at"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("core_organizations.id", ondelete="RESTRICT"), nullable=False
    )
    actor_id: Mapped[UUID] = mapped_column(
        ForeignKey("core_users.id", ondelete="RESTRICT"), nullable=False
    )
    action: Mapped[str] = mapped_column(String(40), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    before: Mapped[dict] = mapped_column(JSONB, nullable=False)
    after: Mapped[dict] = mapped_column(JSONB, nullable=False)
