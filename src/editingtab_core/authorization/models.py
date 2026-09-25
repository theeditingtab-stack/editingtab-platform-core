"""Organization ownership is enforced with composite foreign keys."""

from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    String,
    UniqueConstraint,
    Uuid,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from editingtab_core.identity.models import Base


class PermissionDefinition(Base):
    __tablename__ = "core_permission_definitions"
    __table_args__ = (
        UniqueConstraint(
            "code",
            "organization_assignable",
            "lifecycle",
            name="uq_core_permission_definitions_assignment",
        ),
        CheckConstraint(
            "code ~ '^[a-z][a-z0-9_]*\\.[a-z][a-z0-9_]*\\.[a-z][a-z0-9_]*$'",
            name="ck_core_permission_definitions_code",
        ),
        CheckConstraint(
            "module ~ '^[a-z][a-z0-9_]*$' AND code LIKE module || '.%'",
            name="ck_core_permission_definitions_module",
        ),
        CheckConstraint(
            "description = btrim(description) AND length(description) > 0",
            name="ck_core_permission_definitions_description",
        ),
        CheckConstraint(
            "lifecycle IN ('active', 'deprecated')",
            name="ck_core_permission_definitions_lifecycle",
        ),
    )
    code: Mapped[str] = mapped_column(String(64), primary_key=True)
    module: Mapped[str] = mapped_column(String(32), index=True)
    description: Mapped[str] = mapped_column(String(255))
    organization_assignable: Mapped[bool] = mapped_column(Boolean)
    lifecycle: Mapped[str] = mapped_column(String(16))


class Role(Base):
    __tablename__ = "core_roles"
    __table_args__ = (
        UniqueConstraint("id", "organization_id", name="uq_core_roles_id_organization"),
        UniqueConstraint("organization_id", "provisioning_kind", name="uq_core_roles_provisioning"),
        CheckConstraint(
            "provisioning_kind IS NULL OR provisioning_kind = 'booking_inventory'",
            name="ck_core_roles_provisioning",
        ),
        UniqueConstraint("organization_id", "normalized_name", name="uq_core_roles_name"),
        CheckConstraint("name = btrim(name) AND name ~ '^[ -~]+$'", name="ck_core_roles_name"),
        CheckConstraint(
            'normalized_name = lower(name COLLATE "C")', name="ck_core_roles_normalized_name"
        ),
    )
    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("core_organizations.id", ondelete="RESTRICT")
    )
    provisioning_kind: Mapped[str | None] = mapped_column(String(32))
    name: Mapped[str] = mapped_column(String(100))
    normalized_name: Mapped[str] = mapped_column(String(100))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class RolePermission(Base):
    __tablename__ = "core_role_permissions"
    __table_args__ = (
        ForeignKeyConstraint(
            ["role_id", "organization_id"],
            ["core_roles.id", "core_roles.organization_id"],
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["code", "definition_organization_assignable", "definition_lifecycle"],
            [
                "core_permission_definitions.code",
                "core_permission_definitions.organization_assignable",
                "core_permission_definitions.lifecycle",
            ],
            ondelete="RESTRICT",
            onupdate="RESTRICT",
            name="fk_core_role_permissions_assignable_definition",
        ),
        CheckConstraint(
            "definition_organization_assignable",
            name="ck_core_role_permissions_organization_assignable",
        ),
        CheckConstraint(
            "definition_lifecycle = 'active'",
            name="ck_core_role_permissions_active",
        ),
    )
    organization_id: Mapped[UUID] = mapped_column(Uuid, primary_key=True)
    role_id: Mapped[UUID] = mapped_column(Uuid, primary_key=True)
    code: Mapped[str] = mapped_column(String(64), primary_key=True)
    definition_organization_assignable: Mapped[bool] = mapped_column(
        Boolean, default=True, server_default="true"
    )
    definition_lifecycle: Mapped[str] = mapped_column(
        String(16), default="active", server_default="active"
    )


class MembershipRole(Base):
    __tablename__ = "core_membership_roles"
    __table_args__ = (
        ForeignKeyConstraint(
            ["membership_id", "organization_id"],
            ["core_memberships.id", "core_memberships.organization_id"],
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["role_id", "organization_id"],
            ["core_roles.id", "core_roles.organization_id"],
            ondelete="RESTRICT",
        ),
        Index("ix_core_membership_roles_role", "organization_id", "role_id"),
    )
    organization_id: Mapped[UUID] = mapped_column(Uuid, primary_key=True)
    membership_id: Mapped[UUID] = mapped_column(Uuid, primary_key=True)
    role_id: Mapped[UUID] = mapped_column(Uuid, primary_key=True)


class RoleAudit(Base):
    __tablename__ = "core_role_audit"
    __table_args__ = (
        Index("ix_core_role_audit_organization_time", "organization_id", "created_at"),
    )
    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("core_organizations.id", ondelete="RESTRICT")
    )
    actor_id: Mapped[UUID] = mapped_column(ForeignKey("core_users.id", ondelete="RESTRICT"))
    action: Mapped[str] = mapped_column(String(40))
    target_id: Mapped[UUID] = mapped_column(Uuid)
    membership_id: Mapped[UUID | None] = mapped_column(Uuid)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    permissions_before: Mapped[list[str]] = mapped_column(JSONB)
    permissions_after: Mapped[list[str]] = mapped_column(JSONB)
