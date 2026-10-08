"""Membership-scoped Booking permission-manager designations and scopes.

Revision ID: 0013_booking_manager_scopes
Revises: 0012_booking_permission_mgr
"""

import sqlalchemy as sa
from alembic import op

revision = "0013_booking_manager_scopes"
down_revision = "0012_booking_permission_mgr"
branch_labels = None
depends_on = None


def _create_legacy_scope_table():
    op.create_table(
        "core_role_permission_management",
        sa.Column("organization_id", sa.Uuid(), primary_key=True),
        sa.Column("role_id", sa.Uuid(), primary_key=True),
        sa.Column("code", sa.String(64), primary_key=True),
        sa.Column(
            "definition_organization_assignable",
            sa.Boolean(),
            server_default=sa.true(),
            nullable=False,
        ),
        sa.Column(
            "definition_lifecycle",
            sa.String(16),
            server_default="active",
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["role_id", "organization_id"],
            ["core_roles.id", "core_roles.organization_id"],
            ondelete="RESTRICT",
            name="fk_core_role_permission_management_role",
        ),
        sa.ForeignKeyConstraint(
            ["code", "definition_organization_assignable", "definition_lifecycle"],
            [
                "core_permission_definitions.code",
                "core_permission_definitions.organization_assignable",
                "core_permission_definitions.lifecycle",
            ],
            ondelete="RESTRICT",
            onupdate="RESTRICT",
            name="fk_core_role_permission_management_assignable_definition",
        ),
        sa.CheckConstraint(
            "definition_organization_assignable",
            name="ck_core_role_permission_management_organization_assignable",
        ),
        sa.CheckConstraint(
            "definition_lifecycle = 'active'",
            name="ck_core_role_permission_management_active",
        ),
    )
    op.create_index(
        "ix_core_role_permission_management_code",
        "core_role_permission_management",
        ["organization_id", "code"],
    )


def upgrade():
    op.execute(
        "DO $$ BEGIN "
        "IF EXISTS (SELECT 1 FROM core_role_permission_management) THEN "
        "RAISE EXCEPTION '0013 cannot map existing role-level manager scopes safely'; "
        "END IF; END $$"
    )
    op.create_table(
        "core_booking_permission_manager_designations",
        sa.Column("organization_id", sa.Uuid(), primary_key=True),
        sa.Column("membership_id", sa.Uuid(), primary_key=True),
        sa.Column("role_id", sa.Uuid(), nullable=False),
        sa.Column(
            "designated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.ForeignKeyConstraint(
            ["membership_id", "organization_id"],
            ["core_memberships.id", "core_memberships.organization_id"],
            ondelete="RESTRICT",
            name="fk_core_booking_manager_designation_membership",
        ),
        sa.ForeignKeyConstraint(
            ["role_id", "organization_id"],
            ["core_roles.id", "core_roles.organization_id"],
            ondelete="RESTRICT",
            name="fk_core_booking_manager_designation_role",
        ),
    )
    op.create_index(
        "ix_core_booking_manager_designations_role",
        "core_booking_permission_manager_designations",
        ["organization_id", "role_id"],
    )
    op.create_table(
        "core_booking_permission_manager_scopes",
        sa.Column("organization_id", sa.Uuid(), primary_key=True),
        sa.Column("membership_id", sa.Uuid(), primary_key=True),
        sa.Column("code", sa.String(64), primary_key=True),
        sa.Column(
            "definition_organization_assignable",
            sa.Boolean(),
            server_default=sa.true(),
            nullable=False,
        ),
        sa.Column(
            "definition_lifecycle",
            sa.String(16),
            server_default="active",
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "membership_id"],
            [
                "core_booking_permission_manager_designations.organization_id",
                "core_booking_permission_manager_designations.membership_id",
            ],
            ondelete="RESTRICT",
            name="fk_core_booking_manager_scope_designation",
        ),
        sa.ForeignKeyConstraint(
            ["code", "definition_organization_assignable", "definition_lifecycle"],
            [
                "core_permission_definitions.code",
                "core_permission_definitions.organization_assignable",
                "core_permission_definitions.lifecycle",
            ],
            ondelete="RESTRICT",
            onupdate="RESTRICT",
            name="fk_core_booking_manager_scope_assignable_definition",
        ),
        sa.CheckConstraint(
            "definition_organization_assignable",
            name="ck_core_booking_manager_scope_organization_assignable",
        ),
        sa.CheckConstraint(
            "definition_lifecycle = 'active'", name="ck_core_booking_manager_scope_active"
        ),
        sa.CheckConstraint("code LIKE 'booking.%'", name="ck_core_booking_manager_scope_booking"),
    )
    op.create_index(
        "ix_core_booking_manager_scopes_code",
        "core_booking_permission_manager_scopes",
        ["organization_id", "code"],
    )
    op.drop_table("core_role_permission_management")


def downgrade():
    op.execute(
        "DO $$ BEGIN "
        "IF EXISTS (SELECT 1 FROM core_booking_permission_manager_designations) "
        "OR EXISTS (SELECT 1 FROM core_booking_permission_manager_scopes) THEN "
        "RAISE EXCEPTION '0013 downgrade requires empty manager designation and scope state'; "
        "END IF; END $$"
    )
    _create_legacy_scope_table()
    op.drop_table("core_booking_permission_manager_scopes")
    op.drop_table("core_booking_permission_manager_designations")
