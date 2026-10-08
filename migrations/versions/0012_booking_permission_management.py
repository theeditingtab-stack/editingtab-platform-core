"""Grant-only Booking permission-management foundation.

Revision ID: 0012_booking_permission_mgr
Revises: 0011_booking_admin_permissions
"""

import sqlalchemy as sa
from alembic import op

revision = "0012_booking_permission_mgr"
down_revision = "0011_booking_admin_permissions"
branch_labels = None
depends_on = None


def upgrade():
    op.drop_constraint("ck_core_roles_provisioning", "core_roles", type_="check")
    op.create_check_constraint(
        "ck_core_roles_provisioning",
        "core_roles",
        "provisioning_kind IS NULL OR provisioning_kind IN "
        "('booking_inventory', 'booking_permission_manager')",
    )
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


def downgrade():
    op.execute(
        "DO $$ BEGIN "
        "IF EXISTS (SELECT 1 FROM core_role_permission_management) "
        "OR EXISTS ("
        "SELECT 1 FROM core_roles "
        "WHERE provisioning_kind = 'booking_permission_manager'"
        ") THEN "
        "RAISE EXCEPTION "
        "'0012 downgrade requires empty permission-management and manager role state'; "
        "END IF; END $$"
    )
    op.drop_table("core_role_permission_management")
    op.drop_constraint("ck_core_roles_provisioning", "core_roles", type_="check")
    op.create_check_constraint(
        "ck_core_roles_provisioning",
        "core_roles",
        "provisioning_kind IS NULL OR provisioning_kind = 'booking_inventory'",
    )
