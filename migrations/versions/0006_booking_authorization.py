"""Booking permission catalog and dedicated provisioning role identity. No grants.

Revision ID: 0006_booking_authorization
Revises: 0005_platform_onboarding
"""

import sqlalchemy as sa
from alembic import op

revision = "0006_booking_authorization"
down_revision = "0005_platform_onboarding"
branch_labels = None
depends_on = None
CORE_CODES = "'core.organization.read', 'core.members.read', 'core.roles.read', 'core.roles.manage'"


def upgrade():
    op.drop_constraint("ck_core_role_permissions_catalog", "core_role_permissions", type_="check")
    op.create_check_constraint(
        "ck_core_role_permissions_catalog",
        "core_role_permissions",
        "code IN (" + CORE_CODES + ", 'booking.inventory.read', 'booking.inventory.manage')",
    )
    op.add_column("core_roles", sa.Column("provisioning_kind", sa.String(32), nullable=True))
    op.create_unique_constraint(
        "uq_core_roles_provisioning", "core_roles", ["organization_id", "provisioning_kind"]
    )
    op.create_check_constraint(
        "ck_core_roles_provisioning",
        "core_roles",
        "provisioning_kind IS NULL OR provisioning_kind = 'booking_inventory'",
    )


def downgrade():
    # Fails rather than silently deleting Booking permission records when present.
    op.drop_constraint("ck_core_role_permissions_catalog", "core_role_permissions", type_="check")
    op.create_check_constraint(
        "ck_core_role_permissions_catalog", "core_role_permissions", "code IN (" + CORE_CODES + ")"
    )
    op.drop_constraint("uq_core_roles_provisioning", "core_roles", type_="unique")
    op.drop_constraint("ck_core_roles_provisioning", "core_roles", type_="check")
    op.drop_column("core_roles", "provisioning_kind")
