"""Explicit delegated grant authority and granular role operations.

Revision ID: 0008_delegated_grant_authority
Revises: 0007_permission_registry
"""

import sqlalchemy as sa
from alembic import op

revision = "0008_delegated_grant_authority"
down_revision = "0007_permission_registry"
branch_labels = None
depends_on = None

ROLE_OPERATIONS = (
    "core.roles.create",
    "core.roles.update",
    "core.roles.archive",
    "core.roles.assign",
)


def upgrade():
    op.add_column(
        "core_role_permissions",
        sa.Column("can_grant", sa.Boolean(), server_default=sa.false(), nullable=False),
    )

    # A role that already carried the legacy management capability was an explicit
    # administrator role. Preserve its ability to administer its existing ceiling,
    # and map the coarse operation to the four granular operations. Other roles,
    # including the Booking provisioning role, remain non-delegating.
    operations = ", ".join(repr(code) for code in ROLE_OPERATIONS)
    op.execute(
        sa.text(
            "INSERT INTO core_role_permissions "
            "(organization_id, role_id, code, definition_organization_assignable, "
            "definition_lifecycle, can_grant) "
            "SELECT organization_id, role_id, operation, true, 'active', true "
            "FROM core_role_permissions "
            f"CROSS JOIN unnest(ARRAY[{operations}]) AS operation "
            "WHERE code = 'core.roles.manage' "
            "ON CONFLICT (organization_id, role_id, code) DO UPDATE SET can_grant = true"
        )
    )
    op.execute(
        "UPDATE core_role_permissions SET can_grant = true "
        "WHERE role_id IN ("
        "SELECT role_id FROM core_role_permissions WHERE code = 'core.roles.manage'"
        ")"
    )


def downgrade():
    # PostgreSQL 0007 has no lossless representation for delegation metadata.
    # Refuse a populated downgrade instead of silently restoring the unsafe
    # historical equivalence between use and grant authority.
    op.execute(
        "DO $$ BEGIN "
        "IF EXISTS (SELECT 1 FROM core_role_permissions) THEN "
        "RAISE EXCEPTION '0008 downgrade requires an empty core_role_permissions table'; "
        "END IF; END $$"
    )
    op.drop_column("core_role_permissions", "can_grant")
