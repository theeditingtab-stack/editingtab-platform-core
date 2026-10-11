"""Platform owner invitations and recent reauthentication.

Revision ID: 0015_platform_owner_lifecycle
Revises: 0014_company_user_management
"""

import sqlalchemy as sa
from alembic import op

revision = "0015_platform_owner_lifecycle"
down_revision = "0014_company_user_management"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "core_login_sessions",
        sa.Column("reauthenticated_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.execute(
        "UPDATE core_login_sessions SET reauthenticated_at = created_at "
        "WHERE reauthenticated_at IS NULL"
    )
    op.alter_column("core_login_sessions", "reauthenticated_at", nullable=False)
    op.add_column(
        "core_organization_invitations",
        sa.Column("kind", sa.String(32), server_default="employee", nullable=False),
    )
    op.add_column(
        "core_organization_invitations",
        sa.Column("intended_display_name", sa.String(200), nullable=True),
    )
    op.create_check_constraint(
        "ck_core_invitations_kind",
        "core_organization_invitations",
        "kind IN ('employee', 'organization_owner')",
    )


def downgrade():
    op.drop_constraint("ck_core_invitations_kind", "core_organization_invitations", type_="check")
    op.drop_column("core_organization_invitations", "intended_display_name")
    op.drop_column("core_organization_invitations", "kind")
    op.drop_column("core_login_sessions", "reauthenticated_at")
