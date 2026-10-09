"""Company-scoped employee profile and membership activation state.

Revision ID: 0014_company_user_management
Revises: 0013_booking_manager_scopes
"""

import sqlalchemy as sa
from alembic import op

revision = "0014_company_user_management"
down_revision = "0013_booking_manager_scopes"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "core_memberships",
        sa.Column("is_active", sa.Boolean(), server_default=sa.true(), nullable=False),
    )
    op.add_column("core_memberships", sa.Column("display_name", sa.String(200)))
    op.create_check_constraint(
        "ck_core_memberships_display_name",
        "core_memberships",
        "display_name IS NULL OR char_length(btrim(display_name)) > 0",
    )
    op.execute(
        "UPDATE core_memberships AS membership "
        "SET display_name = core_users.display_name "
        "FROM core_users WHERE core_users.id = membership.user_id"
    )


def downgrade():
    op.drop_constraint("ck_core_memberships_display_name", "core_memberships", type_="check")
    op.drop_column("core_memberships", "display_name")
    op.drop_column("core_memberships", "is_active")
