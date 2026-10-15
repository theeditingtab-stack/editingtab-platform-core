"""Persist the selected initial platform administrator.

Revision ID: 0016_first_time_web_setup
Revises: 0015_platform_owner_lifecycle
"""

import sqlalchemy as sa
from alembic import op

revision = "0016_first_time_web_setup"
down_revision = "0015_platform_owner_lifecycle"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "core_platform_bootstrap",
        sa.Column("administrator_user_id", sa.Uuid(), nullable=True),
    )
    op.create_foreign_key(
        "fk_platform_bootstrap_administrator_user",
        "core_platform_bootstrap",
        "core_users",
        ["administrator_user_id"],
        ["id"],
        ondelete="RESTRICT",
    )
    # Existing completed installations have one historical initial grant. Preserve
    # that identity so recovery no longer depends on the legacy fixed email.
    op.execute(
        "UPDATE core_platform_bootstrap AS bootstrap "
        "SET administrator_user_id = grants.user_id "
        "FROM ("
        "  SELECT min(user_id::text)::uuid AS user_id "
        "  FROM core_platform_admin_grants "
        "  HAVING count(*) = 1"
        ") AS grants "
        "WHERE bootstrap.id = 1 AND bootstrap.completed_at IS NOT NULL"
    )


def downgrade():
    op.drop_constraint(
        "fk_platform_bootstrap_administrator_user",
        "core_platform_bootstrap",
        type_="foreignkey",
    )
    op.drop_column("core_platform_bootstrap", "administrator_user_id")
