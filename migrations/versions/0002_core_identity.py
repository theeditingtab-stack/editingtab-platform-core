"""Core organizations, users and memberships; no authentication or roles."""

import sqlalchemy as sa
from alembic import op

revision = "0002_core_identity"
down_revision = "0001_foundation"
branch_labels = None
depends_on = None


def _record_columns():
    return [
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    ]


def upgrade() -> None:
    op.create_table(
        "core_organizations",
        *_record_columns(),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("slug", sa.String(63), nullable=False),
        sa.UniqueConstraint("slug", name="uq_core_organizations_slug"),
        sa.CheckConstraint("char_length(btrim(name)) > 0", name="ck_core_organizations_name"),
        sa.CheckConstraint("slug ~ '^[a-z0-9]+(-[a-z0-9]+)*$'", name="ck_core_organizations_slug"),
    )
    op.create_table(
        "core_users",
        *_record_columns(),
        sa.Column("email", sa.String(254), nullable=False),
        sa.Column("normalized_email", sa.String(254), nullable=False),
        sa.Column("display_name", sa.String(200), nullable=False),
        sa.Column("is_active", sa.Boolean(), server_default=sa.true(), nullable=False),
        sa.UniqueConstraint("normalized_email", name="uq_core_users_normalized_email"),
        sa.CheckConstraint(
            """normalized_email = lower(email COLLATE "C")""",
            name="ck_core_users_normalized_email",
        ),
        sa.CheckConstraint(
            "email ~ '^[!-~]+@[!-~]+$' AND "
            "char_length(email) - char_length(replace(email, '@', '')) = 1",
            name="ck_core_users_email",
        ),
        sa.CheckConstraint(
            "char_length(btrim(display_name)) > 0", name="ck_core_users_display_name"
        ),
    )
    op.create_table(
        "core_memberships",
        *_record_columns(),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.ForeignKeyConstraint(
            ["organization_id"], ["core_organizations.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(["user_id"], ["core_users.id"], ondelete="RESTRICT"),
        sa.UniqueConstraint(
            "organization_id", "user_id", name="uq_core_memberships_organization_user"
        ),
    )
    op.create_index("ix_core_memberships_user_id", "core_memberships", ["user_id"])


def downgrade() -> None:
    # Destructive operation: never run against development without separate authorization.
    op.drop_index("ix_core_memberships_user_id", table_name="core_memberships")
    op.drop_table("core_memberships")
    op.drop_table("core_users")
    op.drop_table("core_organizations")
