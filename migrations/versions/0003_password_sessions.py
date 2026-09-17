"""Password credentials, revocable sessions, and shared login throttles.

Revision ID: 0003_password_sessions
Revises: 0002_core_identity
"""

import sqlalchemy as sa
from alembic import op

revision = "0003_password_sessions"
down_revision = "0002_core_identity"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "core_password_credentials",
        sa.Column(
            "user_id",
            sa.Uuid(),
            sa.ForeignKey("core_users.id", ondelete="RESTRICT"),
            primary_key=True,
        ),
        sa.Column("password_hash", sa.String(512), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
    )
    op.create_table(
        "core_login_sessions",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "user_id",
            sa.Uuid(),
            sa.ForeignKey("core_users.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("token_digest", sa.String(64), unique=True, nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.CheckConstraint("expires_at > created_at", name="ck_core_login_sessions_expiry"),
        sa.CheckConstraint("token_digest ~ '^[0-9a-f]{64}$'", name="ck_core_login_sessions_digest"),
    )
    op.create_index("ix_core_login_sessions_user_id", "core_login_sessions", ["user_id"])
    op.create_index("ix_core_login_sessions_expires_at", "core_login_sessions", ["expires_at"])
    op.create_table(
        "core_login_throttles",
        sa.Column("key", sa.String(66), primary_key=True),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("attempts > 0", name="ck_core_login_throttles_attempts"),
    )
    op.create_index("ix_core_login_throttles_expires_at", "core_login_throttles", ["expires_at"])


def downgrade():
    # Destructive reversal is never run against development by automated checks.
    op.drop_table("core_login_throttles")
    op.drop_table("core_login_sessions")
    op.drop_table("core_password_credentials")
