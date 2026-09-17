"""Separate platform authority and organization module entitlements.

Revision ID: 0005_platform_onboarding
Revises: 0004_organization_roles
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0005_platform_onboarding"
down_revision = "0004_organization_roles"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "core_platform_admin_grants",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "user_id",
            sa.Uuid(),
            sa.ForeignKey("core_users.id", ondelete="RESTRICT"),
            nullable=False,
            unique=True,
        ),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
    )
    state = op.create_table(
        "core_platform_bootstrap",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.CheckConstraint("id = 1", name="ck_platform_bootstrap_singleton"),
    )
    # A lockable singleton, not an administrator grant. Never reset on revocation.
    op.bulk_insert(state, [{"id": 1}])
    op.create_table(
        "core_module_entitlements",
        sa.Column(
            "organization_id",
            sa.Uuid(),
            sa.ForeignKey("core_organizations.id", ondelete="RESTRICT"),
            primary_key=True,
        ),
        sa.Column("module_code", sa.String(32), primary_key=True),
        sa.Column("enabled", sa.Boolean(), server_default="false", nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.CheckConstraint(
            "module_code IN ('booking', 'pos', 'unified_inbox', 'chatbot')",
            name="ck_module_catalog",
        ),
        sa.CheckConstraint("NOT enabled OR module_code = 'booking'", name="ck_module_supported"),
    )
    op.create_table(
        "core_platform_audit",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "organization_id",
            sa.Uuid(),
            sa.ForeignKey("core_organizations.id", ondelete="RESTRICT"),
        ),
        sa.Column("actor_id", sa.Uuid(), sa.ForeignKey("core_users.id", ondelete="RESTRICT")),
        sa.Column("actor_kind", sa.String(32), nullable=False),
        sa.Column("action", sa.String(40), nullable=False),
        sa.Column("target_id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("before", postgresql.JSONB(), nullable=False),
        sa.Column("after", postgresql.JSONB(), nullable=False),
        sa.CheckConstraint(
            "(actor_kind = 'operator_bootstrap' AND actor_id IS NULL) OR "
            "(actor_kind = 'authenticated_user' AND actor_id IS NOT NULL)",
            name="ck_platform_audit_actor",
        ),
    )
    op.create_index(
        "ix_platform_audit_organization_time",
        "core_platform_audit",
        ["organization_id", "created_at"],
    )


def downgrade():
    op.drop_table("core_platform_audit")
    op.drop_table("core_module_entitlements")
    op.drop_table("core_platform_bootstrap")
    op.drop_table("core_platform_admin_grants")
