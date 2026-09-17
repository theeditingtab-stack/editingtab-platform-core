"""Organization-scoped roles, assignments, and transactional audit.

Revision ID: 0004_organization_roles
Revises: 0003_password_sessions
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0004_organization_roles"
down_revision = "0003_password_sessions"
branch_labels = None
depends_on = None


def upgrade():
    op.create_unique_constraint(
        "uq_core_memberships_id_organization", "core_memberships", ["id", "organization_id"]
    )
    op.create_table(
        "core_roles",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "organization_id",
            sa.Uuid(),
            sa.ForeignKey("core_organizations.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("normalized_name", sa.String(100), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("deleted_at", sa.DateTime(timezone=True)),
        sa.UniqueConstraint("id", "organization_id", name="uq_core_roles_id_organization"),
        sa.UniqueConstraint("organization_id", "normalized_name", name="uq_core_roles_name"),
        sa.CheckConstraint("name = btrim(name) AND name ~ '^[ -~]+$'", name="ck_core_roles_name"),
        sa.CheckConstraint(
            'normalized_name = lower(name COLLATE "C")', name="ck_core_roles_normalized_name"
        ),
    )
    op.create_table(
        "core_role_permissions",
        sa.Column("organization_id", sa.Uuid(), primary_key=True),
        sa.Column("role_id", sa.Uuid(), primary_key=True),
        sa.Column("code", sa.String(64), primary_key=True),
        sa.ForeignKeyConstraint(
            ["role_id", "organization_id"],
            ["core_roles.id", "core_roles.organization_id"],
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            "code IN ('core.organization.read', 'core.members.read', "
            "'core.roles.read', 'core.roles.manage')",
            name="ck_core_role_permissions_catalog",
        ),
    )
    op.create_table(
        "core_membership_roles",
        sa.Column("organization_id", sa.Uuid(), primary_key=True),
        sa.Column("membership_id", sa.Uuid(), primary_key=True),
        sa.Column("role_id", sa.Uuid(), primary_key=True),
        sa.ForeignKeyConstraint(
            ["membership_id", "organization_id"],
            ["core_memberships.id", "core_memberships.organization_id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["role_id", "organization_id"],
            ["core_roles.id", "core_roles.organization_id"],
            ondelete="RESTRICT",
        ),
    )
    op.create_index(
        "ix_core_membership_roles_role", "core_membership_roles", ["organization_id", "role_id"]
    )
    op.create_table(
        "core_role_audit",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "organization_id",
            sa.Uuid(),
            sa.ForeignKey("core_organizations.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "actor_id",
            sa.Uuid(),
            sa.ForeignKey("core_users.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("action", sa.String(40), nullable=False),
        sa.Column("target_id", sa.Uuid(), nullable=False),
        sa.Column("membership_id", sa.Uuid()),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("permissions_before", postgresql.JSONB(), nullable=False),
        sa.Column("permissions_after", postgresql.JSONB(), nullable=False),
    )
    op.create_index(
        "ix_core_role_audit_organization_time", "core_role_audit", ["organization_id", "created_at"]
    )


def downgrade():
    op.drop_table("core_role_audit")
    op.drop_table("core_membership_roles")
    op.drop_table("core_role_permissions")
    op.drop_table("core_roles")
    op.drop_constraint("uq_core_memberships_id_organization", "core_memberships", type_="unique")
