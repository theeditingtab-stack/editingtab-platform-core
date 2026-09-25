"""Employee invitations, password recovery, session security audit.

Revision ID: 0010_account_onboarding
Revises: 0009_employee_lifecycle
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0010_account_onboarding"
down_revision = "0009_employee_lifecycle"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "core_organization_invitations",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "organization_id",
            sa.Uuid(),
            sa.ForeignKey("core_organizations.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("normalized_email", sa.String(254), nullable=False),
        sa.Column(
            "inviter_id",
            sa.Uuid(),
            sa.ForeignKey("core_users.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("token_digest", sa.String(64), unique=True, nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("accepted_at", sa.DateTime(timezone=True)),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.UniqueConstraint("id", "organization_id", name="uq_core_invitations_id_organization"),
        sa.CheckConstraint("expires_at > created_at", name="ck_core_invitations_expiry"),
        sa.CheckConstraint("token_digest ~ '^[0-9a-f]{64}$'", name="ck_core_invitations_digest"),
    )
    op.create_index(
        "ix_core_invitations_organization",
        "core_organization_invitations",
        ["organization_id", "created_at"],
    )
    op.create_index("ix_core_invitations_expiry", "core_organization_invitations", ["expires_at"])
    op.create_index(
        "uq_core_invitations_pending_email",
        "core_organization_invitations",
        ["organization_id", "normalized_email"],
        unique=True,
        postgresql_where=sa.text("accepted_at IS NULL AND revoked_at IS NULL"),
    )
    op.create_table(
        "core_invitation_roles",
        sa.Column("organization_id", sa.Uuid(), primary_key=True),
        sa.Column("invitation_id", sa.Uuid(), primary_key=True),
        sa.Column("role_id", sa.Uuid(), primary_key=True),
        sa.ForeignKeyConstraint(
            ["invitation_id", "organization_id"],
            ["core_organization_invitations.id", "core_organization_invitations.organization_id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["role_id", "organization_id"],
            ["core_roles.id", "core_roles.organization_id"],
            ondelete="RESTRICT",
        ),
    )
    op.create_table(
        "core_password_reset_tokens",
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
        sa.Column("consumed_at", sa.DateTime(timezone=True)),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.CheckConstraint("expires_at > created_at", name="ck_core_password_resets_expiry"),
        sa.CheckConstraint(
            "token_digest ~ '^[0-9a-f]{64}$'", name="ck_core_password_resets_digest"
        ),
    )
    op.create_index(
        "ix_core_password_resets_user", "core_password_reset_tokens", ["user_id", "created_at"]
    )
    op.create_index("ix_core_password_resets_expiry", "core_password_reset_tokens", ["expires_at"])
    op.create_table(
        "core_security_audit",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "organization_id",
            sa.Uuid(),
            sa.ForeignKey("core_organizations.id", ondelete="RESTRICT"),
        ),
        sa.Column("actor_id", sa.Uuid(), sa.ForeignKey("core_users.id", ondelete="RESTRICT")),
        sa.Column("action", sa.String(40), nullable=False),
        sa.Column("target_id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("details", postgresql.JSONB(), nullable=False),
    )
    op.create_index("ix_core_security_audit_time", "core_security_audit", ["created_at"])


def downgrade():
    op.drop_table("core_security_audit")
    op.drop_table("core_password_reset_tokens")
    op.drop_table("core_invitation_roles")
    op.drop_table("core_organization_invitations")
