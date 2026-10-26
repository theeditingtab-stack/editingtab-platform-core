"""Core-owned organization branding, logos, audit, and permissions.

Revision ID: 0017_branding_profiles
Revises: 0016_first_time_web_setup
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0017_branding_profiles"
down_revision = "0016_first_time_web_setup"
branch_labels = None
depends_on = None

BRANDING_PERMISSIONS = (
    ("core.branding.read", "Read organization workspace branding."),
    ("core.branding.manage", "Manage organization identity and branding."),
)


def upgrade():
    definitions = sa.table(
        "core_permission_definitions",
        sa.column("code", sa.String),
        sa.column("module", sa.String),
        sa.column("description", sa.String),
        sa.column("organization_assignable", sa.Boolean),
        sa.column("lifecycle", sa.String),
    )
    op.bulk_insert(
        definitions,
        [
            {
                "code": code,
                "module": "core",
                "description": description,
                "organization_assignable": True,
                "lifecycle": "active",
            }
            for code, description in BRANDING_PERMISSIONS
        ],
    )

    op.create_table(
        "core_organization_brand_assets",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("storage_key", sa.String(200), nullable=False),
        sa.Column("media_type", sa.String(50), nullable=False),
        sa.Column("byte_size", sa.Integer(), nullable=False),
        sa.Column("width", sa.Integer(), nullable=False),
        sa.Column("height", sa.Integer(), nullable=False),
        sa.Column("content_sha256", sa.String(64), nullable=False),
        sa.Column("created_by", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("retired_at", sa.DateTime(timezone=True)),
        sa.CheckConstraint("byte_size > 0", name="ck_core_brand_assets_byte_size"),
        sa.CheckConstraint("width > 0 AND height > 0", name="ck_core_brand_assets_dimensions"),
        sa.CheckConstraint(
            "media_type IN ('image/png', 'image/jpeg', 'image/webp')",
            name="ck_core_brand_assets_media_type",
        ),
        sa.CheckConstraint(
            "content_sha256 ~ '^[0-9a-f]{64}$'",
            name="ck_core_brand_assets_content_sha256",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"], ["core_organizations.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(["created_by"], ["core_users.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("storage_key", name="uq_core_brand_assets_storage_key"),
        sa.UniqueConstraint("organization_id", "id", name="uq_core_brand_assets_organization_id"),
    )
    op.create_index(
        "ix_core_brand_assets_organization",
        "core_organization_brand_assets",
        ["organization_id", "created_at"],
    )

    op.create_table(
        "core_organization_branding",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("primary_color", sa.String(7), server_default="#183C2B", nullable=False),
        sa.Column("accent_color", sa.String(7), server_default="#D4A853", nullable=False),
        sa.Column("logo_asset_id", sa.Uuid()),
        sa.Column("version", sa.Integer(), server_default="1", nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.CheckConstraint(
            "primary_color ~ '^#[0-9A-F]{6}$'", name="ck_core_branding_primary_color"
        ),
        sa.CheckConstraint("accent_color ~ '^#[0-9A-F]{6}$'", name="ck_core_branding_accent_color"),
        sa.CheckConstraint("version > 0", name="ck_core_branding_version"),
        sa.ForeignKeyConstraint(
            ["organization_id"], ["core_organizations.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "logo_asset_id"],
            [
                "core_organization_brand_assets.organization_id",
                "core_organization_brand_assets.id",
            ],
            ondelete="RESTRICT",
            name="fk_core_branding_organization_logo",
        ),
        sa.PrimaryKeyConstraint("organization_id"),
    )
    op.execute(
        "INSERT INTO core_organization_branding (organization_id) SELECT id FROM core_organizations"
    )

    op.create_table(
        "core_organization_branding_audit",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("actor_id", sa.Uuid(), nullable=False),
        sa.Column("action", sa.String(40), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("before", postgresql.JSONB(), nullable=False),
        sa.Column("after", postgresql.JSONB(), nullable=False),
        sa.ForeignKeyConstraint(
            ["organization_id"], ["core_organizations.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(["actor_id"], ["core_users.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_core_branding_audit_organization_time",
        "core_organization_branding_audit",
        ["organization_id", "created_at"],
    )

    codes = ", ".join(repr(code) for code, _ in BRANDING_PERMISSIONS)
    op.execute(
        sa.text(
            "INSERT INTO core_role_permissions "
            "(organization_id, role_id, code, definition_organization_assignable, "
            "definition_lifecycle, can_grant) "
            "SELECT role.organization_id, role.id, permission.code, true, 'active', true "
            "FROM core_roles AS role "
            f"CROSS JOIN unnest(ARRAY[{codes}]) AS permission(code) "
            "WHERE role.normalized_name = 'organization owner' "
            "ON CONFLICT (organization_id, role_id, code) DO UPDATE SET can_grant = true"
        )
    )


def downgrade():
    op.execute(
        "DO $$ BEGIN "
        "IF EXISTS (SELECT 1 FROM core_organization_brand_assets) OR "
        "EXISTS (SELECT 1 FROM core_organization_branding_audit) OR "
        "EXISTS (SELECT 1 FROM core_organization_branding "
        "WHERE version <> 1 OR primary_color <> '#183C2B' "
        "OR accent_color <> '#D4A853' OR logo_asset_id IS NOT NULL) THEN "
        "RAISE EXCEPTION '0017 downgrade requires unchanged branding state'; "
        "END IF; END $$"
    )
    codes = ", ".join(repr(code) for code, _ in BRANDING_PERMISSIONS)
    op.execute(f"DELETE FROM core_role_permissions WHERE code IN ({codes})")
    op.execute(f"DELETE FROM core_permission_definitions WHERE code IN ({codes})")
    op.drop_index(
        "ix_core_branding_audit_organization_time",
        table_name="core_organization_branding_audit",
    )
    op.drop_table("core_organization_branding_audit")
    op.drop_table("core_organization_branding")
    op.drop_index("ix_core_brand_assets_organization", table_name="core_organization_brand_assets")
    op.drop_table("core_organization_brand_assets")
