"""Core-owned permission definition registry and final reviewed vocabulary.

Revision ID: 0007_permission_registry
Revises: 0006_booking_authorization
"""

import sqlalchemy as sa
from alembic import op

revision = "0007_permission_registry"
down_revision = "0006_booking_authorization"
branch_labels = None
depends_on = None

DEFINITIONS = (
    ("core.organization.read", "core", "Read organization details."),
    ("core.members.read", "core", "Read organization members and employees."),
    ("core.members.manage", "core", "Manage organization members and employees."),
    ("core.roles.read", "core", "Read organization roles and permission definitions."),
    ("core.roles.create", "core", "Create organization roles."),
    ("core.roles.update", "core", "Update organization roles."),
    ("core.roles.archive", "core", "Archive organization roles."),
    ("core.roles.assign", "core", "Assign and remove organization roles."),
    (
        "core.roles.manage",
        "core",
        "Manage organization roles and assignments (compatibility capability).",
    ),
    ("booking.inventory.read", "booking", "Read Booking inventory."),
    ("booking.inventory.manage", "booking", "Manage Booking inventory."),
    ("booking.reservations.read", "booking", "Read reservations."),
    ("booking.reservations.create", "booking", "Create reservations."),
    ("booking.reservations.update", "booking", "Update reservations."),
    ("booking.reservations.cancel", "booking", "Cancel reservations."),
    ("booking.availability.read", "booking", "Read availability."),
    ("booking.safari.read", "booking", "Read safari definitions."),
    ("booking.safari.manage", "booking", "Manage safari definitions."),
    ("booking.settings.read", "booking", "Read Booking settings."),
    ("booking.settings.manage", "booking", "Manage Booking settings."),
)

LEGACY_CODES = (
    "core.organization.read",
    "core.members.read",
    "core.roles.read",
    "core.roles.manage",
    "booking.inventory.read",
    "booking.inventory.manage",
)


def upgrade():
    definitions = op.create_table(
        "core_permission_definitions",
        sa.Column("code", sa.String(64), primary_key=True),
        sa.Column("module", sa.String(32), nullable=False),
        sa.Column("description", sa.String(255), nullable=False),
        sa.Column("organization_assignable", sa.Boolean(), nullable=False),
        sa.Column("lifecycle", sa.String(16), nullable=False),
        sa.UniqueConstraint(
            "code",
            "organization_assignable",
            "lifecycle",
            name="uq_core_permission_definitions_assignment",
        ),
        sa.CheckConstraint(
            "code ~ '^[a-z][a-z0-9_]*\\.[a-z][a-z0-9_]*\\.[a-z][a-z0-9_]*$'",
            name="ck_core_permission_definitions_code",
        ),
        sa.CheckConstraint(
            "module ~ '^[a-z][a-z0-9_]*$' AND code LIKE module || '.%'",
            name="ck_core_permission_definitions_module",
        ),
        sa.CheckConstraint(
            "description = btrim(description) AND length(description) > 0",
            name="ck_core_permission_definitions_description",
        ),
        sa.CheckConstraint(
            "lifecycle IN ('active', 'deprecated')",
            name="ck_core_permission_definitions_lifecycle",
        ),
    )
    op.create_index(
        "ix_core_permission_definitions_module",
        "core_permission_definitions",
        ["module"],
    )
    op.bulk_insert(
        definitions,
        [
            {
                "code": code,
                "module": module,
                "description": description,
                "organization_assignable": True,
                "lifecycle": "active",
            }
            for code, module, description in DEFINITIONS
        ],
    )

    op.add_column(
        "core_role_permissions",
        sa.Column(
            "definition_organization_assignable",
            sa.Boolean(),
            server_default=sa.true(),
            nullable=False,
        ),
    )
    op.add_column(
        "core_role_permissions",
        sa.Column(
            "definition_lifecycle",
            sa.String(16),
            server_default="active",
            nullable=False,
        ),
    )
    op.drop_constraint("ck_core_role_permissions_catalog", "core_role_permissions", type_="check")
    op.create_check_constraint(
        "ck_core_role_permissions_organization_assignable",
        "core_role_permissions",
        "definition_organization_assignable",
    )
    op.create_check_constraint(
        "ck_core_role_permissions_active",
        "core_role_permissions",
        "definition_lifecycle = 'active'",
    )
    op.create_foreign_key(
        "fk_core_role_permissions_assignable_definition",
        "core_role_permissions",
        "core_permission_definitions",
        ["code", "definition_organization_assignable", "definition_lifecycle"],
        ["code", "organization_assignable", "lifecycle"],
        ondelete="RESTRICT",
        onupdate="RESTRICT",
    )


def downgrade():
    # Creating the legacy constraint first makes downgrade fail rather than discard
    # any assignments that use permission codes introduced by this revision.
    legacy = ", ".join(repr(code) for code in LEGACY_CODES)
    op.create_check_constraint(
        "ck_core_role_permissions_catalog", "core_role_permissions", f"code IN ({legacy})"
    )
    op.drop_constraint(
        "fk_core_role_permissions_assignable_definition",
        "core_role_permissions",
        type_="foreignkey",
    )
    op.drop_constraint("ck_core_role_permissions_active", "core_role_permissions", type_="check")
    op.drop_constraint(
        "ck_core_role_permissions_organization_assignable",
        "core_role_permissions",
        type_="check",
    )
    op.drop_column("core_role_permissions", "definition_lifecycle")
    op.drop_column("core_role_permissions", "definition_organization_assignable")
    op.drop_table("core_permission_definitions")
