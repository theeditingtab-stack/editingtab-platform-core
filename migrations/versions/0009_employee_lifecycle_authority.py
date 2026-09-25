"""Backfill employee lifecycle authority for existing recovery administrators.

Revision ID: 0009_employee_lifecycle
Revises: 0008_delegated_grant_authority
"""

from alembic import op

revision = "0009_employee_lifecycle"
down_revision = "0008_delegated_grant_authority"
branch_labels = None
depends_on = None

ADMINISTRATOR_CODES = (
    "core.roles.read",
    "core.roles.create",
    "core.roles.update",
    "core.roles.archive",
    "core.roles.assign",
)


def upgrade():
    codes = ", ".join(repr(code) for code in ADMINISTRATOR_CODES)
    op.execute(
        "INSERT INTO core_role_permissions "
        "(organization_id, role_id, code, definition_organization_assignable, "
        "definition_lifecycle, can_grant) "
        "SELECT organization_id, role_id, 'core.members.manage', true, 'active', true "
        "FROM core_role_permissions "
        f"WHERE code IN ({codes}) AND can_grant "
        "GROUP BY organization_id, role_id "
        f"HAVING count(DISTINCT code) = {len(ADMINISTRATOR_CODES)} "
        "ON CONFLICT (organization_id, role_id, code) DO UPDATE SET can_grant = true"
    )


def downgrade():
    # The permission definition predates this revision and assignments cannot be
    # distinguished safely from later administrator edits. Preserve authorization
    # data rather than deleting potentially intentional grants.
    pass
