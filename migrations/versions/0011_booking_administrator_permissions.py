"""Upgrade designated Booking administrator roles to the complete permission set.

Revision ID: 0011_booking_admin_permissions
Revises: 0010_account_onboarding
"""

from alembic import op

revision = "0011_booking_admin_permissions"
down_revision = "0010_account_onboarding"
branch_labels = None
depends_on = None

BOOKING_PERMISSIONS = (
    "booking.inventory.read",
    "booking.inventory.manage",
    "booking.reservations.read",
    "booking.reservations.create",
    "booking.reservations.update",
    "booking.reservations.cancel",
    "booking.availability.read",
    "booking.safari.read",
    "booking.safari.manage",
    "booking.settings.read",
    "booking.settings.manage",
)
LEGACY_PERMISSIONS = ("booking.inventory.read", "booking.inventory.manage")


def _quoted(values):
    return ", ".join(f"('{value}')" for value in values)


def upgrade():
    permissions = _quoted(BOOKING_PERMISSIONS)
    op.execute(
        f"""
        DO $$
        BEGIN
          IF EXISTS (
            SELECT 1
            FROM core_roles AS role
            JOIN core_role_permissions AS grant_row ON grant_row.role_id = role.id
              AND grant_row.organization_id = role.organization_id
            WHERE role.provisioning_kind = 'booking_inventory'
              AND grant_row.code NOT IN (SELECT code FROM (VALUES {permissions}) AS allowed(code))
          ) THEN
            RAISE EXCEPTION 'designated Booking role contains non-Booking permissions';
          END IF;
        END $$;

        UPDATE core_roles
        SET name = 'Booking administrator',
            normalized_name = 'booking administrator',
            updated_at = now()
        WHERE provisioning_kind = 'booking_inventory'
          AND name = 'Booking inventory administrator'
          AND normalized_name = 'booking inventory administrator';

        INSERT INTO core_role_permissions
          (organization_id, role_id, code, can_grant,
           definition_organization_assignable, definition_lifecycle)
        SELECT role.organization_id, role.id, permission.code, false, true, 'active'
        FROM core_roles AS role
        CROSS JOIN (VALUES {permissions}) AS permission(code)
        WHERE role.provisioning_kind = 'booking_inventory'
          AND role.deleted_at IS NULL
        ON CONFLICT (organization_id, role_id, code) DO NOTHING;
        """
    )


def downgrade():
    legacy_permissions = _quoted(LEGACY_PERMISSIONS)
    op.execute(
        f"""
        DELETE FROM core_role_permissions AS grant_row
        USING core_roles AS role
        WHERE grant_row.role_id = role.id
          AND grant_row.organization_id = role.organization_id
          AND role.provisioning_kind = 'booking_inventory'
          AND grant_row.code NOT IN (
            SELECT code FROM (VALUES {legacy_permissions}) AS allowed(code)
          );

        UPDATE core_roles
        SET name = 'Booking inventory administrator',
            normalized_name = 'booking inventory administrator',
            updated_at = now()
        WHERE provisioning_kind = 'booking_inventory'
          AND name = 'Booking administrator'
          AND normalized_name = 'booking administrator';
        """
    )
