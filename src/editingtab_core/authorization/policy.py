"""Stable authorization constants; assignable definitions live in PostgreSQL."""

BOOKING_INVENTORY_PERMISSIONS = frozenset({"booking.inventory.read", "booking.inventory.manage"})
BOOKING_PERMISSIONS = BOOKING_INVENTORY_PERMISSIONS | frozenset(
    {
        "booking.reservations.read",
        "booking.reservations.create",
        "booking.reservations.update",
        "booking.reservations.cancel",
        "booking.availability.read",
        "booking.safari.read",
        "booking.safari.manage",
        "booking.settings.read",
        "booking.settings.manage",
    }
)
OWNER_PERMISSIONS = frozenset(
    {
        "core.organization.read",
        "core.members.read",
        "core.roles.read",
        "core.roles.create",
        "core.roles.update",
        "core.roles.archive",
        "core.roles.assign",
    }
)
ROLE_CREATE = "core.roles.create"
ROLE_UPDATE = "core.roles.update"
ROLE_ARCHIVE = "core.roles.archive"
ROLE_ASSIGN = "core.roles.assign"
ADMINISTRATOR_PERMISSIONS = frozenset(
    {"core.roles.read", ROLE_CREATE, ROLE_UPDATE, ROLE_ARCHIVE, ROLE_ASSIGN}
)


class AccessError(Exception):
    status = 403
    message = "Permission denied."


class Inaccessible(AccessError):
    status = 404
    message = "Resource not found."


class InvalidPermission(AccessError):
    status = 422
    message = "Unknown permission code or invalid role name."


class Conflict(AccessError):
    status = 409
    message = "Role name is reserved or assignment already exists."


class LastAdministrator(Conflict):
    message = "An active organization must retain an active administrator."


class StorageUnavailable(AccessError):
    status = 503
    message = "Organization operation unavailable."


def role_name(value):
    name = value.strip()
    if not 1 <= len(name) <= 100 or any(not 32 <= ord(c) <= 126 for c in name):
        raise InvalidPermission()
    return name, name.lower()
