"""Explicit catalog: adding features requires deliberately adding permissions."""

BOOKING_PERMISSIONS = frozenset({"booking.inventory.read", "booking.inventory.manage"})

CATALOG = BOOKING_PERMISSIONS | frozenset(
    {
        "core.organization.read",
        "core.members.read",
        "core.roles.read",
        "core.roles.manage",
    }
)
OWNER_PERMISSIONS = frozenset(
    {
        "core.organization.read",
        "core.members.read",
        "core.roles.read",
        "core.roles.manage",
    }
)
MANAGE = "core.roles.manage"


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


def permissions(values):
    result = frozenset(values)
    if not result <= CATALOG:
        raise InvalidPermission()
    return result


def role_name(value):
    name = value.strip()
    if not 1 <= len(name) <= 100 or any(not 32 <= ord(c) <= 126 for c in name):
        raise InvalidPermission()
    return name, name.lower()
