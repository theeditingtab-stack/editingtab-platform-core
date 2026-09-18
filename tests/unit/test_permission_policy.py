import pytest

from editingtab_core.authorization.policy import (
    CATALOG,
    OWNER_PERMISSIONS,
    InvalidPermission,
    permissions,
    role_name,
)


def test_owner_is_explicit_and_no_platform_permissions():
    expected = {
        "core.organization.read",
        "core.members.read",
        "core.roles.read",
        "core.roles.manage",
    }
    assert OWNER_PERMISSIONS == expected
    assert CATALOG == expected | {"booking.inventory.read", "booking.inventory.manage"}
    with pytest.raises(InvalidPermission):
        permissions(["platform.admin"])


@pytest.mark.parametrize("name", ["", " ", "x" * 101, "New\nrole", "R\u00f4le"])
def test_invalid_role_names(name):
    with pytest.raises(InvalidPermission):
        role_name(name)


def test_role_name_normalization():
    assert role_name("  Hotel  Reader ") == ("Hotel  Reader", "hotel  reader")
