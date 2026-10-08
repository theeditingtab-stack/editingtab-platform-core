from datetime import UTC, datetime
from types import SimpleNamespace

import pytest

from editingtab_core.authorization import repository
from editingtab_core.authorization.models import (
    MembershipRole,
    Role,
    RolePermission,
    RolePermissionManagement,
)
from editingtab_core.identity import services as identity
from editingtab_core.identity.models import Membership, Organization, User
from editingtab_core.platform.models import ModuleEntitlement

pytestmark = pytest.mark.integration

MANAGED = "booking.inventory.read"
FULL_GRANT = "booking.inventory.manage"


@pytest.fixture
def management_env(identity_session):
    user_id = identity.create_user(
        identity_session, email="manager@example.test", display_name="Permission Manager"
    )
    organization_id = identity.create_organization(
        identity_session, name="Managed Organization", slug="managed-organization"
    )
    membership_id = identity.add_membership(
        identity_session, organization_id=organization_id, user_id=user_id
    )
    with identity_session.begin():
        manager_role = Role(
            organization_id=organization_id,
            name="Booking permission manager",
            normalized_name="booking permission manager",
            provisioning_kind="booking_permission_manager",
        )
        identity_session.add(manager_role)
        identity_session.flush()
        identity_session.add_all(
            [
                RolePermissionManagement(
                    organization_id=organization_id,
                    role_id=manager_role.id,
                    code=MANAGED,
                ),
                MembershipRole(
                    organization_id=organization_id,
                    membership_id=membership_id,
                    role_id=manager_role.id,
                ),
                ModuleEntitlement(
                    organization_id=organization_id,
                    module_code="booking",
                    enabled=True,
                ),
            ]
        )
    return SimpleNamespace(
        organization_id=organization_id,
        user_id=user_id,
        membership_id=membership_id,
        manager_role_id=manager_role.id,
    )


def test_grant_only_scope_is_exact_and_never_operational_or_full_grant(
    identity_session, management_env
):
    env = management_env
    with identity_session.begin():
        assert repository.role_permission_management_scopes(
            identity_session, env.organization_id, env.manager_role_id
        ) == {MANAGED}
        assert (
            repository.effective_permissions(identity_session, env.organization_id, env.user_id)
            == frozenset()
        )
        assert (
            repository.effective_grant_authority(identity_session, env.organization_id, env.user_id)
            == frozenset()
        )
        assert repository.effective_grant_only_permission_management_authority(
            identity_session, env.organization_id, env.user_id
        ) == {MANAGED}
        assert repository.effective_permission_management_authority(
            identity_session, env.organization_id, env.user_id
        ) == {MANAGED}


def test_effective_management_authority_unions_existing_full_grants(
    identity_session, management_env
):
    env = management_env
    with identity_session.begin():
        full_role = Role(
            organization_id=env.organization_id,
            name="Existing full grant",
            normalized_name="existing full grant",
        )
        identity_session.add(full_role)
        identity_session.flush()
        identity_session.add_all(
            [
                RolePermission(
                    organization_id=env.organization_id,
                    role_id=full_role.id,
                    code=FULL_GRANT,
                    can_grant=True,
                ),
                MembershipRole(
                    organization_id=env.organization_id,
                    membership_id=env.membership_id,
                    role_id=full_role.id,
                ),
            ]
        )
    with identity_session.begin():
        assert repository.effective_grant_authority(
            identity_session, env.organization_id, env.user_id
        ) == {FULL_GRANT}
        assert repository.effective_permission_management_authority(
            identity_session, env.organization_id, env.user_id
        ) == {MANAGED, FULL_GRANT}


@pytest.mark.parametrize("state", ["role", "inactive_user", "user", "membership", "organization"])
def test_inactive_state_cannot_contribute_grant_only_authority(
    identity_session, management_env, state
):
    env = management_env
    with identity_session.begin():
        if state == "inactive_user":
            identity_session.get(User, env.user_id).is_active = False
        else:
            model, key = {
                "role": (Role, env.manager_role_id),
                "user": (User, env.user_id),
                "membership": (Membership, env.membership_id),
                "organization": (Organization, env.organization_id),
            }[state]
            identity_session.get(model, key).deleted_at = datetime.now(UTC)
    with identity_session.begin():
        assert (
            repository.effective_grant_only_permission_management_authority(
                identity_session, env.organization_id, env.user_id
            )
            == frozenset()
        )
        assert (
            repository.effective_permission_management_authority(
                identity_session, env.organization_id, env.user_id
            )
            == frozenset()
        )


def test_foreign_organization_scope_does_not_leak(identity_session, management_env):
    env = management_env
    foreign_organization_id = identity.create_organization(
        identity_session, name="Foreign Organization", slug="foreign-organization"
    )
    foreign_membership_id = identity.add_membership(
        identity_session,
        organization_id=foreign_organization_id,
        user_id=env.user_id,
    )
    with identity_session.begin():
        foreign_role = Role(
            organization_id=foreign_organization_id,
            name="Foreign manager",
            normalized_name="foreign manager",
            provisioning_kind="booking_permission_manager",
        )
        identity_session.add(foreign_role)
        identity_session.flush()
        identity_session.add_all(
            [
                RolePermissionManagement(
                    organization_id=foreign_organization_id,
                    role_id=foreign_role.id,
                    code=FULL_GRANT,
                ),
                MembershipRole(
                    organization_id=foreign_organization_id,
                    membership_id=foreign_membership_id,
                    role_id=foreign_role.id,
                ),
                ModuleEntitlement(
                    organization_id=foreign_organization_id,
                    module_code="booking",
                    enabled=True,
                ),
            ]
        )
    with identity_session.begin():
        assert repository.effective_permission_management_authority(
            identity_session, env.organization_id, env.user_id
        ) == {MANAGED}
        assert repository.effective_permission_management_authority(
            identity_session, foreign_organization_id, env.user_id
        ) == {FULL_GRANT}
        assert (
            repository.role_permission_management_scopes(
                identity_session, env.organization_id, foreign_role.id
            )
            == frozenset()
        )


def test_disabled_entitlement_suspends_only_manager_derived_authority(
    identity_session, management_env
):
    env = management_env
    with identity_session.begin():
        full_role = Role(
            organization_id=env.organization_id,
            name="Full grant while disabled",
            normalized_name="full grant while disabled",
        )
        identity_session.add(full_role)
        identity_session.flush()
        identity_session.add_all(
            [
                RolePermission(
                    organization_id=env.organization_id,
                    role_id=full_role.id,
                    code=FULL_GRANT,
                    can_grant=True,
                ),
                MembershipRole(
                    organization_id=env.organization_id,
                    membership_id=env.membership_id,
                    role_id=full_role.id,
                ),
            ]
        )
        identity_session.get(ModuleEntitlement, (env.organization_id, "booking")).enabled = False
    with identity_session.begin():
        assert (
            repository.effective_grant_only_permission_management_authority(
                identity_session, env.organization_id, env.user_id
            )
            == frozenset()
        )
        assert repository.effective_grant_authority(
            identity_session, env.organization_id, env.user_id
        ) == {FULL_GRANT}
        assert repository.effective_permission_management_authority(
            identity_session, env.organization_id, env.user_id
        ) == {FULL_GRANT}
