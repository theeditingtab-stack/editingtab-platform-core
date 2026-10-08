from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from sqlalchemy.exc import IntegrityError

from editingtab_core.authorization import repository
from editingtab_core.authorization import services as access
from editingtab_core.authorization.models import (
    BookingPermissionManagerDesignation,
    BookingPermissionManagerScope,
    MembershipRole,
    Role,
    RolePermission,
)
from editingtab_core.authorization.policy import (
    MEMBER_MANAGE,
    OWNER_PERMISSIONS,
    ROLE_ARCHIVE,
    ROLE_ASSIGN,
    ROLE_CREATE,
    ROLE_UPDATE,
    AccessError,
    Inaccessible,
    ProtectedRole,
)
from editingtab_core.identity import services as identity
from editingtab_core.identity.models import Membership, Organization, User
from editingtab_core.platform.models import ModuleEntitlement

pytestmark = pytest.mark.integration

MANAGED = "booking.inventory.read"
FULL_GRANT = "booking.inventory.manage"
ALTERNATE = "booking.reservations.read"
CORE_PERMISSION = "core.organization.read"
ROLE_OPERATIONS = {ROLE_CREATE, ROLE_UPDATE, ROLE_ARCHIVE, ROLE_ASSIGN, MEMBER_MANAGE}


@pytest.fixture
def management_env(identity_session):
    user_id = identity.create_user(
        identity_session, email="manager@example.test", display_name="Permission Manager"
    )
    organization_id = identity.create_organization(
        identity_session, name="Managed Organization", slug="managed-organization"
    )
    recovery_user_id = identity.create_user(
        identity_session, email="recovery@example.test", display_name="Recovery Administrator"
    )
    membership_id = identity.add_membership(
        identity_session, organization_id=organization_id, user_id=user_id
    )
    recovery_membership_id = identity.add_membership(
        identity_session, organization_id=organization_id, user_id=recovery_user_id
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
        recovery_role = Role(
            organization_id=organization_id,
            name="Recovery administrator",
            normalized_name="recovery administrator",
        )
        identity_session.add(recovery_role)
        identity_session.flush()
        identity_session.add_all(
            [
                BookingPermissionManagerDesignation(
                    organization_id=organization_id,
                    membership_id=membership_id,
                    role_id=manager_role.id,
                ),
                BookingPermissionManagerScope(
                    organization_id=organization_id,
                    membership_id=membership_id,
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
                *(
                    RolePermission(
                        organization_id=organization_id,
                        role_id=recovery_role.id,
                        code=code,
                        can_grant=True,
                    )
                    for code in OWNER_PERMISSIONS
                ),
                MembershipRole(
                    organization_id=organization_id,
                    membership_id=recovery_membership_id,
                    role_id=recovery_role.id,
                ),
            ]
        )
    return SimpleNamespace(
        organization_id=organization_id,
        user_id=user_id,
        membership_id=membership_id,
        manager_role_id=manager_role.id,
    )


@pytest.fixture
def tenant_manager_env(identity_session, management_env):
    env = management_env
    target_user_id = identity.create_user(
        identity_session, email="target@example.test", display_name="Target Member"
    )
    target_membership_id = identity.add_membership(
        identity_session,
        organization_id=env.organization_id,
        user_id=target_user_id,
    )
    with identity_session.begin():
        operations_role = Role(
            organization_id=env.organization_id,
            name="Tenant role operations",
            normalized_name="tenant role operations",
        )
        identity_session.add(operations_role)
        identity_session.flush()
        identity_session.add_all(
            [
                *(
                    RolePermission(
                        organization_id=env.organization_id,
                        role_id=operations_role.id,
                        code=code,
                        can_grant=False,
                    )
                    for code in ROLE_OPERATIONS
                ),
                MembershipRole(
                    organization_id=env.organization_id,
                    membership_id=env.membership_id,
                    role_id=operations_role.id,
                ),
            ]
        )
    return SimpleNamespace(
        **vars(env),
        target_user_id=target_user_id,
        target_membership_id=target_membership_id,
        operations_role_id=operations_role.id,
    )


def seed_custom_role(session, env, name, permissions):
    with session.begin():
        role = Role(
            organization_id=env.organization_id,
            name=name,
            normalized_name=name.lower(),
        )
        session.add(role)
        session.flush()
        session.add_all(
            RolePermission(
                organization_id=env.organization_id,
                role_id=role.id,
                code=code,
                can_grant=can_grant,
            )
            for code, can_grant in permissions.items()
        )
        return role.id


def test_grant_only_scope_is_exact_and_never_operational_or_full_grant(
    identity_session, management_env
):
    env = management_env
    with identity_session.begin():
        assert repository.booking_permission_manager_scopes(
            identity_session, env.organization_id, env.membership_id
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


def test_two_managers_have_independent_scope_sets_and_updates(identity_session, management_env):
    env = management_env
    second_user_id = identity.create_user(
        identity_session, email="second-manager@example.test", display_name="Second Manager"
    )
    second_membership_id = identity.add_membership(
        identity_session, organization_id=env.organization_id, user_id=second_user_id
    )
    with identity_session.begin():
        identity_session.add_all(
            [
                BookingPermissionManagerDesignation(
                    organization_id=env.organization_id,
                    membership_id=second_membership_id,
                    role_id=env.manager_role_id,
                ),
                BookingPermissionManagerScope(
                    organization_id=env.organization_id,
                    membership_id=second_membership_id,
                    code=FULL_GRANT,
                ),
                MembershipRole(
                    organization_id=env.organization_id,
                    membership_id=second_membership_id,
                    role_id=env.manager_role_id,
                ),
            ]
        )
    with identity_session.begin():
        assert repository.effective_grant_only_permission_management_authority(
            identity_session, env.organization_id, env.user_id
        ) == {MANAGED}
        assert repository.effective_grant_only_permission_management_authority(
            identity_session, env.organization_id, second_user_id
        ) == {FULL_GRANT}
        identity_session.delete(
            identity_session.get(
                BookingPermissionManagerScope,
                (env.organization_id, env.membership_id, MANAGED),
            )
        )
        identity_session.add(
            BookingPermissionManagerScope(
                organization_id=env.organization_id,
                membership_id=env.membership_id,
                code=ALTERNATE,
            )
        )
    with identity_session.begin():
        assert repository.booking_permission_manager_scopes(
            identity_session, env.organization_id, env.membership_id
        ) == {ALTERNATE}
        assert repository.effective_grant_only_permission_management_authority(
            identity_session, env.organization_id, env.user_id
        ) == {ALTERNATE}
        assert repository.effective_grant_only_permission_management_authority(
            identity_session, env.organization_id, second_user_id
        ) == {FULL_GRANT}


def test_revoked_designation_and_stale_assignment_give_no_authority(
    identity_session, management_env
):
    env = management_env
    with identity_session.begin():
        designation = identity_session.get(
            BookingPermissionManagerDesignation,
            (env.organization_id, env.membership_id),
        )
        designation.revoked_at = datetime.now(UTC)
    with identity_session.begin():
        assert (
            identity_session.get(
                MembershipRole,
                (env.organization_id, env.membership_id, env.manager_role_id),
            )
            is not None
        )
        assert repository.booking_permission_manager_scopes(
            identity_session, env.organization_id, env.membership_id
        ) == {MANAGED}
        assert (
            repository.effective_grant_only_permission_management_authority(
                identity_session, env.organization_id, env.user_id
            )
            == frozenset()
        )


def test_designation_without_protected_role_assignment_gives_no_authority(
    identity_session, management_env
):
    env = management_env
    with identity_session.begin():
        identity_session.delete(
            identity_session.get(
                MembershipRole,
                (env.organization_id, env.membership_id, env.manager_role_id),
            )
        )
    with identity_session.begin():
        assert (
            repository.effective_grant_only_permission_management_authority(
                identity_session, env.organization_id, env.user_id
            )
            == frozenset()
        )


def test_stale_protected_role_assignment_without_designation_gives_no_authority(
    identity_session, management_env
):
    env = management_env
    other_user_id = identity.create_user(
        identity_session, email="assignment-only@example.test", display_name="Assignment Only"
    )
    other_membership_id = identity.add_membership(
        identity_session, organization_id=env.organization_id, user_id=other_user_id
    )
    with identity_session.begin():
        identity_session.add(
            MembershipRole(
                organization_id=env.organization_id,
                membership_id=other_membership_id,
                role_id=env.manager_role_id,
            )
        )
    with identity_session.begin():
        assert (
            repository.effective_grant_only_permission_management_authority(
                identity_session, env.organization_id, other_user_id
            )
            == frozenset()
        )


def test_scope_database_rejects_non_booking_and_unknown_codes(identity_session, management_env):
    env = management_env
    for code in (CORE_PERMISSION, "booking.future.read"):
        with pytest.raises(IntegrityError), identity_session.begin():
            identity_session.add(
                BookingPermissionManagerScope(
                    organization_id=env.organization_id,
                    membership_id=env.membership_id,
                    code=code,
                )
            )
            identity_session.flush()


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
                BookingPermissionManagerDesignation(
                    organization_id=foreign_organization_id,
                    membership_id=foreign_membership_id,
                    role_id=foreign_role.id,
                ),
                BookingPermissionManagerScope(
                    organization_id=foreign_organization_id,
                    membership_id=foreign_membership_id,
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
            repository.booking_permission_manager_scopes(
                identity_session, env.organization_id, foreign_membership_id
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


def test_manager_can_assign_and_revoke_use_only_booking_permission(
    identity_session, tenant_manager_env
):
    env = tenant_manager_env
    created = access.create_role(
        identity_session,
        organization_id=env.organization_id,
        actor_id=env.user_id,
        name="Booking reader",
        permissions={MANAGED: False},
    )
    role_id = created["id"]
    access.change_assignment(
        identity_session,
        organization_id=env.organization_id,
        actor_id=env.user_id,
        membership_id=env.target_membership_id,
        role_id=role_id,
    )
    with identity_session.begin():
        assert repository.effective_permissions(
            identity_session, env.organization_id, env.target_user_id
        ) == {MANAGED}
    result = access.change_role_permission(
        identity_session,
        organization_id=env.organization_id,
        actor_id=env.user_id,
        role_id=role_id,
        code=MANAGED,
        remove=True,
    )
    assert result["permissions"] == []
    with identity_session.begin():
        assert (
            repository.effective_permissions(
                identity_session, env.organization_id, env.target_user_id
            )
            == frozenset()
        )


def test_manager_can_archive_and_restore_use_only_booking_role(
    identity_session, tenant_manager_env
):
    env = tenant_manager_env
    role_id = seed_custom_role(identity_session, env, "Booking lifecycle", {MANAGED: False})
    access.archive_role(
        identity_session,
        organization_id=env.organization_id,
        actor_id=env.user_id,
        role_id=role_id,
    )
    restored = access.restore_role(
        identity_session,
        organization_id=env.organization_id,
        actor_id=env.user_id,
        role_id=role_id,
    )
    assert restored["state"] == "active"
    assert restored["permissions"] == [{"code": MANAGED, "can_grant": False}]


def test_manager_cannot_create_delegating_or_core_permission_roles(
    identity_session, tenant_manager_env
):
    env = tenant_manager_env
    for name, permissions in (
        ("Delegating Booking role", {MANAGED: True}),
        ("Unauthorized Core role", {CORE_PERMISSION: False}),
    ):
        with pytest.raises(AccessError):
            access.create_role(
                identity_session,
                organization_id=env.organization_id,
                actor_id=env.user_id,
                name=name,
                permissions=permissions,
            )


def test_manager_cannot_edit_or_assign_mixed_or_stronger_roles(
    identity_session, tenant_manager_env
):
    env = tenant_manager_env
    mixed = seed_custom_role(
        identity_session, env, "Mixed authority", {MANAGED: False, CORE_PERMISSION: False}
    )
    stronger = seed_custom_role(identity_session, env, "Stronger authority", {MANAGED: True})
    booking_only = seed_custom_role(identity_session, env, "Booking only", {MANAGED: False})

    attempts = (
        lambda: access.update_role(
            identity_session,
            organization_id=env.organization_id,
            actor_id=env.user_id,
            role_id=mixed,
            name="Cannot discard unauthorized old state",
            permissions={MANAGED: False},
        ),
        lambda: access.update_role(
            identity_session,
            organization_id=env.organization_id,
            actor_id=env.user_id,
            role_id=booking_only,
            name="Cannot add unauthorized new state",
            permissions={MANAGED: False, CORE_PERMISSION: False},
        ),
        lambda: access.update_role_metadata(
            identity_session,
            organization_id=env.organization_id,
            actor_id=env.user_id,
            role_id=stronger,
            name="Cannot seize stronger role",
        ),
        lambda: access.change_role_permission(
            identity_session,
            organization_id=env.organization_id,
            actor_id=env.user_id,
            role_id=mixed,
            code=MANAGED,
            remove=True,
        ),
        lambda: access.archive_role(
            identity_session,
            organization_id=env.organization_id,
            actor_id=env.user_id,
            role_id=stronger,
        ),
        lambda: access.change_assignment(
            identity_session,
            organization_id=env.organization_id,
            actor_id=env.user_id,
            membership_id=env.target_membership_id,
            role_id=mixed,
        ),
        lambda: access.change_assignment(
            identity_session,
            organization_id=env.organization_id,
            actor_id=env.user_id,
            membership_id=env.target_membership_id,
            role_id=stronger,
        ),
    )
    for attempt in attempts:
        with pytest.raises(AccessError):
            attempt()


def test_manager_cannot_assign_unassign_or_remove_protected_role_via_tenant_paths(
    identity_session, tenant_manager_env
):
    env = tenant_manager_env
    for remove, membership_id in (
        (False, env.target_membership_id),
        (True, env.membership_id),
    ):
        with pytest.raises(ProtectedRole):
            access.change_assignment(
                identity_session,
                organization_id=env.organization_id,
                actor_id=env.user_id,
                membership_id=membership_id,
                role_id=env.manager_role_id,
                remove=remove,
            )
    protected_mutations = (
        lambda: access.update_role(
            identity_session,
            organization_id=env.organization_id,
            actor_id=env.user_id,
            role_id=env.manager_role_id,
            name="Repurposed manager",
            permissions={},
        ),
        lambda: access.update_role_metadata(
            identity_session,
            organization_id=env.organization_id,
            actor_id=env.user_id,
            role_id=env.manager_role_id,
            name="Renamed manager",
        ),
        lambda: access.change_role_permission(
            identity_session,
            organization_id=env.organization_id,
            actor_id=env.user_id,
            role_id=env.manager_role_id,
            code=MANAGED,
        ),
        lambda: access.archive_role(
            identity_session,
            organization_id=env.organization_id,
            actor_id=env.user_id,
            role_id=env.manager_role_id,
        ),
        lambda: access.restore_role(
            identity_session,
            organization_id=env.organization_id,
            actor_id=env.user_id,
            role_id=env.manager_role_id,
        ),
    )
    for mutation in protected_mutations:
        with pytest.raises(ProtectedRole):
            mutation()
    with pytest.raises(ProtectedRole):
        access.archive_member(
            identity_session,
            organization_id=env.organization_id,
            actor_id=env.user_id,
            membership_id=env.membership_id,
        )


def test_manager_cannot_assign_protected_role_during_member_creation(
    identity_session, tenant_manager_env
):
    env = tenant_manager_env
    new_user_id = identity.create_user(
        identity_session, email="new-target@example.test", display_name="New Target"
    )
    with pytest.raises(ProtectedRole):
        access.add_member(
            identity_session,
            organization_id=env.organization_id,
            actor_id=env.user_id,
            user_id=new_user_id,
            role_ids=[env.manager_role_id],
        )


def test_manager_authority_requires_operation_permission(identity_session, management_env):
    with pytest.raises(AccessError):
        access.create_role(
            identity_session,
            organization_id=management_env.organization_id,
            actor_id=management_env.user_id,
            name="Missing operation",
            permissions={MANAGED: False},
        )


def test_manager_authority_requires_enabled_entitlement(identity_session, tenant_manager_env):
    env = tenant_manager_env
    with identity_session.begin():
        identity_session.get(ModuleEntitlement, (env.organization_id, "booking")).enabled = False
    with pytest.raises(AccessError):
        access.create_role(
            identity_session,
            organization_id=env.organization_id,
            actor_id=env.user_id,
            name="Disabled entitlement",
            permissions={MANAGED: False},
        )


def test_manager_cannot_act_on_foreign_organization(identity_session, tenant_manager_env):
    env = tenant_manager_env
    foreign_organization_id = identity.create_organization(
        identity_session, name="Foreign tenant", slug="foreign-tenant"
    )
    foreign_role_id = seed_custom_role(
        identity_session,
        SimpleNamespace(organization_id=foreign_organization_id),
        "Foreign role",
        {MANAGED: False},
    )
    with pytest.raises(Inaccessible):
        access.update_role(
            identity_session,
            organization_id=env.organization_id,
            actor_id=env.user_id,
            role_id=foreign_role_id,
            name="Cross tenant",
            permissions={MANAGED: False},
        )


def test_existing_full_grant_authority_can_still_delegate(identity_session, tenant_manager_env):
    env = tenant_manager_env
    with identity_session.begin():
        identity_session.add(
            RolePermission(
                organization_id=env.organization_id,
                role_id=env.operations_role_id,
                code=MANAGED,
                can_grant=True,
            )
        )
    result = access.create_role(
        identity_session,
        organization_id=env.organization_id,
        actor_id=env.user_id,
        name="Compatible full delegation",
        permissions={MANAGED: True},
    )
    assert result["permissions"] == [{"code": MANAGED, "can_grant": True}]
