from contextlib import contextmanager
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import patch
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

from editingtab_core.app import create_app
from editingtab_core.auth.provision import provision_user
from editingtab_core.auth.security import Passwords
from editingtab_core.authorization import repository as repo
from editingtab_core.authorization.models import (
    BookingPermissionManagerDesignation,
    MembershipRole,
    PermissionDefinition,
    Role,
    RolePermission,
)
from editingtab_core.authorization.policy import (
    COMPANY_ADMINISTRATOR_PERMISSIONS,
    AccessError,
    Inaccessible,
    InvalidPermission,
    StorageUnavailable,
)
from editingtab_core.identity import services as identity
from editingtab_core.identity.models import Membership, Organization, User
from editingtab_core.platform import booking_permission_managers as managers
from editingtab_core.platform import services as platform
from editingtab_core.platform.booking_permissions import provision as provision_booking_admin
from editingtab_core.platform.models import ModuleEntitlement, PlatformAudit

pytestmark = pytest.mark.integration
ORIGIN = "http://127.0.0.1:18080"
PASSWORD = "synthetic manager lifecycle password"
READ = "booking.inventory.read"
MANAGE = "booking.inventory.manage"
ALTERNATE = "booking.reservations.read"


@pytest.fixture
def manager_env(identity_session, integration_settings):
    passwords = Passwords()
    users = {}
    for name in ("operator", "owner", "second", "unprivileged"):
        users[name] = provision_user(
            identity_session,
            settings=integration_settings,
            passwords=passwords,
            email=(
                platform.PLATFORM_ADMIN_EMAIL
                if name == "operator"
                else f"manager-{name}@example.test"
            ),
            display_name=name.title(),
            password=PASSWORD,
        )
    platform.bootstrap_initial(
        identity_session,
        passwords=passwords,
        password=PASSWORD,
        display_name="Platform Administrator",
    )
    organization_id = platform.onboard(
        identity_session,
        actor_id=users["operator"],
        name="Manager Lifecycle",
        slug="manager-lifecycle",
        owner_email="manager-owner@example.test",
        enabled_modules=["booking"],
    )["id"]
    second_membership = identity.add_membership(
        identity_session, organization_id=organization_id, user_id=users["second"]
    )
    unprivileged_membership = identity.add_membership(
        identity_session, organization_id=organization_id, user_id=users["unprivileged"]
    )
    with identity_session.begin():
        owner_membership = identity_session.scalar(
            select(Membership.id).where(
                Membership.organization_id == organization_id,
                Membership.user_id == users["owner"],
            )
        )
        operations_role = Role(
            organization_id=organization_id,
            name="Role operations",
            normalized_name="role operations",
        )
        identity_session.add(operations_role)
        identity_session.flush()
        identity_session.add_all(
            [
                *(
                    RolePermission(
                        organization_id=organization_id,
                        role_id=operations_role.id,
                        code=code,
                        can_grant=False,
                    )
                    for code in COMPANY_ADMINISTRATOR_PERMISSIONS
                ),
                MembershipRole(
                    organization_id=organization_id,
                    membership_id=second_membership,
                    role_id=operations_role.id,
                ),
            ]
        )
    return SimpleNamespace(
        **users,
        organization_id=organization_id,
        owner_membership=owner_membership,
        second_membership=second_membership,
        unprivileged_membership=unprivileged_membership,
        operations_role=operations_role.id,
    )


@pytest.fixture
def manager_clients(migration_connection, integration_settings):
    @contextmanager
    def make(email=platform.PLATFORM_ADMIN_EMAIL):
        app = create_app(
            integration_settings.model_copy(update={"auth_allowed_origins": (ORIGIN,)})
        )
        with TestClient(app, base_url=ORIGIN) as client:
            app.state.session_factory = sessionmaker(
                bind=migration_connection,
                join_transaction_mode="create_savepoint",
                expire_on_commit=False,
            )
            assert (
                client.post(
                    "/auth/login",
                    json={"email": email, "password": PASSWORD},
                    headers={"Origin": ORIGIN},
                ).status_code
                == 204
            )
            yield client

    return make


def designate(session, env, membership_id=None, scopes=(READ,)):
    return managers.designate(
        session,
        actor_id=env.operator,
        organization_id=env.organization_id,
        membership_id=membership_id or env.owner_membership,
        scopes=scopes,
    )


def test_platform_designation_listing_idempotency_and_audit(identity_session, manager_env):
    env = manager_env
    result = designate(identity_session, env, scopes=(MANAGE, READ))
    assert result == {
        "organization_id": env.organization_id,
        "membership_id": env.owner_membership,
        "user_id": env.owner,
        "role_id": result["role_id"],
        "state": "active",
        "scopes": [MANAGE, READ],
    }
    assert designate(identity_session, env, scopes=(MANAGE, READ)) == result
    assert managers.list_managers(
        identity_session, actor_id=env.operator, organization_id=env.organization_id
    ) == [result]
    with identity_session.begin():
        role = identity_session.get(Role, result["role_id"])
        assert role.provisioning_kind == managers.KIND
        assert repo.role_permission_grants(identity_session, env.organization_id, role.id) == {}
        assert READ not in repo.effective_permissions(
            identity_session, env.organization_id, env.owner
        )
        assert READ not in repo.effective_grant_authority(
            identity_session, env.organization_id, env.owner
        )
        audits = identity_session.scalars(
            select(PlatformAudit).where(PlatformAudit.action == "booking.manager.designated")
        ).all()
        assert len(audits) == 1
        audit = audits[0]
        assert audit.actor_id == env.operator
        assert audit.organization_id == env.organization_id
        assert audit.target_id == env.owner_membership
        assert audit.before == {
            "state": "absent",
            "role_id": str(role.id),
            "scopes": [],
        }
        assert audit.after == {
            "state": "active",
            "role_id": str(role.id),
            "scopes": [MANAGE, READ],
        }


def test_two_managers_scope_replacement_is_independent(identity_session, manager_env):
    env = manager_env
    first = designate(identity_session, env, scopes=(READ,))
    second = designate(identity_session, env, env.second_membership, (MANAGE,))
    updated = designate(identity_session, env, scopes=(ALTERNATE,))
    assert updated["role_id"] == second["role_id"] == first["role_id"]
    assert updated["scopes"] == [ALTERNATE]
    listed = managers.list_managers(
        identity_session, actor_id=env.operator, organization_id=env.organization_id
    )
    assert {row["membership_id"]: row["scopes"] for row in listed} == {
        env.owner_membership: [ALTERNATE],
        env.second_membership: [MANAGE],
    }
    with identity_session.begin():
        audit = identity_session.scalar(
            select(PlatformAudit).where(PlatformAudit.action == "booking.manager.scopes_replaced")
        )
        assert audit.target_id == env.owner_membership
        assert audit.before["scopes"] == [READ]
        assert audit.after["scopes"] == [ALTERNATE]


@pytest.mark.parametrize("target", ["missing", "foreign", "membership", "inactive_user", "user"])
def test_designation_rejects_invalid_or_inactive_targets(identity_session, manager_env, target):
    env = manager_env
    membership_id = uuid4()
    if target == "foreign":
        foreign_org = identity.create_organization(
            identity_session, name="Foreign manager", slug="foreign-manager"
        )
        membership_id = identity.add_membership(
            identity_session, organization_id=foreign_org, user_id=env.second
        )
    elif target != "missing":
        membership_id = env.second_membership
        with identity_session.begin():
            if target == "membership":
                identity_session.get(Membership, membership_id).deleted_at = datetime.now(UTC)
            elif target == "inactive_user":
                identity_session.get(User, env.second).is_active = False
            else:
                identity_session.get(User, env.second).deleted_at = datetime.now(UTC)
    with pytest.raises(Inaccessible):
        designate(identity_session, env, membership_id)


def test_designation_rejects_archived_organization(identity_session, manager_env):
    env = manager_env
    with identity_session.begin():
        identity_session.get(Organization, env.organization_id).deleted_at = datetime.now(UTC)
    with pytest.raises(Inaccessible):
        designate(identity_session, env)


def test_designation_requires_entitlement_and_role_operations(identity_session, manager_env):
    env = manager_env
    with pytest.raises(AccessError):
        designate(identity_session, env, env.unprivileged_membership)
    with identity_session.begin():
        identity_session.get(ModuleEntitlement, (env.organization_id, "booking")).enabled = False
    with pytest.raises(AccessError):
        designate(identity_session, env)


@pytest.mark.parametrize(
    "scopes",
    [
        ("unknown.permission.code",),
        ("core.roles.read",),
        ("booking.*.read",),
        (1,),
        (READ, READ),
    ],
)
def test_designation_rejects_invalid_exact_scopes(identity_session, manager_env, scopes):
    with pytest.raises(InvalidPermission):
        designate(identity_session, manager_env, scopes=scopes)


def test_designation_rejects_inactive_booking_definition(identity_session, manager_env):
    with identity_session.begin():
        identity_session.get(PermissionDefinition, ALTERNATE).lifecycle = "deprecated"
    with pytest.raises(InvalidPermission):
        designate(identity_session, manager_env, scopes=(ALTERNATE,))


def test_designation_rejects_nonassignable_booking_definition(identity_session, manager_env):
    with identity_session.begin():
        identity_session.get(PermissionDefinition, ALTERNATE).organization_assignable = False
    with pytest.raises(InvalidPermission):
        designate(identity_session, manager_env, scopes=(ALTERNATE,))


def test_revocation_lifecycle_and_explicit_redesignation(identity_session, manager_env):
    env = manager_env
    result = designate(identity_session, env, scopes=(READ,))
    with identity_session.begin():
        assert repo.effective_grant_only_permission_management_authority(
            identity_session, env.organization_id, env.owner
        ) == {READ}
        identity_session.get(ModuleEntitlement, (env.organization_id, "booking")).enabled = False
    with identity_session.begin():
        assert (
            repo.effective_grant_only_permission_management_authority(
                identity_session, env.organization_id, env.owner
            )
            == frozenset()
        )
        identity_session.get(ModuleEntitlement, (env.organization_id, "booking")).enabled = True
    with identity_session.begin():
        assert repo.effective_grant_only_permission_management_authority(
            identity_session, env.organization_id, env.owner
        ) == {READ}

    managers.revoke(
        identity_session,
        actor_id=env.operator,
        organization_id=env.organization_id,
        membership_id=env.owner_membership,
    )
    managers.revoke(
        identity_session,
        actor_id=env.operator,
        organization_id=env.organization_id,
        membership_id=env.owner_membership,
    )
    with identity_session.begin():
        designation = identity_session.get(
            BookingPermissionManagerDesignation,
            (env.organization_id, env.owner_membership),
        )
        assert designation.revoked_at is not None
        assert repo.booking_permission_manager_scopes(
            identity_session, env.organization_id, env.owner_membership
        ) == {READ}
        assert (
            identity_session.get(
                MembershipRole,
                (env.organization_id, env.owner_membership, result["role_id"]),
            )
            is None
        )
        assert (
            repo.effective_grant_only_permission_management_authority(
                identity_session, env.organization_id, env.owner
            )
            == frozenset()
        )
        identity_session.get(ModuleEntitlement, (env.organization_id, "booking")).enabled = False
    with identity_session.begin():
        identity_session.get(ModuleEntitlement, (env.organization_id, "booking")).enabled = True
    with identity_session.begin():
        assert (
            repo.effective_grant_only_permission_management_authority(
                identity_session, env.organization_id, env.owner
            )
            == frozenset()
        )
        assert (
            identity_session.scalar(
                select(func.count())
                .select_from(PlatformAudit)
                .where(PlatformAudit.action == "booking.manager.revoked")
            )
            == 1
        )

    restored = designate(identity_session, env, scopes=(ALTERNATE,))
    assert restored["state"] == "active" and restored["scopes"] == [ALTERNATE]
    with identity_session.begin():
        assert repo.effective_grant_only_permission_management_authority(
            identity_session, env.organization_id, env.owner
        ) == {ALTERNATE}


def test_revocation_does_not_require_recipient_role_operations(identity_session, manager_env):
    env = manager_env
    result = designate(identity_session, env, env.second_membership, (READ,))
    with identity_session.begin():
        identity_session.delete(
            identity_session.get(
                MembershipRole,
                (env.organization_id, env.second_membership, env.operations_role),
            )
        )
    managers.revoke(
        identity_session,
        actor_id=env.operator,
        organization_id=env.organization_id,
        membership_id=env.second_membership,
    )
    with identity_session.begin():
        assert (
            identity_session.get(
                MembershipRole,
                (env.organization_id, env.second_membership, result["role_id"]),
            )
            is None
        )


def test_trusted_revocation_cleans_up_an_archived_membership(identity_session, manager_env):
    env = manager_env
    result = designate(identity_session, env, env.second_membership, (READ,))
    protected_assignment = (
        env.organization_id,
        env.second_membership,
        result["role_id"],
    )
    unrelated_assignment = (
        env.organization_id,
        env.second_membership,
        env.operations_role,
    )
    with identity_session.begin():
        identity_session.get(Membership, env.second_membership).deleted_at = datetime.now(UTC)
        assert identity_session.get(MembershipRole, protected_assignment) is not None
        assert identity_session.get(MembershipRole, unrelated_assignment) is not None

    managers.revoke(
        identity_session,
        actor_id=env.operator,
        organization_id=env.organization_id,
        membership_id=env.second_membership,
    )
    with identity_session.begin():
        designation = identity_session.get(
            BookingPermissionManagerDesignation,
            (env.organization_id, env.second_membership),
        )
        revoked_at = designation.revoked_at
        assert revoked_at is not None
        assert identity_session.get(MembershipRole, protected_assignment) is None
        assert identity_session.get(MembershipRole, unrelated_assignment) is not None
        assert (
            identity_session.scalar(
                select(func.count())
                .select_from(PlatformAudit)
                .where(
                    PlatformAudit.action == "booking.manager.revoked",
                    PlatformAudit.organization_id == env.organization_id,
                    PlatformAudit.target_id == env.second_membership,
                )
            )
            == 1
        )

    managers.revoke(
        identity_session,
        actor_id=env.operator,
        organization_id=env.organization_id,
        membership_id=env.second_membership,
    )
    with identity_session.begin():
        designation = identity_session.get(
            BookingPermissionManagerDesignation,
            (env.organization_id, env.second_membership),
        )
        assert designation.revoked_at == revoked_at
        assert identity_session.get(MembershipRole, protected_assignment) is None
        assert identity_session.get(MembershipRole, unrelated_assignment) is not None
        assert (
            identity_session.scalar(
                select(func.count())
                .select_from(PlatformAudit)
                .where(
                    PlatformAudit.action == "booking.manager.revoked",
                    PlatformAudit.organization_id == env.organization_id,
                    PlatformAudit.target_id == env.second_membership,
                )
            )
            == 1
        )


def test_revocation_removes_stale_protected_assignment_without_designation(
    identity_session, manager_env
):
    env = manager_env
    role_id = designate(identity_session, env)["role_id"]
    with identity_session.begin():
        identity_session.add(
            MembershipRole(
                organization_id=env.organization_id,
                membership_id=env.unprivileged_membership,
                role_id=role_id,
            )
        )
    managers.revoke(
        identity_session,
        actor_id=env.operator,
        organization_id=env.organization_id,
        membership_id=env.unprivileged_membership,
    )
    with identity_session.begin():
        assert (
            identity_session.get(
                MembershipRole,
                (env.organization_id, env.unprivileged_membership, role_id),
            )
            is None
        )


def test_booking_administrator_remains_compatible(identity_session, manager_env):
    env = manager_env
    administrator = provision_booking_admin(
        identity_session,
        actor_id=env.operator,
        organization_id=env.organization_id,
        membership_id=env.owner_membership,
    )
    manager = designate(identity_session, env, scopes=(READ,))
    assert manager["role_id"] != administrator["role_id"]
    with identity_session.begin():
        assignments = set(
            identity_session.scalars(
                select(MembershipRole.role_id).where(
                    MembershipRole.organization_id == env.organization_id,
                    MembershipRole.membership_id == env.owner_membership,
                )
            )
        )
        assert {manager["role_id"], administrator["role_id"]} <= assignments
        assert READ in repo.effective_permissions(identity_session, env.organization_id, env.owner)
        assert READ not in repo.effective_grant_authority(
            identity_session, env.organization_id, env.owner
        )


def test_designation_audit_failure_rolls_back_atomically(identity_session, manager_env):
    env = manager_env
    with patch.object(managers, "_audit", side_effect=IntegrityError("hidden", {}, Exception())):
        with pytest.raises(StorageUnavailable):
            designate(identity_session, env)
    with identity_session.begin():
        assert (
            identity_session.get(
                BookingPermissionManagerDesignation,
                (env.organization_id, env.owner_membership),
            )
            is None
        )
        assert (
            identity_session.scalar(
                select(Role.id).where(
                    Role.organization_id == env.organization_id,
                    Role.provisioning_kind == managers.KIND,
                )
            )
            is None
        )


def test_http_contract_and_tenant_denial(identity_session, manager_env, manager_clients):
    env = manager_env
    path = (
        f"/platform/organizations/{env.organization_id}/booking-permission-managers/"
        f"{env.owner_membership}"
    )
    collection = f"/platform/organizations/{env.organization_id}/booking-permission-managers"
    with manager_clients() as client:
        response = client.put(path, json={"scopes": [READ]}, headers={"Origin": ORIGIN})
        assert response.status_code == 200
        assert set(response.json()) == {
            "organization_id",
            "membership_id",
            "user_id",
            "role_id",
            "state",
            "scopes",
        }
        assert response.json()["state"] == "active"
        assert client.get(collection).json() == [response.json()]
        assert client.delete(path, headers={"Origin": ORIGIN}).status_code == 204
        assert client.get(collection).json()[0]["state"] == "revoked"
        for body in (
            {"scopes": [READ, READ]},
            {"scopes": ["booking.*.read"]},
            {"scopes": [1]},
            {"scopes": [READ], "can_grant": True},
        ):
            assert client.put(path, json=body, headers={"Origin": ORIGIN}).status_code == 422

    with manager_clients("manager-owner@example.test") as client:
        assert client.get(collection).status_code == 403
        assert (
            client.put(path, json={"scopes": [READ]}, headers={"Origin": ORIGIN}).status_code == 403
        )
        assert client.delete(path, headers={"Origin": ORIGIN}).status_code == 403


def test_authenticated_context_combines_company_admin_and_scoped_management_authority(
    identity_session, manager_env, manager_clients
):
    env = manager_env
    designate(identity_session, env, scopes=(READ,))

    def organization_context(email):
        with manager_clients(email) as client:
            response = client.get("/auth/context")
        assert response.status_code == 200
        return next(
            (
                organization
                for organization in response.json()["organizations"]
                if organization["organization_id"] == str(env.organization_id)
            ),
            None,
        )

    owner = organization_context("manager-owner@example.test")
    assert owner is not None
    assert READ not in owner["effective_permissions"]
    assert READ not in owner["effective_grant_authority"]
    assert READ in owner["effective_permission_management_authority"]
    assert MANAGE in owner["effective_permission_management_authority"]

    unprivileged = organization_context("manager-unprivileged@example.test")
    assert unprivileged is not None
    assert unprivileged["effective_permission_management_authority"] == []

    managers.revoke(
        identity_session,
        actor_id=env.operator,
        organization_id=env.organization_id,
        membership_id=env.owner_membership,
    )
    revoked = organization_context("manager-owner@example.test")
    assert revoked is not None
    assert READ in revoked["effective_permission_management_authority"]
    assert MANAGE in revoked["effective_permission_management_authority"]

    designate(identity_session, env, scopes=(READ,))
    with identity_session.begin():
        identity_session.get(ModuleEntitlement, (env.organization_id, "booking")).enabled = False
    disabled = organization_context("manager-owner@example.test")
    assert disabled is not None
    assert not any(
        code.startswith("booking.")
        for code in disabled["effective_permission_management_authority"]
    )
    assert READ not in disabled["effective_permission_management_authority"]

    with identity_session.begin():
        identity_session.get(ModuleEntitlement, (env.organization_id, "booking")).enabled = True
        identity_session.get(Membership, env.owner_membership).deleted_at = datetime.now(UTC)
    assert organization_context("manager-owner@example.test") is None
