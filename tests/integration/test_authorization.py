from contextlib import contextmanager
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
from editingtab_core.authorization import services as access
from editingtab_core.authorization.bootstrap import bootstrap
from editingtab_core.authorization.models import (
    MembershipRole,
    PermissionDefinition,
    Role,
    RoleAudit,
    RolePermission,
)
from editingtab_core.authorization.policy import (
    OWNER_PERMISSIONS,
    ROLE_ARCHIVE,
    ROLE_ASSIGN,
    ROLE_CREATE,
    ROLE_UPDATE,
    AccessError,
    Conflict,
    Inaccessible,
    InvalidPermission,
    LastAdministrator,
    StorageUnavailable,
)
from editingtab_core.identity import services as identity
from editingtab_core.identity.models import Membership, Organization, User

pytestmark = pytest.mark.integration
ORIGIN = "http://127.0.0.1:18080"
PASSWORD = "synthetic role test password"


@pytest.fixture
def setup(identity_session, integration_settings):
    session = identity_session
    passwords = Passwords()
    owner = provision_user(
        session,
        settings=integration_settings,
        passwords=passwords,
        email="owner@example.test",
        display_name="Owner",
        password=PASSWORD,
    )
    user = provision_user(
        session,
        settings=integration_settings,
        passwords=passwords,
        email="member@example.test",
        display_name="Member",
        password=PASSWORD,
    )
    org = bootstrap(
        session, settings=integration_settings, email="owner@example.test", slug="demo", name="Demo"
    )
    member = identity.add_membership(session, organization_id=org, user_id=user)
    with session.begin():
        owner_role = session.scalar(select(Role.id).where(Role.organization_id == org))
        owner_member = session.scalar(
            select(Membership.id).where(
                Membership.organization_id == org, Membership.user_id == owner
            )
        )
    return SimpleNamespace(
        owner=owner,
        user=user,
        org=org,
        member=member,
        owner_role=owner_role,
        owner_member=owner_member,
    )


@pytest.fixture
def clients(identity_session, migration_connection, integration_settings):
    @contextmanager
    def make(email="owner@example.test", authenticated=True):
        app = create_app(
            integration_settings.model_copy(update={"auth_allowed_origins": (ORIGIN,)})
        )
        with TestClient(app, base_url=ORIGIN) as client:
            app.state.session_factory = sessionmaker(
                bind=migration_connection,
                join_transaction_mode="create_savepoint",
                expire_on_commit=False,
            )
            if authenticated:
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


def create(session, env, name, codes):
    return access.create_role(
        session, organization_id=env.org, actor_id=env.owner, name=name, codes=codes
    )["id"]


def assign(session, env, role, member=None):
    access.change_assignment(
        session,
        organization_id=env.org,
        actor_id=env.owner,
        membership_id=member or env.member,
        role_id=role,
    )


def test_union_deny_default_and_unknown_permissions(identity_session, setup):
    env = setup
    with pytest.raises(AccessError):
        access.read_organization(identity_session, organization_id=env.org, actor_id=env.user)
    for code in ("core.organization.read", "core.members.read"):
        assign(identity_session, env, create(identity_session, env, code, [code]))
    assert (
        access.read_organization(identity_session, organization_id=env.org, actor_id=env.user)["id"]
        == env.org
    )
    assert (
        len(access.list_members(identity_session, organization_id=env.org, actor_id=env.user)) == 2
    )
    for code in ("platform.admin", "*", "core.fake"):
        with pytest.raises(InvalidPermission):
            create(identity_session, env, "Unknown", [code])
    with identity_session.begin():
        identity_session.add(
            RolePermission(organization_id=env.org, role_id=env.owner_role, code="platform.admin")
        )
        with pytest.raises(IntegrityError):
            identity_session.flush()
        identity_session.rollback()


@pytest.mark.parametrize(
    "organization_assignable,lifecycle",
    [(True, "deprecated"), (False, "active")],
)
def test_registry_rejects_unassignable_definitions(
    identity_session, setup, organization_assignable, lifecycle
):
    code = f"core.restricted.{lifecycle}" if organization_assignable else "core.internal.manage"
    with identity_session.begin():
        identity_session.add(
            PermissionDefinition(
                code=code,
                module="core",
                description="Test-only restricted definition.",
                organization_assignable=organization_assignable,
                lifecycle=lifecycle,
            )
        )
    with pytest.raises(InvalidPermission):
        create(identity_session, setup, f"Rejected {lifecycle}", [code])
    with pytest.raises(IntegrityError), identity_session.begin():
        identity_session.add(
            RolePermission(organization_id=setup.org, role_id=setup.owner_role, code=code)
        )
        identity_session.flush()


def test_permission_definition_code_is_globally_unique(identity_session):
    with pytest.raises(IntegrityError), identity_session.begin():
        identity_session.add(
            PermissionDefinition(
                code="core.roles.read",
                module="core",
                description="Duplicate.",
                organization_assignable=True,
                lifecycle="active",
            )
        )
        identity_session.flush()


def test_permission_catalog_is_protected_deterministic_and_tenant_scoped(
    identity_session, setup, clients, integration_settings
):
    expected = access.list_permission_catalog(
        identity_session, organization_id=setup.org, actor_id=setup.owner
    )
    assert [row["code"] for row in expected] == sorted(
        (row["code"] for row in expected), key=lambda code: (code.split(".", 1)[0], code)
    )
    assert all(row["lifecycle"] == "active" for row in expected)
    assert all(row["module"] != "platform" for row in expected)
    assert "booking.reservations.cancel" in {row["code"] for row in expected}

    other = bootstrap(
        identity_session,
        settings=integration_settings,
        email="owner@example.test",
        slug="catalog-other",
        name="Catalog other",
    )
    root = f"/organizations/{setup.org}/permissions"
    with (
        clients(authenticated=False) as anonymous,
        clients() as owner,
        clients("member@example.test") as member,
    ):
        assert anonymous.get(root).status_code == 401
        response = owner.get(root)
        assert response.status_code == 200
        assert response.json() == expected
        assert member.get(root).status_code == 403
        assert member.get(f"/organizations/{other}/permissions").status_code == 404


def test_normalized_names_reserved_after_archive(identity_session, setup):
    role = create(identity_session, setup, " Reader ", [])
    with pytest.raises(Conflict):
        create(identity_session, setup, "reader", [])
    access.archive_role(
        identity_session, organization_id=setup.org, actor_id=setup.owner, role_id=role
    )
    with pytest.raises(Conflict):
        create(identity_session, setup, "READER", [])
    with identity_session.begin():
        assert identity_session.get(Role, role).deleted_at is not None


def test_limited_manager_cannot_manipulate_more_privileged_roles(identity_session, setup):
    env = setup
    limited = access.create_role(
        identity_session,
        organization_id=env.org,
        actor_id=env.owner,
        name="Limited manager",
        permissions={
            ROLE_CREATE: False,
            ROLE_UPDATE: False,
            ROLE_ARCHIVE: False,
            ROLE_ASSIGN: False,
        },
    )["id"]
    assign(identity_session, env, limited)
    common = dict(organization_id=env.org, actor_id=env.user)
    attempts = [
        lambda: access.create_role(
            identity_session, **common, name="Escalate", codes=OWNER_PERMISSIONS
        ),
        lambda: access.update_role(
            identity_session, **common, role_id=limited, name="Escalate", codes=OWNER_PERMISSIONS
        ),
        lambda: access.update_role(
            identity_session, **common, role_id=env.owner_role, name="Weak", codes=[]
        ),
        lambda: access.archive_role(identity_session, **common, role_id=env.owner_role),
        lambda: access.change_assignment(
            identity_session, **common, role_id=env.owner_role, membership_id=env.member
        ),
        lambda: access.change_assignment(
            identity_session,
            **common,
            role_id=env.owner_role,
            membership_id=env.owner_member,
            remove=True,
        ),
        lambda: identity.archive_membership(
            identity_session, **common, membership_id=env.owner_member
        ),
    ]
    for attempt in attempts:
        with pytest.raises(AccessError):
            attempt()
    assert create(identity_session, env, "Still usable", [])


def test_use_permission_is_not_grant_authority_and_delegation_is_explicit(identity_session, setup):
    env = setup
    capability_only = access.create_role(
        identity_session,
        organization_id=env.org,
        actor_id=env.owner,
        name="Capability only",
        permissions={ROLE_CREATE: False, "core.organization.read": False},
    )["id"]
    assign(identity_session, env, capability_only)

    with identity_session.begin():
        assert "core.organization.read" in repo.effective_permissions(
            identity_session, env.org, env.user
        )
        assert "core.organization.read" not in repo.effective_grant_authority(
            identity_session, env.org, env.user
        )
    with pytest.raises(AccessError):
        access.create_role(
            identity_session,
            organization_id=env.org,
            actor_id=env.user,
            name="Forbidden delegation",
            permissions={"core.organization.read": False},
        )
    with pytest.raises(AccessError):
        access.create_role(
            identity_session,
            organization_id=env.org,
            actor_id=env.user,
            name="Forbidden onward delegation",
            permissions={"core.organization.read": True},
        )

    delegator = access.create_role(
        identity_session,
        organization_id=env.org,
        actor_id=env.owner,
        name="Explicit delegator",
        permissions={"core.organization.read": True},
    )["id"]
    assign(identity_session, env, delegator)
    created = access.create_role(
        identity_session,
        organization_id=env.org,
        actor_id=env.user,
        name="Allowed delegation",
        permissions={"core.organization.read": True},
    )
    assert created["permissions"] == [{"code": "core.organization.read", "can_grant": True}]


@pytest.mark.parametrize(
    "capability,operation",
    [
        (ROLE_CREATE, "create"),
        (ROLE_UPDATE, "update"),
        (ROLE_ARCHIVE, "archive"),
        (ROLE_ASSIGN, "assign"),
    ],
)
def test_granular_role_operations_are_enforced_separately(
    identity_session, setup, capability, operation
):
    env = setup
    operator = access.create_role(
        identity_session,
        organization_id=env.org,
        actor_id=env.owner,
        name=f"Only {operation}",
        permissions={capability: False},
    )["id"]
    assign(identity_session, env, operator)
    target = create(identity_session, env, f"{operation} target", [])
    common = {"organization_id": env.org, "actor_id": env.user}

    if operation == "create":
        access.create_role(identity_session, **common, name="Created", permissions={})
    elif operation == "update":
        access.update_role(
            identity_session, **common, role_id=target, name="Updated", permissions={}
        )
    elif operation == "archive":
        access.archive_role(identity_session, **common, role_id=target)
    else:
        access.change_assignment(
            identity_session, **common, membership_id=env.member, role_id=target
        )

    denied = {
        "create": lambda: access.create_role(
            identity_session, **common, name="Denied create", permissions={}
        ),
        "update": lambda: access.update_role(
            identity_session, **common, role_id=target, name="Denied update", permissions={}
        ),
        "archive": lambda: access.archive_role(identity_session, **common, role_id=target),
        "assign": lambda: access.change_assignment(
            identity_session, **common, membership_id=env.member, role_id=target
        ),
    }
    other = next(name for name in denied if name != operation)
    with pytest.raises(AccessError):
        denied[other]()


def test_update_archive_and_assignment_validate_stronger_existing_role(identity_session, setup):
    env = setup
    stronger = create(identity_session, env, "Stronger", ["core.members.read"])
    assign(identity_session, env, stronger)
    operator = access.create_role(
        identity_session,
        organization_id=env.org,
        actor_id=env.owner,
        name="Narrow administrator",
        permissions={
            ROLE_UPDATE: False,
            ROLE_ARCHIVE: False,
            ROLE_ASSIGN: False,
            "core.organization.read": True,
        },
    )["id"]
    assign(identity_session, env, operator)
    common = {"organization_id": env.org, "actor_id": env.user}

    attempts = [
        lambda: access.update_role(
            identity_session,
            **common,
            role_id=stronger,
            name="Seized",
            permissions={"core.organization.read": False},
        ),
        lambda: access.archive_role(identity_session, **common, role_id=stronger),
        lambda: access.change_assignment(
            identity_session,
            **common,
            membership_id=env.member,
            role_id=stronger,
            remove=True,
        ),
    ]
    for attempt in attempts:
        with pytest.raises(AccessError):
            attempt()
    with identity_session.begin():
        assert identity_session.get(Role, stronger).name == "Stronger"
        assert identity_session.get(MembershipRole, (env.org, env.member, stronger)) is not None


def test_foreign_resources_and_database_ownership(identity_session, setup, integration_settings):
    env = setup
    other = bootstrap(
        identity_session,
        settings=integration_settings,
        email="owner@example.test",
        slug="other",
        name="Other",
    )
    with identity_session.begin():
        foreign_role = identity_session.scalar(select(Role.id).where(Role.organization_id == other))
        foreign_member = identity_session.scalar(
            select(Membership.id).where(Membership.organization_id == other)
        )
    with pytest.raises(Inaccessible):
        access.read_organization(identity_session, organization_id=other, actor_id=env.user)
    with pytest.raises(Inaccessible):
        access.archive_role(
            identity_session, organization_id=env.org, actor_id=env.owner, role_id=foreign_role
        )
    for member, role in ((env.member, foreign_role), (foreign_member, env.owner_role)):
        with pytest.raises(Inaccessible):
            access.change_assignment(
                identity_session,
                organization_id=env.org,
                actor_id=env.owner,
                membership_id=member,
                role_id=role,
            )
        with pytest.raises(IntegrityError), identity_session.begin():
            identity_session.add(
                MembershipRole(organization_id=env.org, membership_id=member, role_id=role)
            )
            identity_session.flush()


@pytest.mark.parametrize("operation", ["archive", "permissions", "assignment", "membership"])
def test_last_administrator_rejections_rollback(identity_session, setup, operation):
    env = setup
    with identity_session.begin():
        before = identity_session.scalar(select(func.count()).select_from(RoleAudit))
    with pytest.raises(LastAdministrator):
        if operation == "archive":
            access.archive_role(
                identity_session,
                organization_id=env.org,
                actor_id=env.owner,
                role_id=env.owner_role,
            )
        elif operation == "permissions":
            access.update_role(
                identity_session,
                organization_id=env.org,
                actor_id=env.owner,
                role_id=env.owner_role,
                name="Owner",
                codes=[],
            )
        elif operation == "assignment":
            access.change_assignment(
                identity_session,
                organization_id=env.org,
                actor_id=env.owner,
                membership_id=env.owner_member,
                role_id=env.owner_role,
                remove=True,
            )
        else:
            identity.archive_membership(
                identity_session,
                organization_id=env.org,
                actor_id=env.owner,
                membership_id=env.owner_member,
            )
    with identity_session.begin():
        assert identity_session.scalar(select(func.count()).select_from(RoleAudit)) == before
        assert repo.has_administrator(identity_session, env.org)


def test_membership_restore_does_not_restore_assignments(identity_session, setup):
    env = setup
    assign(identity_session, env, env.owner_role)
    identity.archive_membership(
        identity_session, organization_id=env.org, actor_id=env.owner, membership_id=env.member
    )
    assert (
        identity.add_membership(identity_session, organization_id=env.org, user_id=env.user)
        == env.member
    )
    with identity_session.begin():
        assert repo.effective_permissions(identity_session, env.org, env.user) == frozenset()
        assert identity_session.get(Membership, env.member) is not None
        assert identity_session.get(MembershipRole, (env.org, env.member, env.owner_role)) is None


@pytest.mark.parametrize("state", ["organization", "user", "inactive", "membership", "role"])
def test_archived_or_inactive_entities_grant_nothing(identity_session, setup, state):
    env = setup
    with identity_session.begin():
        if state == "inactive":
            identity_session.get(User, env.owner).is_active = False
        else:
            model, key = {
                "organization": (Organization, env.org),
                "user": (User, env.owner),
                "membership": (Membership, env.owner_member),
                "role": (Role, env.owner_role),
            }[state]
            identity_session.get(model, key).deleted_at = func.now()
    with pytest.raises(AccessError):
        access.read_organization(identity_session, organization_id=env.org, actor_id=env.owner)


def test_audit_is_atomic_and_bootstrap_never_regrants(
    identity_session, setup, integration_settings
):
    env = setup
    with identity_session.begin():
        before = identity_session.scalar(select(func.count()).select_from(RoleAudit))
    original = repo.audit

    def fail(*args, **kwargs):
        original(*args, **kwargs)
        raise IntegrityError("hidden", {}, Exception("hidden"))

    with patch.object(repo, "audit", side_effect=fail), pytest.raises(StorageUnavailable):
        create(identity_session, env, "Rolled back", [])
    with identity_session.begin():
        assert identity_session.scalar(select(func.count()).select_from(RoleAudit)) == before
        assert identity_session.scalar(select(Role.id).where(Role.name == "Rolled back")) is None
    role = create(identity_session, env, "Audited", ["core.organization.read"])
    access.update_role(
        identity_session,
        organization_id=env.org,
        actor_id=env.owner,
        role_id=role,
        name="Audited role",
        permissions={"core.organization.read": True},
    )
    with pytest.raises(Conflict):
        bootstrap(
            identity_session,
            settings=integration_settings,
            email="owner@example.test",
            slug="demo",
            name="Demo",
        )
    with identity_session.begin():
        event = identity_session.scalar(select(RoleAudit).where(RoleAudit.action == "role.updated"))
        assert event.permissions_before == [{"code": "core.organization.read", "can_grant": False}]
        assert event.permissions_after == [{"code": "core.organization.read", "can_grant": True}]
        assert event.actor_id == env.owner and event.organization_id == env.org


@pytest.mark.parametrize("revocation", ["assignment", "permissions", "role"])
def test_http_revocation_without_relogin(identity_session, setup, clients, revocation):
    env = setup
    role = create(identity_session, env, "Reader", ["core.organization.read"])
    assign(identity_session, env, role)
    with clients("member@example.test") as client:
        path = f"/organizations/{env.org}"
        assert client.get(path).status_code == 200
        if revocation == "assignment":
            access.change_assignment(
                identity_session,
                organization_id=env.org,
                actor_id=env.owner,
                membership_id=env.member,
                role_id=role,
                remove=True,
            )
        elif revocation == "permissions":
            access.update_role(
                identity_session,
                organization_id=env.org,
                actor_id=env.owner,
                role_id=role,
                name="Reader",
                codes=[],
            )
        else:
            access.archive_role(
                identity_session, organization_id=env.org, actor_id=env.owner, role_id=role
            )
        assert client.get(path).status_code == 403
        assert client.get("/auth/me").status_code == 200


def test_http_security_routes_and_minimal_profiles(identity_session, setup, clients):
    env = setup
    root = f"/organizations/{env.org}"
    with clients(authenticated=False) as client:
        assert client.get("/organizations").status_code == 401
        assert client.get(root).status_code == 401
        assert (
            client.post(
                root + "/roles", json={"name": "New", "permissions": []}, headers={"Origin": ORIGIN}
            ).status_code
            == 401
        )
    with clients() as owner, clients("member@example.test") as member:
        assert owner.get("/organizations?limit=101").status_code == 422
        assert len(owner.get("/organizations?limit=1").json()) == 1
        assert member.get(root).status_code == 403
        foreign = f"/organizations/{uuid4()}"
        assert owner.get(foreign).status_code == 404
        assert (
            owner.delete(root + f"/roles/{uuid4()}", headers={"Origin": ORIGIN}).json()
            == owner.get(foreign).json()
        )
        profiles = owner.get(root + "/members").json()
        assert all(
            set(profile) == {"membership_id", "user_id", "display_name", "email", "state", "roles"}
            for profile in profiles
        )
        payload = {
            "name": "HTTP Reader",
            "permissions": [{"code": "core.organization.read", "can_grant": False}],
        }
        assert owner.post(root + "/roles", json=payload).status_code == 403
        role = owner.post(root + "/roles", json=payload, headers={"Origin": ORIGIN})
        assert role.status_code == 201
        role_id = role.json()["id"]
        assert (
            owner.post(root + "/roles", json=payload, headers={"Origin": ORIGIN}).status_code == 409
        )
        duplicate = {
            "name": "Duplicate",
            "permissions": payload["permissions"] * 2,
        }
        assert (
            owner.post(root + "/roles", json=duplicate, headers={"Origin": ORIGIN}).status_code
            == 422
        )
        assert (
            owner.post(
                root + "/roles",
                json={**payload, "actor_id": str(env.owner)},
                headers={"Origin": ORIGIN},
            ).status_code
            == 422
        )
        assignment_path = root + f"/members/{env.member}/roles/{role_id}"
        role_path = root + f"/roles/{role_id}"
        for method, path, body in [
            ("PUT", assignment_path, None),
            ("DELETE", assignment_path, None),
            ("PUT", role_path, payload),
            ("DELETE", role_path, None),
        ]:
            assert owner.request(method, path, json=body).status_code == 403
            assert (
                owner.request(
                    method, path, json=body, headers={"Origin": "https://evil.example"}
                ).status_code
                == 403
            )
        assert owner.put(assignment_path, headers={"Origin": ORIGIN}).status_code == 204
        assert member.get(root).status_code == 200
        assert (
            owner.put(
                role_path, json={**payload, "permissions": []}, headers={"Origin": ORIGIN}
            ).status_code
            == 200
        )
        assert member.get(root).status_code == 403
        assert owner.delete(assignment_path, headers={"Origin": ORIGIN}).status_code == 204
        assert owner.delete(role_path, headers={"Origin": ORIGIN}).status_code == 204
        assert (
            owner.delete(root + f"/roles/{env.owner_role}", headers={"Origin": ORIGIN}).status_code
            == 409
        )


def test_organization_archive_is_internal_and_hides_access(identity_session, setup):
    identity.archive_organization(identity_session, organization_id=setup.org)
    assert access.list_organizations(identity_session, actor_id=setup.owner) == []
    with pytest.raises(Inaccessible):
        access.read_organization(identity_session, organization_id=setup.org, actor_id=setup.owner)


def test_duplicate_assignment_is_idempotent_and_audited_once(identity_session, setup):
    role = create(identity_session, setup, "Read only", ["core.organization.read"])
    assign(identity_session, setup, role)
    assign(identity_session, setup, role)
    with identity_session.begin():
        assert (
            identity_session.scalar(
                select(func.count())
                .select_from(RoleAudit)
                .where(RoleAudit.target_id == role, RoleAudit.action == "assignment.added")
            )
            == 1
        )
        assert (
            identity_session.scalar(
                select(func.count())
                .select_from(MembershipRole)
                .where(MembershipRole.role_id == role)
            )
            == 1
        )


def test_http_foreign_role_and_member_are_non_disclosing(
    identity_session, setup, clients, integration_settings
):
    other = bootstrap(
        identity_session,
        settings=integration_settings,
        email="owner@example.test",
        slug="other",
        name="Other",
    )
    with identity_session.begin():
        role = identity_session.scalar(select(Role.id).where(Role.organization_id == other))
        member = identity_session.scalar(
            select(Membership.id).where(Membership.organization_id == other)
        )
    with clients() as owner, clients("member@example.test") as restricted:
        root = f"/organizations/{setup.org}"
        expected = {"detail": "Resource not found."}
        for response in [
            restricted.get(f"/organizations/{other}"),
            owner.delete(root + f"/roles/{role}", headers={"Origin": ORIGIN}),
            owner.put(
                root + f"/members/{member}/roles/{setup.owner_role}", headers={"Origin": ORIGIN}
            ),
            owner.put(
                root + f"/roles/{role}",
                headers={"Origin": ORIGIN},
                json={"name": "Foreign", "permissions": []},
            ),
        ]:
            assert response.status_code == 404
            assert response.json() == expected
    with pytest.raises(IntegrityError), identity_session.begin():
        identity_session.add(
            RolePermission(organization_id=setup.org, role_id=role, code="core.members.read")
        )
        identity_session.flush()


def test_bootstrap_requires_local_mode_and_preserves_archived_org(
    identity_session, setup, integration_settings
):
    with pytest.raises(ValueError):
        bootstrap(
            identity_session,
            settings=integration_settings.model_copy(update={"environment": "production"}),
            email="owner@example.test",
            slug="new",
            name="New",
        )
    identity.archive_organization(identity_session, organization_id=setup.org)
    with pytest.raises(Conflict):
        bootstrap(
            identity_session,
            settings=integration_settings,
            email="owner@example.test",
            slug="demo",
            name="Demo",
        )
    with identity_session.begin():
        assert identity_session.get(Organization, setup.org).deleted_at is not None


def test_membership_archive_without_actor_cannot_bypass_role_checks(identity_session, setup):
    with pytest.raises(AccessError):
        identity.archive_membership(
            identity_session, organization_id=setup.org, membership_id=setup.owner_member
        )
    with identity_session.begin():
        assert identity_session.get(Membership, setup.owner_member).deleted_at is None
        assert repo.has_administrator(identity_session, setup.org)


def test_member_read_contract_requires_permission_and_is_non_disclosing(
    identity_session, setup, integration_settings
):
    env = setup
    with pytest.raises(AccessError):
        access.list_members(
            identity_session,
            organization_id=env.org,
            actor_id=env.user,
        )
    with pytest.raises(AccessError):
        access.read_member(
            identity_session,
            organization_id=env.org,
            actor_id=env.user,
            membership_id=env.member,
        )
    reader = create(identity_session, env, "Member reader", ["core.members.read"])
    assign(identity_session, env, reader)
    detail = access.read_member(
        identity_session,
        organization_id=env.org,
        actor_id=env.user,
        membership_id=env.member,
    )
    assert detail == {
        "membership_id": env.member,
        "user_id": env.user,
        "display_name": "Member",
        "email": "member@example.test",
        "state": "active",
        "roles": [
            {
                "id": reader,
                "name": "Member reader",
                "permissions": [{"code": "core.members.read", "can_grant": False}],
            }
        ],
    }
    other = bootstrap(
        identity_session,
        settings=integration_settings,
        email="owner@example.test",
        slug="member-read-other",
        name="Other",
    )
    with identity_session.begin():
        foreign_member = identity_session.scalar(
            select(Membership.id).where(Membership.organization_id == other)
        )
    with pytest.raises(Inaccessible):
        access.read_member(
            identity_session,
            organization_id=env.org,
            actor_id=env.owner,
            membership_id=foreign_member,
        )


def test_add_duplicate_archive_restore_and_audit(identity_session, setup):
    env = setup
    user = identity.create_user(
        identity_session, email="employee@example.test", display_name="Employee"
    )
    role = create(identity_session, env, "Employee reader", ["core.organization.read"])
    added = access.add_member(
        identity_session,
        organization_id=env.org,
        actor_id=env.owner,
        user_id=user,
        role_ids=[role],
    )
    membership_id = added["membership_id"]
    assert added["state"] == "active"
    assert [item["id"] for item in added["roles"]] == [role]
    duplicate = access.add_member(
        identity_session,
        organization_id=env.org,
        actor_id=env.owner,
        user_id=user,
        role_ids=[role],
    )
    assert duplicate == added
    with identity_session.begin():
        assert (
            identity_session.scalar(
                select(func.count())
                .select_from(Membership)
                .where(Membership.organization_id == env.org, Membership.user_id == user)
            )
            == 1
        )
        assert (
            identity_session.scalar(
                select(func.count())
                .select_from(RoleAudit)
                .where(
                    RoleAudit.membership_id == membership_id,
                    RoleAudit.action == "member.added",
                )
            )
            == 1
        )
    access.archive_member(
        identity_session,
        organization_id=env.org,
        actor_id=env.owner,
        membership_id=membership_id,
    )
    archived = access.read_member(
        identity_session,
        organization_id=env.org,
        actor_id=env.owner,
        membership_id=membership_id,
    )
    assert archived["state"] == "archived" and archived["roles"] == []
    restored = access.restore_member(
        identity_session,
        organization_id=env.org,
        actor_id=env.owner,
        membership_id=membership_id,
    )
    assert restored["membership_id"] == membership_id
    assert restored["state"] == "active" and restored["roles"] == []
    with identity_session.begin():
        events = list(
            identity_session.scalars(
                select(RoleAudit.action).where(RoleAudit.membership_id == membership_id)
            )
        )
        assert sorted(events) == sorted(
            [
                "member.added",
                "assignment.added",
                "assignment.removed",
                "member.archived",
                "member.restored",
            ]
        )
        assert identity_session.get(User, user).is_active is True


def test_member_manage_permission_and_initial_role_grant_ceiling(identity_session, setup):
    env = setup
    manager_user = identity.create_user(
        identity_session, email="manager@example.test", display_name="Manager"
    )
    manager_member = identity.add_membership(
        identity_session, organization_id=env.org, user_id=manager_user
    )
    manager_role = access.create_role(
        identity_session,
        organization_id=env.org,
        actor_id=env.owner,
        name="Member manager",
        permissions={"core.members.manage": False, "core.roles.assign": False},
    )["id"]
    assign(identity_session, env, manager_role, manager_member)
    target = identity.create_user(
        identity_session, email="managed@example.test", display_name="Managed"
    )
    with pytest.raises(AccessError):
        access.add_member(
            identity_session,
            organization_id=env.org,
            actor_id=env.user,
            user_id=target,
        )
    weak = create(identity_session, env, "Weak role", ["core.organization.read"])
    with pytest.raises(AccessError):
        access.add_member(
            identity_session,
            organization_id=env.org,
            actor_id=manager_user,
            user_id=target,
            role_ids=[weak],
        )
    with identity_session.begin():
        assert (
            identity_session.scalar(
                select(Membership.id).where(
                    Membership.organization_id == env.org, Membership.user_id == target
                )
            )
            is None
        )
    result = access.add_member(
        identity_session,
        organization_id=env.org,
        actor_id=manager_user,
        user_id=target,
    )
    assert result["roles"] == []


def test_initial_roles_reject_foreign_role_and_roll_back_restore(
    identity_session, setup, integration_settings
):
    env = setup
    target = identity.create_user(
        identity_session, email="atomic@example.test", display_name="Atomic"
    )
    other = bootstrap(
        identity_session,
        settings=integration_settings,
        email="owner@example.test",
        slug="atomic-other",
        name="Atomic other",
    )
    with identity_session.begin():
        foreign_role = identity_session.scalar(select(Role.id).where(Role.organization_id == other))
    with pytest.raises(Inaccessible):
        access.add_member(
            identity_session,
            organization_id=env.org,
            actor_id=env.owner,
            user_id=target,
            role_ids=[foreign_role],
        )
    with identity_session.begin():
        assert (
            identity_session.scalar(
                select(Membership.id).where(
                    Membership.organization_id == env.org, Membership.user_id == target
                )
            )
            is None
        )
    membership = access.add_member(
        identity_session,
        organization_id=env.org,
        actor_id=env.owner,
        user_id=target,
    )["membership_id"]
    access.archive_member(
        identity_session,
        organization_id=env.org,
        actor_id=env.owner,
        membership_id=membership,
    )
    with pytest.raises(Inaccessible):
        access.restore_member(
            identity_session,
            organization_id=env.org,
            actor_id=env.owner,
            membership_id=membership,
            role_ids=[foreign_role],
        )
    with identity_session.begin():
        assert identity_session.get(Membership, membership).deleted_at is not None


def test_archive_immediately_revokes_only_one_organization(
    identity_session, setup, clients, integration_settings
):
    env = setup
    access.change_assignment(
        identity_session,
        organization_id=env.org,
        actor_id=env.owner,
        membership_id=env.member,
        role_id=create(identity_session, env, "Organization reader", ["core.organization.read"]),
    )
    other = bootstrap(
        identity_session,
        settings=integration_settings,
        email="member@example.test",
        slug="shared-user-other",
        name="Shared user other",
    )
    with clients("member@example.test") as client:
        assert client.get(f"/organizations/{env.org}").status_code == 200
        assert client.get(f"/organizations/{other}").status_code == 200
        access.archive_member(
            identity_session,
            organization_id=env.org,
            actor_id=env.owner,
            membership_id=env.member,
        )
        assert client.get(f"/organizations/{env.org}").status_code == 404
        assert client.get(f"/organizations/{other}").status_code == 200
    with identity_session.begin():
        assert identity_session.get(User, env.user).is_active is True


def test_last_administrator_membership_cannot_be_archived(identity_session, setup):
    with pytest.raises(LastAdministrator):
        access.archive_member(
            identity_session,
            organization_id=setup.org,
            actor_id=setup.owner,
            membership_id=setup.owner_member,
        )
    with identity_session.begin():
        assert identity_session.get(Membership, setup.owner_member).deleted_at is None
        assert repo.has_administrator(identity_session, setup.org)


def test_member_http_lifecycle_statuses_and_global_update_boundary(
    identity_session, setup, clients
):
    env = setup
    target = identity.create_user(
        identity_session, email="http-employee@example.test", display_name="HTTP Employee"
    )
    root = f"/organizations/{env.org}/members"
    with clients() as owner:
        add = owner.post(root, json={"user_id": str(target)}, headers={"Origin": ORIGIN})
        assert add.status_code == 200
        membership = add.json()["membership_id"]
        assert owner.get(f"{root}/{membership}").status_code == 200
        assert (
            owner.post(
                root,
                json={"user_id": str(target), "is_active": False},
                headers={"Origin": ORIGIN},
            ).status_code
            == 422
        )
        assert owner.delete(f"{root}/{membership}", headers={"Origin": ORIGIN}).status_code == 204
        assert owner.get(f"{root}/{membership}").json()["state"] == "archived"
        restore = owner.post(f"{root}/{membership}/restore", json={}, headers={"Origin": ORIGIN})
        assert restore.status_code == 200
        assert restore.json()["membership_id"] == membership
    with identity_session.begin():
        assert identity_session.get(User, target).is_active is True


def test_member_audit_failure_rolls_back_membership(identity_session, setup):
    target = identity.create_user(
        identity_session, email="audit-rollback@example.test", display_name="Audit rollback"
    )
    original = repo.member_audit

    def fail(*args, **kwargs):
        original(*args, **kwargs)
        raise IntegrityError("hidden", {}, Exception("hidden"))

    with patch.object(repo, "member_audit", side_effect=fail), pytest.raises(StorageUnavailable):
        access.add_member(
            identity_session,
            organization_id=setup.org,
            actor_id=setup.owner,
            user_id=target,
        )
    with identity_session.begin():
        assert (
            identity_session.scalar(
                select(Membership.id).where(
                    Membership.organization_id == setup.org, Membership.user_id == target
                )
            )
            is None
        )
