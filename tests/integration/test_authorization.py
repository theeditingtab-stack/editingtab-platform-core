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
from editingtab_core.authorization.models import MembershipRole, Role, RoleAudit, RolePermission
from editingtab_core.authorization.policy import (
    MANAGE,
    OWNER_PERMISSIONS,
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
    limited = create(identity_session, env, "Limited manager", [MANAGE])
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
    access.update_role(
        identity_session,
        organization_id=env.org,
        actor_id=env.owner,
        role_id=env.owner_role,
        name="Owner",
        codes=[MANAGE],
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
        assert repo.effective_permissions(identity_session, env.org, env.owner) == {MANAGE}
        event = identity_session.scalar(select(RoleAudit).where(RoleAudit.action == "role.updated"))
        assert set(event.permissions_before) == OWNER_PERMISSIONS
        assert event.permissions_after == [MANAGE]
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
        assert all(set(profile) == {"id", "user_id", "display_name"} for profile in profiles)
        payload = {"name": "HTTP Reader", "permissions": ["core.organization.read"]}
        assert owner.post(root + "/roles", json=payload).status_code == 403
        role = owner.post(root + "/roles", json=payload, headers={"Origin": ORIGIN})
        assert role.status_code == 201
        role_id = role.json()["id"]
        assert (
            owner.post(root + "/roles", json=payload, headers={"Origin": ORIGIN}).status_code == 409
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
