from contextlib import contextmanager
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import sessionmaker

from editingtab_core.app import create_app
from editingtab_core.auth import services as auth
from editingtab_core.auth.models import LoginSession
from editingtab_core.auth.provision import provision_user
from editingtab_core.auth.security import COOKIE_NAME, Passwords
from editingtab_core.authorization.models import MembershipRole, Role, RolePermission
from editingtab_core.identity import services as identity
from editingtab_core.identity.models import Membership, Organization, User
from editingtab_core.platform.models import ModuleEntitlement, PlatformAdminGrant

pytestmark = pytest.mark.integration
ORIGIN = "http://127.0.0.1:18080"
PASSWORD = "synthetic access context password"


@pytest.fixture
def context_env(identity_session, integration_settings):
    passwords = Passwords()
    user = provision_user(
        identity_session,
        settings=integration_settings,
        passwords=passwords,
        email="context@example.test",
        display_name="Context User",
        password=PASSWORD,
    )
    outsider = provision_user(
        identity_session,
        settings=integration_settings,
        passwords=passwords,
        email="outsider@example.test",
        display_name="Outsider",
        password=PASSWORD,
    )
    platform_only = provision_user(
        identity_session,
        settings=integration_settings,
        passwords=passwords,
        email="platform-only@example.test",
        display_name="Platform only",
        password=PASSWORD,
    )
    organizations = {
        slug: identity.create_organization(identity_session, name=name, slug=slug)
        for slug, name in (
            ("zebra", "Zebra"),
            ("alpha", "Alpha"),
            ("archived-membership", "Archived membership"),
            ("archived-organization", "Archived organization"),
            ("foreign", "Foreign"),
        )
    }
    memberships = {
        slug: identity.add_membership(
            identity_session, organization_id=organization_id, user_id=user
        )
        for slug, organization_id in organizations.items()
        if slug != "foreign"
    }
    foreign_membership = identity.add_membership(
        identity_session, organization_id=organizations["foreign"], user_id=outsider
    )

    with identity_session.begin():
        alpha_role = Role(
            organization_id=organizations["alpha"],
            name="Alpha reader",
            normalized_name="alpha reader",
        )
        zebra_role = Role(
            organization_id=organizations["alpha"],
            name="Zebra manager",
            normalized_name="zebra manager",
        )
        foreign_role = Role(
            organization_id=organizations["foreign"],
            name="Foreign secret role",
            normalized_name="foreign secret role",
        )
        identity_session.add_all((zebra_role, alpha_role, foreign_role))
        identity_session.flush()
        identity_session.add_all(
            (
                RolePermission(
                    organization_id=organizations["alpha"],
                    role_id=alpha_role.id,
                    code="core.members.read",
                ),
                RolePermission(
                    organization_id=organizations["alpha"],
                    role_id=zebra_role.id,
                    code="booking.inventory.manage",
                    can_grant=True,
                ),
                RolePermission(
                    organization_id=organizations["alpha"],
                    role_id=zebra_role.id,
                    code="core.organization.read",
                    can_grant=True,
                ),
                RolePermission(
                    organization_id=organizations["foreign"],
                    role_id=foreign_role.id,
                    code="core.roles.read",
                    can_grant=True,
                ),
                MembershipRole(
                    organization_id=organizations["alpha"],
                    membership_id=memberships["alpha"],
                    role_id=zebra_role.id,
                ),
                MembershipRole(
                    organization_id=organizations["alpha"],
                    membership_id=memberships["alpha"],
                    role_id=alpha_role.id,
                ),
                MembershipRole(
                    organization_id=organizations["foreign"],
                    membership_id=foreign_membership,
                    role_id=foreign_role.id,
                ),
                ModuleEntitlement(
                    organization_id=organizations["alpha"], module_code="booking", enabled=True
                ),
                ModuleEntitlement(
                    organization_id=organizations["alpha"], module_code="pos", enabled=False
                ),
                PlatformAdminGrant(user_id=user),
            )
        )
        now = identity_session.scalar(select(func.clock_timestamp()))
        identity_session.get(Membership, memberships["archived-membership"]).deleted_at = now
        identity_session.get(Organization, organizations["archived-organization"]).deleted_at = now

    return SimpleNamespace(
        user=user,
        outsider=outsider,
        platform_only=platform_only,
        organizations=organizations,
        memberships=memberships,
        alpha_role=alpha_role,
        zebra_role=zebra_role,
        passwords=passwords,
    )


@pytest.fixture
def clients(migration_connection, integration_settings):
    @contextmanager
    def make(email="context@example.test", password=PASSWORD, authenticated=True):
        settings = integration_settings.model_copy(update={"auth_allowed_origins": (ORIGIN,)})
        app = create_app(settings)
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
                        json={"email": email, "password": password},
                        headers={"Origin": ORIGIN},
                    ).status_code
                    == 204
                )
            yield client

    return make


def test_context_rejects_unauthenticated_request_and_disables_caching(clients):
    with clients(authenticated=False) as client:
        response = client.get("/auth/context")
        assert response.status_code == 401
        assert response.headers["cache-control"] == "no-store"


def test_context_is_stable_scoped_and_contains_only_effective_current_state(clients, context_env):
    with clients() as client:
        first = client.get("/auth/context")
        second = client.get("/auth/context")

    assert first.status_code == 200
    assert first.headers["cache-control"] == "no-store"
    assert first.json() == second.json()
    body = first.json()
    assert body["user"] == {
        "user_id": str(context_env.user),
        "email": "context@example.test",
        "display_name": "Context User",
    }
    assert body["is_platform_admin"] is True
    assert [organization["slug"] for organization in body["organizations"]] == [
        "alpha",
        "zebra",
    ]
    alpha, zebra = body["organizations"]
    assert alpha == {
        "organization_id": str(context_env.organizations["alpha"]),
        "name": "Alpha",
        "slug": "alpha",
        "membership_id": str(context_env.memberships["alpha"]),
        "roles": [
            {"role_id": str(context_env.alpha_role.id), "role_name": "Alpha reader"},
            {"role_id": str(context_env.zebra_role.id), "role_name": "Zebra manager"},
        ],
        "effective_permissions": [
            "booking.inventory.manage",
            "core.members.read",
            "core.organization.read",
        ],
        "effective_grant_authority": [
            "booking.inventory.manage",
            "core.organization.read",
        ],
        "enabled_modules": ["booking"],
    }
    assert zebra == {
        "organization_id": str(context_env.organizations["zebra"]),
        "name": "Zebra",
        "slug": "zebra",
        "membership_id": str(context_env.memberships["zebra"]),
        "roles": [],
        "effective_permissions": [],
        "effective_grant_authority": [],
        "enabled_modules": [],
    }
    serialized = first.text.lower()
    for forbidden in (
        "password",
        "session",
        "token",
        "digest",
        "foreign secret role",
        str(context_env.organizations["foreign"]),
    ):
        assert forbidden not in serialized


def test_role_archive_and_entitlement_revocation_are_immediate(
    clients, context_env, identity_session
):
    with clients() as client:
        assert len(client.get("/auth/context").json()["organizations"][0]["roles"]) == 2
        with identity_session.begin():
            context_env.zebra_role.deleted_at = identity_session.scalar(
                select(func.clock_timestamp())
            )
            entitlement = identity_session.get(
                ModuleEntitlement, (context_env.organizations["alpha"], "booking")
            )
            entitlement.enabled = False
        alpha = client.get("/auth/context").json()["organizations"][0]

    assert alpha["roles"] == [
        {"role_id": str(context_env.alpha_role.id), "role_name": "Alpha reader"}
    ]
    assert alpha["effective_permissions"] == ["core.members.read"]
    assert alpha["effective_grant_authority"] == []
    assert alpha["enabled_modules"] == []


def test_platform_admin_without_membership_has_no_tenant_context(
    clients, context_env, identity_session
):
    with identity_session.begin():
        identity_session.add(PlatformAdminGrant(user_id=context_env.platform_only))
    with clients(email="platform-only@example.test") as client:
        body = client.get("/auth/context").json()
    assert body["is_platform_admin"] is True
    assert body["organizations"] == []


def test_logout_selected_revocation_reset_and_inactive_user_invalidate_context(
    clients, context_env, identity_session, integration_settings
):
    with clients() as client:
        assert client.get("/auth/context").status_code == 200
        assert client.post("/auth/logout", headers={"Origin": ORIGIN}).status_code == 204
        assert client.get("/auth/context").status_code == 401

    with clients() as client:
        token = client.cookies.get(COOKIE_NAME)
        with identity_session.begin():
            session_id = identity_session.scalar(
                select(LoginSession.id).where(
                    LoginSession.user_id == context_env.user,
                    LoginSession.revoked_at.is_(None),
                )
            )
        assert auth.revoke_selected_session(identity_session, token, session_id) is True
        assert client.get("/auth/context").status_code == 401

    with clients() as client:
        reset_token = auth.request_password_reset(
            identity_session,
            settings=integration_settings,
            email="context@example.test",
            source="reset-test",
        )
        assert reset_token is not None
        auth.reset_password(
            identity_session,
            passwords=context_env.passwords,
            token=reset_token,
            password="new synthetic access context password",
        )
        assert client.get("/auth/context").status_code == 401

    with clients(password="new synthetic access context password") as client:
        assert client.get("/auth/context").status_code == 200
        with identity_session.begin():
            identity_session.get(User, context_env.user).is_active = False
        assert client.get("/auth/context").status_code == 401
