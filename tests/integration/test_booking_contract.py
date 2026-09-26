from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.orm import sessionmaker

from editingtab_core.app import create_app
from editingtab_core.auth import services as auth
from editingtab_core.auth.models import LoginSession
from editingtab_core.auth.provision import provision_user
from editingtab_core.auth.security import COOKIE_NAME, Passwords, token_digest
from editingtab_core.authorization import repository as repo
from editingtab_core.authorization import services as access
from editingtab_core.authorization.models import MembershipRole, Role, RoleAudit, RolePermission
from editingtab_core.authorization.policy import (
    BOOKING_PERMISSIONS,
    AccessError,
    Conflict,
    Inaccessible,
    StorageUnavailable,
)
from editingtab_core.identity import services as identity
from editingtab_core.identity.models import Membership, Organization, User
from editingtab_core.internal.booking import PATH
from editingtab_core.platform import services as platform
from editingtab_core.platform.booking_permissions import LEGACY_ROLE_NAME, ROLE_NAME, provision
from editingtab_core.platform.models import PlatformAudit

pytestmark = pytest.mark.integration
ORIGIN = "http://127.0.0.1:18080"
PASSWORD = "synthetic integration password"
CURRENT = "current-test-only-" + "c" * 32
PREVIOUS = "previous-test-only-" + "p" * 32
READ = "booking.inventory.read"


@pytest.fixture
def env(identity_session, integration_settings):
    s = identity_session
    passwords = Passwords()
    ids = {}
    for name in ("operator", "owner", "ordinary"):
        ids[name] = provision_user(
            s,
            settings=integration_settings,
            passwords=passwords,
            email=f"{name}@example.test",
            display_name=name,
            password=PASSWORD,
        )
    platform.bootstrap_initial(s, email="operator@example.test")
    org = platform.onboard(
        s,
        actor_id=ids["operator"],
        name="Client",
        slug="client",
        owner_email="owner@example.test",
        enabled_modules=["booking"],
    )["id"]
    ordinary_member = identity.add_membership(s, organization_id=org, user_id=ids["ordinary"])
    with s.begin():
        member = s.scalar(
            select(Membership.id).where(
                Membership.organization_id == org, Membership.user_id == ids["owner"]
            )
        )
    tokens = {
        name: auth.login(
            s,
            settings=integration_settings,
            passwords=passwords,
            email=f"{name}@example.test",
            password=PASSWORD,
            source="127.0.0.1",
        )
        for name in ids
    }
    return SimpleNamespace(
        **ids,
        org=org,
        member=member,
        ordinary_member=ordinary_member,
        tokens=tokens,
        passwords=passwords,
    )


@pytest.fixture
def clients(migration_connection, integration_settings):
    @contextmanager
    def make(configured=True):
        settings = integration_settings.model_copy(
            update={
                "auth_allowed_origins": (ORIGIN,),
                "booking_service_current_digest": SecretStr(sha256(CURRENT.encode()).hexdigest())
                if configured
                else None,
                "booking_service_previous_digest": SecretStr(sha256(PREVIOUS.encode()).hexdigest()),
            }
        )
        app = create_app(settings)
        with TestClient(app, base_url=ORIGIN, client=("127.0.0.1", 40000)) as client:
            app.state.session_factory = sessionmaker(
                bind=migration_connection,
                join_transaction_mode="create_savepoint",
                expire_on_commit=False,
            )
            yield client

    return make


def grant(s, e):
    return provision(s, actor_id=e.operator, organization_id=e.org, membership_id=e.member)


def request(client, e, *, service=CURRENT, token=None, body=None):
    headers = {"X-Core-Session": token or e.tokens["owner"]}
    if service is not None:
        headers["Authorization"] = "Bearer " + service
    response = client.post(
        PATH,
        headers=headers,
        json=body if body is not None else {"organization_id": str(e.org), "permission": READ},
    )
    assert response.headers["cache-control"] == "no-store"
    for value in (CURRENT, PREVIOUS, *e.tokens.values()):
        assert value not in response.text
    return response


def error(response, status, code):
    assert response.status_code == status
    assert response.json() == {"error": code}


@pytest.mark.parametrize("service", [None, "wrong" * 12, "x" * 10000])
def test_service_first_no_user_or_tenant_reads(identity_session, env, clients, service):
    with (
        clients() as client,
        patch("editingtab_core.internal.booking.auth_repo.authenticated_user") as lookup,
    ):
        error(
            request(client, env, service=service, body={"bad": "input"}),
            401,
            "invalid_service_credentials",
        )
        lookup.assert_not_called()


def test_cookie_only_and_missing_configuration(identity_session, env, clients):
    with clients() as client:
        client.cookies.set(COOKIE_NAME, env.tokens["owner"])
        error(
            client.post(PATH, json={"organization_id": str(env.org), "permission": READ}),
            401,
            "invalid_service_credentials",
        )
        error(
            client.post(PATH, headers={"Authorization": "Bearer " + CURRENT}, json={}),
            401,
            "invalid_user_session",
        )
    with clients(False) as client:
        error(request(client, env, service=PREVIOUS), 401, "invalid_service_credentials")
        assert client.get("/health/live").status_code == 200


@pytest.mark.parametrize("service", [CURRENT, PREVIOUS])
def test_success_minimal_response_both_rotation_slots(identity_session, env, clients, service):
    grant(identity_session, env)
    with clients() as client:
        response = request(client, env, service=service)
        assert response.status_code == 200
        assert response.json() == {
            "allowed": True,
            "user_id": str(env.owner),
            "membership_id": str(env.member),
            "organization_id": str(env.org),
            "permission": READ,
        }


@pytest.mark.parametrize("state", ["invalid", "expired", "revoked", "inactive", "archived_user"])
def test_session_and_user_denials(identity_session, env, clients, state):
    token = env.tokens["owner"]
    with identity_session.begin():
        if state in ("expired", "revoked"):
            row = identity_session.scalar(
                select(LoginSession).where(LoginSession.token_digest == token_digest(token))
            )
            if state == "expired":
                row.created_at = datetime.now(UTC) - timedelta(days=2)
                row.expires_at = datetime.now(UTC) - timedelta(days=1)
            else:
                row.revoked_at = datetime.now(UTC)
        elif state == "inactive":
            identity_session.get(User, env.owner).is_active = False
        elif state == "archived_user":
            identity_session.get(User, env.owner).deleted_at = datetime.now(UTC)
    with clients() as client:
        error(
            request(client, env, token="invalid" if state == "invalid" else token),
            401,
            "invalid_user_session",
        )


@pytest.mark.parametrize("state", ["organization", "membership", "foreign", "platform_only"])
def test_tenant_isolation(identity_session, env, clients, state):
    grant(identity_session, env)
    org = env.org
    with identity_session.begin():
        if state == "organization":
            identity_session.get(Organization, env.org).deleted_at = datetime.now(UTC)
        elif state == "membership":
            identity_session.get(Membership, env.member).deleted_at = datetime.now(UTC)
    if state == "foreign":
        org = platform.onboard(
            identity_session,
            actor_id=env.operator,
            name="Other",
            slug="other",
            owner_email="ordinary@example.test",
            enabled_modules=["booking"],
        )["id"]
    with clients() as client:
        error(
            request(
                client,
                env,
                token=env.tokens["operator"] if state == "platform_only" else None,
                body={"organization_id": str(org), "permission": READ},
            ),
            404,
            "organization_not_accessible",
        )


def test_permission_entitlement_and_revocation_without_relogin(identity_session, env, clients):
    with clients() as client:
        error(request(client, env), 403, "permission_denied")
        role = grant(identity_session, env)["role_id"]
        assert request(client, env).status_code == 200
        platform.set_entitlement(
            identity_session,
            actor_id=env.operator,
            organization_id=env.org,
            module_code="booking",
            enabled=False,
        )
        error(request(client, env), 403, "module_disabled")
        platform.set_entitlement(
            identity_session,
            actor_id=env.operator,
            organization_id=env.org,
            module_code="booking",
            enabled=True,
        )
        assert request(client, env).status_code == 200
        with pytest.raises(AccessError):
            access.change_assignment(
                identity_session,
                organization_id=env.org,
                actor_id=env.owner,
                membership_id=env.member,
                role_id=role,
                remove=True,
            )
        with identity_session.begin():
            identity_session.delete(
                identity_session.get(MembershipRole, (env.org, env.member, role))
            )
        error(request(client, env), 403, "permission_denied")
        grant(identity_session, env)
        auth.logout(identity_session, env.tokens["owner"])
        error(request(client, env), 401, "invalid_user_session")


@pytest.mark.parametrize("permission", sorted(BOOKING_PERMISSIONS))
def test_every_booking_permission_can_be_authorized(identity_session, env, clients, permission):
    grant(identity_session, env)
    with clients() as client:
        response = request(
            client,
            env,
            body={"organization_id": str(env.org), "permission": permission},
        )
        assert response.status_code == 200
        assert response.json()["permission"] == permission


@pytest.mark.parametrize(
    "change",
    [
        {"permission": "core.roles.manage"},
        {"permission": "platform.admin"},
        {"permission": "booking.unknown"},
        {"actor_id": "forged"},
        {"organization_id": "bad"},
        {"permission": {"secret": CURRENT}},
    ],
)
def test_request_validation_never_echoes_credentials(identity_session, env, clients, change):
    with clients() as client:
        error(
            request(
                client, env, body={"organization_id": str(env.org), "permission": READ, **change}
            ),
            422,
            "invalid_authorization_request",
        )


def test_database_failure_is_unavailable_not_denial_or_allow(identity_session, env, clients):
    with (
        clients() as client,
        patch(
            "editingtab_core.internal.booking.auth_repo.authenticated_user",
            side_effect=OperationalError("private", {}, Exception("hidden")),
        ),
    ):
        error(request(client, env), 503, "authorization_unavailable")


def test_provisioning_idempotent_audit_and_no_tenant_delegation(identity_session, env):
    result = grant(identity_session, env)
    with identity_session.begin():
        audit = identity_session.scalar(
            select(PlatformAudit).where(PlatformAudit.action == "booking.permissions.provisioned")
        )
        assert audit.actor_id == env.operator and audit.target_id == env.member
        assert audit.before == {"assigned": False, "permissions": []}
        assert {item["code"] for item in audit.after["permissions"]} == (BOOKING_PERMISSIONS)
        assert all(not item["can_grant"] for item in audit.after["permissions"])
        count = identity_session.scalar(select(func.count()).select_from(RoleAudit))
    assert grant(identity_session, env) == result
    with identity_session.begin():
        assert identity_session.scalar(select(func.count()).select_from(RoleAudit)) == count
        assert (
            identity_session.scalar(
                select(func.count())
                .select_from(PlatformAudit)
                .where(PlatformAudit.action == "booking.permissions.provisioned")
            )
            == 1
        )
    with identity_session.begin():
        assert READ in repo.effective_permissions(identity_session, env.org, env.owner)
        assert READ not in repo.effective_grant_authority(identity_session, env.org, env.owner)
    with pytest.raises(AccessError):
        access.create_role(
            identity_session,
            organization_id=env.org,
            actor_id=env.owner,
            name="Booking reader",
            codes=[READ],
        )


@pytest.mark.parametrize(
    "case",
    ["tenant_actor", "foreign_member", "no_manage", "disabled", "collision", "archived_member"],
)
def test_provisioning_boundaries(identity_session, env, case):
    actor, member = env.operator, env.member
    expected = AccessError
    if case == "tenant_actor":
        actor = env.owner
    elif case == "foreign_member":
        foreign_org = platform.onboard(
            identity_session,
            actor_id=env.operator,
            name="Other",
            slug="other",
            owner_email="ordinary@example.test",
            enabled_modules=["booking"],
        )["id"]
        with identity_session.begin():
            member = identity_session.scalar(
                select(Membership.id).where(Membership.organization_id == foreign_org)
            )
        expected = Inaccessible
    elif case == "no_manage":
        member = env.ordinary_member
    elif case == "disabled":
        platform.set_entitlement(
            identity_session,
            actor_id=env.operator,
            organization_id=env.org,
            module_code="booking",
            enabled=False,
        )
    elif case == "collision":
        access.create_role(
            identity_session, organization_id=env.org, actor_id=env.owner, name=ROLE_NAME, codes=[]
        )
        expected = Conflict
    else:
        with identity_session.begin():
            identity_session.get(Membership, env.member).deleted_at = datetime.now(UTC)
        expected = Inaccessible
    with pytest.raises(expected):
        provision(identity_session, actor_id=actor, organization_id=env.org, membership_id=member)
    with identity_session.begin():
        assert (
            identity_session.scalar(
                select(func.count())
                .select_from(PlatformAudit)
                .where(PlatformAudit.action == "booking.permissions.provisioned")
            )
            == 0
        )


def test_provisioning_atomic_failure_and_designated_role_collision(identity_session, env):
    with patch(
        "editingtab_core.platform.booking_permissions._audit",
        side_effect=IntegrityError("private", {}, Exception("hidden")),
    ):
        with pytest.raises(StorageUnavailable):
            grant(identity_session, env)
    with identity_session.begin():
        assert (
            identity_session.scalar(
                select(Role.id).where(Role.provisioning_kind == "booking_inventory")
            )
            is None
        )
    role = grant(identity_session, env)["role_id"]
    with identity_session.begin():
        identity_session.add(
            RolePermission(
                organization_id=env.org,
                role_id=role,
                code="core.organization.read",
                can_grant=False,
            )
        )
    with pytest.raises(Conflict):
        grant(identity_session, env)


def test_browser_origin_remains_required_for_explicit_provisioning(identity_session, env, clients):
    path = f"/platform/organizations/{env.org}/booking-inventory-administrator"
    with clients() as client:
        client.cookies.set(COOKIE_NAME, env.tokens["operator"])
        body = {"membership_id": str(env.member)}
        assert client.post(path, json=body).status_code == 403
        assert (
            client.post(path, json=body, headers={"Origin": "https://evil.test"}).status_code == 403
        )
        assert (
            client.post(
                path, json={**body, "actor_id": str(env.owner)}, headers={"Origin": ORIGIN}
            ).status_code
            == 422
        )
        assert client.post(path, json=body, headers={"Origin": ORIGIN}).status_code == 200
        assert request(client, env).status_code == 200


@pytest.mark.parametrize("state", ["renamed", "archived"])
def test_designated_role_is_not_silently_restored_or_repurposed(identity_session, env, state):
    role = grant(identity_session, env)["role_id"]
    with identity_session.begin():
        designated = identity_session.get(Role, role)
        if state == "renamed":
            designated.name = "Tenant repurposed"
            designated.normalized_name = "tenant repurposed"
        else:
            designated.deleted_at = datetime.now(UTC)
    with pytest.raises(Conflict):
        grant(identity_session, env)


def test_explicit_reprovision_can_restore_only_designated_booking_permissions(
    identity_session, env
):
    role = grant(identity_session, env)["role_id"]
    with identity_session.begin():
        repo.replace_permissions(identity_session, env.org, role, {READ: False})
    grant(identity_session, env)
    with identity_session.begin():
        assert repo.role_permissions(identity_session, env.org, role) == BOOKING_PERMISSIONS
        audits = identity_session.scalars(
            select(PlatformAudit).where(PlatformAudit.action == "booking.permissions.provisioned")
        ).all()
        assert len(audits) == 2
        assert any(
            row.before
            == {
                "assigned": True,
                "permissions": [{"code": READ, "can_grant": False}],
            }
            for row in audits
        )


def test_provisioning_preserves_custom_roles_and_adds_no_core_permissions(identity_session, env):
    with identity_session.begin():
        custom = Role(
            organization_id=env.org,
            name="Custom Booking reader",
            normalized_name="custom booking reader",
        )
        identity_session.add(custom)
        identity_session.flush()
        repo.replace_permissions(
            identity_session,
            env.org,
            custom.id,
            {"booking.reservations.read": False, "core.organization.read": False},
        )
        before = repo.role_permission_grants(identity_session, env.org, custom.id)
    result = grant(identity_session, env)
    with identity_session.begin():
        assert repo.role_permission_grants(identity_session, env.org, custom.id) == before
        provisioned = repo.role_permission_grants(identity_session, env.org, result["role_id"])
        assert set(provisioned) == BOOKING_PERMISSIONS
        assert not any(provisioned.values())
        assert not any(code.startswith("core.") for code in provisioned)


def test_explicit_reprovision_evolves_legacy_dedicated_role(identity_session, env):
    with identity_session.begin():
        legacy = Role(
            organization_id=env.org,
            name=LEGACY_ROLE_NAME,
            normalized_name=LEGACY_ROLE_NAME.lower(),
            provisioning_kind="booking_inventory",
        )
        identity_session.add(legacy)
        identity_session.flush()
        repo.replace_permissions(identity_session, env.org, legacy.id, {READ: False})
    result = grant(identity_session, env)
    with identity_session.begin():
        evolved = identity_session.get(Role, result["role_id"])
        assert evolved.id == legacy.id
        assert evolved.name == ROLE_NAME
        assert repo.role_permissions(identity_session, env.org, evolved.id) == BOOKING_PERMISSIONS
        audit = identity_session.scalar(
            select(PlatformAudit).where(PlatformAudit.action == "booking.permissions.provisioned")
        )
        assert audit.before["role_name"] == LEGACY_ROLE_NAME
        assert audit.after["role_name"] == ROLE_NAME


def test_same_user_multi_org_authorization_is_independent(identity_session, env, clients):
    other = platform.onboard(
        identity_session,
        actor_id=env.operator,
        name="Second client",
        slug="second-client",
        owner_email="owner@example.test",
        enabled_modules=["booking"],
    )["id"]
    with identity_session.begin():
        other_member = identity_session.scalar(
            select(Membership.id).where(
                Membership.organization_id == other, Membership.user_id == env.owner
            )
        )
    grant(identity_session, env)
    with clients() as client:
        assert request(client, env).status_code == 200
        error(
            request(
                client,
                env,
                body={"organization_id": str(other), "permission": READ},
            ),
            403,
            "permission_denied",
        )
        provision(
            identity_session,
            actor_id=env.operator,
            organization_id=other,
            membership_id=other_member,
        )
        response = request(
            client,
            env,
            body={"organization_id": str(other), "permission": READ},
        )
        assert response.status_code == 200
        assert response.json()["membership_id"] == str(other_member)


def test_entitlement_from_another_organization_never_applies(identity_session, env, clients):
    other = platform.onboard(
        identity_session,
        actor_id=env.operator,
        name="No Booking entitlement",
        slug="no-booking-entitlement",
        owner_email="owner@example.test",
        enabled_modules=[],
    )["id"]
    with identity_session.begin():
        other_member = identity_session.scalar(
            select(Membership.id).where(
                Membership.organization_id == other, Membership.user_id == env.owner
            )
        )
        role = Role(
            organization_id=other,
            name="Existing Booking reader",
            normalized_name="existing booking reader",
        )
        identity_session.add(role)
        identity_session.flush()
        identity_session.add_all(
            (
                RolePermission(
                    organization_id=other,
                    role_id=role.id,
                    code=READ,
                    can_grant=False,
                ),
                MembershipRole(
                    organization_id=other,
                    membership_id=other_member,
                    role_id=role.id,
                ),
            )
        )
    with clients() as client:
        error(
            request(
                client,
                env,
                body={"organization_id": str(other), "permission": READ},
            ),
            403,
            "module_disabled",
        )


def test_selected_revocation_and_password_reset_invalidate_authorization(
    identity_session, env, clients, integration_settings
):
    grant(identity_session, env)
    token = env.tokens["owner"]
    with identity_session.begin():
        session_id = identity_session.scalar(
            select(LoginSession.id).where(LoginSession.token_digest == token_digest(token))
        )
    assert auth.revoke_selected_session(identity_session, token, session_id) is True
    with clients() as client:
        error(request(client, env, token=token), 401, "invalid_user_session")

    fresh = auth.login(
        identity_session,
        settings=integration_settings,
        passwords=env.passwords,
        email="owner@example.test",
        password=PASSWORD,
        source="127.0.0.2",
    )
    reset = auth.request_password_reset(
        identity_session,
        settings=integration_settings,
        email="owner@example.test",
        source="booking-reset-test",
    )
    assert reset is not None
    auth.reset_password(
        identity_session,
        passwords=env.passwords,
        token=reset,
        password="new synthetic booking authorization password",
    )
    with clients() as client:
        error(request(client, env, token=fresh), 401, "invalid_user_session")


def test_access_context_and_authoritative_decision_share_current_state(
    identity_session, env, clients
):
    grant(identity_session, env)
    context = auth.access_context(identity_session, env.tokens["owner"])
    organization = next(
        item for item in context["organizations"] if item["organization_id"] == env.org
    )
    assert READ in organization["effective_permissions"]
    assert "booking" in organization["enabled_modules"]
    with clients() as client:
        assert request(client, env).status_code == 200
        platform.set_entitlement(
            identity_session,
            actor_id=env.operator,
            organization_id=env.org,
            module_code="booking",
            enabled=False,
        )
        context = auth.access_context(identity_session, env.tokens["owner"])
        organization = next(
            item for item in context["organizations"] if item["organization_id"] == env.org
        )
        assert READ in organization["effective_permissions"]
        assert "booking" not in organization["enabled_modules"]
        error(request(client, env), 403, "module_disabled")
