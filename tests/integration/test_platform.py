"""Real database coverage; service commits run inside fixture-owned savepoints."""

from contextlib import contextmanager
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

from editingtab_core.app import create_app
from editingtab_core.auth.provision import provision_user
from editingtab_core.auth.security import Passwords
from editingtab_core.authorization import services as tenant
from editingtab_core.authorization.http import Actor, Database
from editingtab_core.authorization.models import MembershipRole, Role, RoleAudit, RolePermission
from editingtab_core.authorization.policy import (
    OWNER_PERMISSIONS,
    AccessError,
    Conflict,
    Inaccessible,
    StorageUnavailable,
)
from editingtab_core.identity import services as identity
from editingtab_core.identity.models import Membership, Organization, User
from editingtab_core.platform import services
from editingtab_core.platform.models import (
    BootstrapState,
    ModuleEntitlement,
    PlatformAdminGrant,
    PlatformAudit,
)

pytestmark = pytest.mark.integration
ORIGIN = "http://127.0.0.1:18080"
PASSWORD = "synthetic platform test password"


@pytest.fixture
def setup(identity_session, integration_settings):
    passwords = Passwords()
    ids = {}
    for name in ("operator", "owner", "ordinary"):
        ids[name] = provision_user(
            identity_session,
            settings=integration_settings,
            passwords=passwords,
            email=f"{name}@example.test",
            display_name=name,
            password=PASSWORD,
        )
    grant = services.bootstrap_initial(identity_session, email="OPERATOR@example.test")
    return SimpleNamespace(**ids, grant=grant)


def onboard(session, env, **changes):
    values = dict(
        actor_id=env.operator,
        name="Client",
        slug="client",
        owner_email="OWNER@example.test",
        enabled_modules=["booking"],
    )
    values.update(changes)
    return services.onboard(session, **values)


@pytest.fixture
def clients(migration_connection, integration_settings):
    @contextmanager
    def make(email="operator@example.test", authenticated=True):
        app = create_app(
            integration_settings.model_copy(update={"auth_allowed_origins": (ORIGIN,)})
        )

        # Test-only route proves the real guard composition; never installed in the application.
        @app.get("/organizations/{organization_id}/test-booking")
        def guarded(organization_id: str, session: Database, actor_id: Actor):
            from uuid import UUID

            org_id = UUID(organization_id)
            with tenant.transaction(session):
                tenant.authorize(session, org_id, actor_id, "core.organization.read")
                services.require_entitlement(session, organization_id=org_id, module_code="booking")
            return {"allowed": True}

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


def counts(session):
    with session.begin():
        return {
            model.__tablename__: session.scalar(select(func.count()).select_from(model))
            for model in (
                Organization,
                Membership,
                Role,
                RolePermission,
                MembershipRole,
                RoleAudit,
                ModuleEntitlement,
                PlatformAudit,
            )
        }


def test_atomic_onboarding_owner_permissions_and_actual_auditor(identity_session, setup):
    result = onboard(identity_session, setup)
    org = result["id"]
    assert result["slug"] == "client" and result["enabled_modules"] == ["booking"]
    assert (
        tenant.read_organization(identity_session, organization_id=org, actor_id=setup.owner)["id"]
        == org
    )
    roles = tenant.list_roles(identity_session, organization_id=org, actor_id=setup.owner)
    assert {permission["code"] for permission in roles[0]["permissions"]} == OWNER_PERMISSIONS
    assert all(permission["can_grant"] for permission in roles[0]["permissions"])
    with identity_session.begin():
        audits = identity_session.scalars(
            select(RoleAudit).where(RoleAudit.organization_id == org)
        ).all()
        assert len(audits) == 2 and all(row.actor_id == setup.operator for row in audits)
        audit = identity_session.scalar(
            select(PlatformAudit).where(PlatformAudit.organization_id == org)
        )
        assert audit.actor_id == setup.operator and audit.actor_kind == "authenticated_user"
        assert audit.before == {} and audit.after == {
            "owner_id": str(setup.owner),
            "enabled_modules": ["booking"],
        }
        assert audit.target_id == org and audit.created_at.tzinfo is not None
    # Platform authority is not membership and cannot access tenant APIs.
    with pytest.raises(Inaccessible):
        tenant.read_organization(identity_session, organization_id=org, actor_id=setup.operator)


def test_default_no_modules_duplicate_slug_and_archived_slug_preserved(identity_session, setup):
    org = onboard(identity_session, setup, enabled_modules=[])["id"]
    assert (
        services.tenant_entitlements(identity_session, actor_id=setup.owner, organization_id=org)[
            "enabled_modules"
        ]
        == []
    )
    before = counts(identity_session)
    for archived in (False, True):
        if archived:
            identity.archive_organization(identity_session, organization_id=org)
        with pytest.raises(Conflict):
            onboard(identity_session, setup)
        assert counts(identity_session) == before
    assert services.list_organizations(identity_session, actor_id=setup.operator) == []


@pytest.mark.parametrize("failure", ["audit", "owner_assignment"])
def test_mid_write_failure_rolls_back_everything_and_session_reusable(
    identity_session, setup, failure
):
    before = counts(identity_session)
    if failure == "audit":
        target = "editingtab_core.platform.services._audit"
    else:
        target = "editingtab_core.authorization.onboarding.repo.audit"
    with patch(target, side_effect=IntegrityError("hidden", {}, Exception("hidden"))):
        with pytest.raises(StorageUnavailable):
            onboard(identity_session, setup)
    assert counts(identity_session) == before
    assert onboard(identity_session, setup)["slug"] == "client"


@pytest.mark.parametrize("state", ["missing", "inactive", "archived", "credentialless"])
def test_owner_must_be_existing_active_credentialed(identity_session, setup, state):
    email = "owner@example.test"
    if state == "missing":
        email = "absent@example.test"
    elif state == "credentialless":
        email = "no-login@example.test"
        identity.create_user(identity_session, email=email, display_name="No login")
    else:
        with identity_session.begin():
            user = identity_session.get(User, setup.owner)
            if state == "inactive":
                user.is_active = False
            else:
                user.deleted_at = datetime.now(UTC)
    before = counts(identity_session)
    with pytest.raises(services.InvalidOnboarding):
        onboard(identity_session, setup, owner_email=email)
    assert counts(identity_session) == before


@pytest.mark.parametrize("module", ["unknown", "pos", "unified_inbox", "chatbot"])
def test_unknown_and_unsupported_activation_rejected(identity_session, setup, module):
    before = counts(identity_session)
    with pytest.raises(services.InvalidModule):
        onboard(identity_session, setup, enabled_modules=[module])
    assert counts(identity_session) == before
    org = onboard(identity_session, setup)["id"]
    with pytest.raises(services.InvalidModule):
        services.set_entitlement(
            identity_session,
            actor_id=setup.operator,
            organization_id=org,
            module_code=module,
            enabled=True,
        )


def test_noop_disable_enable_preserves_records_and_audits_actual_change(identity_session, setup):
    org = onboard(identity_session, setup)["id"]
    baseline = counts(identity_session)

    def update(code, enabled):
        return services.set_entitlement(
            identity_session,
            actor_id=setup.operator,
            organization_id=org,
            module_code=code,
            enabled=enabled,
        )

    update("booking", True)
    update("pos", False)
    assert counts(identity_session) == baseline
    assert update("booking", False)["enabled_modules"] == []
    after = counts(identity_session)
    assert after == {**baseline, "core_platform_audit": baseline["core_platform_audit"] + 1}
    update("booking", False)
    assert counts(identity_session) == after
    update("booking", True)
    with identity_session.begin():
        changes = identity_session.scalars(
            select(PlatformAudit)
            .where(PlatformAudit.action == "entitlement.changed")
            .order_by(PlatformAudit.created_at, PlatformAudit.id)
        ).all()
        assert len(changes) == 2
        assert all(row.actor_id == setup.operator and row.organization_id == org for row in changes)
        assert {row.before["enabled"] for row in changes} == {True, False}
        assert all(row.before["enabled"] != row.after["enabled"] for row in changes)


def test_entitlement_update_audit_failure_rolls_back(identity_session, setup):
    org = onboard(identity_session, setup)["id"]
    before = counts(identity_session)
    with patch(
        "editingtab_core.platform.services._audit",
        side_effect=IntegrityError("hidden", {}, Exception("hidden")),
    ):
        with pytest.raises(StorageUnavailable):
            services.set_entitlement(
                identity_session,
                actor_id=setup.operator,
                organization_id=org,
                module_code="booking",
                enabled=False,
            )
    assert counts(identity_session) == before
    assert services.read_entitlements(
        identity_session, actor_id=setup.operator, organization_id=org
    )["enabled_modules"] == ["booking"]


def test_bootstrap_audits_operator_and_never_reopens_after_revocation(identity_session, setup):
    with identity_session.begin():
        row = identity_session.get(PlatformAdminGrant, setup.grant)
        row.revoked_at = datetime.now(UTC)
        audit = identity_session.scalar(
            select(PlatformAudit).where(PlatformAudit.action == "operator.bootstrap")
        )
        assert audit.actor_id is None and audit.actor_kind == "operator_bootstrap"
        assert audit.target_id == setup.grant and audit.organization_id is None
        assert identity_session.get(BootstrapState, 1).completed_at is not None
    with pytest.raises(services.BootstrapClosed):
        services.bootstrap_initial(identity_session, email="owner@example.test")
    with identity_session.begin():
        assert identity_session.scalar(select(func.count()).select_from(PlatformAdminGrant)) == 1


def test_bootstrap_failure_leaves_no_grant_marker_or_audit(identity_session):
    user = identity.create_user(identity_session, email="first@example.test", display_name="First")
    with patch(
        "editingtab_core.platform.services._audit",
        side_effect=IntegrityError("hidden", {}, Exception("hidden")),
    ):
        with pytest.raises(StorageUnavailable):
            services.bootstrap_initial(identity_session, email="first@example.test")
    with identity_session.begin():
        assert identity_session.get(BootstrapState, 1).completed_at is None
        assert identity_session.scalar(select(func.count()).select_from(PlatformAdminGrant)) == 0
        assert identity_session.scalar(select(func.count()).select_from(PlatformAudit)) == 0
    grant = services.bootstrap_initial(identity_session, email="first@example.test")
    with identity_session.begin():
        assert identity_session.get(PlatformAdminGrant, grant).user_id == user


@pytest.mark.parametrize("state", ["inactive", "archived", "missing"])
def test_bootstrap_rejects_ineligible_user(identity_session, state):
    if state != "missing":
        user = identity.create_user(
            identity_session, email="first@example.test", display_name="First"
        )
        with identity_session.begin():
            row = identity_session.get(User, user)
            if state == "inactive":
                row.is_active = False
            else:
                row.deleted_at = datetime.now(UTC)
    with pytest.raises(services.InvalidOnboarding):
        services.bootstrap_initial(identity_session, email="first@example.test")
    with identity_session.begin():
        assert identity_session.get(BootstrapState, 1).completed_at is None


@pytest.mark.parametrize("state", ["inactive", "archived", "revoked"])
def test_current_platform_status_immediately_denies_same_session(
    identity_session, setup, clients, state
):
    with clients() as client:
        assert client.get("/platform/organizations").status_code == 200
        with identity_session.begin():
            if state == "revoked":
                identity_session.get(PlatformAdminGrant, setup.grant).revoked_at = datetime.now(UTC)
            elif state == "inactive":
                identity_session.get(User, setup.operator).is_active = False
            else:
                identity_session.get(User, setup.operator).deleted_at = datetime.now(UTC)
        assert client.get("/platform/organizations").status_code == (
            403 if state == "revoked" else 401
        )
    with pytest.raises(AccessError):
        services.list_organizations(identity_session, actor_id=setup.operator)


@pytest.mark.parametrize("email", ["owner@example.test", "ordinary@example.test"])
def test_tenant_users_denied_all_platform_operations(identity_session, setup, clients, email):
    org = onboard(identity_session, setup)["id"]
    with clients(email) as client:
        for method, path, body in [
            ("GET", "/platform/organizations", None),
            (
                "POST",
                "/platform/organizations",
                {"name": "Other", "slug": "other", "owner_email": email},
            ),
            ("GET", f"/platform/organizations/{org}/modules", None),
            ("PUT", f"/platform/organizations/{org}/modules/booking", {"enabled": False}),
        ]:
            assert (
                client.request(method, path, json=body, headers={"Origin": ORIGIN}).status_code
                == 403
            )
    with pytest.raises(AccessError):
        onboard(identity_session, setup, actor_id=setup.owner, slug="blocked")
    with pytest.raises(AccessError):
        services.set_entitlement(
            identity_session,
            actor_id=setup.owner,
            organization_id=org,
            module_code="booking",
            enabled=False,
        )


def test_unauthenticated_platform_and_tenant_routes_denied(identity_session, setup, clients):
    org = onboard(identity_session, setup)["id"]
    with clients(authenticated=False) as client:
        for method, path, body in [
            ("GET", "/platform/organizations", None),
            (
                "POST",
                "/platform/organizations",
                {"name": "Other", "slug": "other", "owner_email": "owner@example.test"},
            ),
            ("GET", f"/platform/organizations/{org}/modules", None),
            ("PUT", f"/platform/organizations/{org}/modules/booking", {"enabled": False}),
            ("GET", f"/organizations/{org}/modules", None),
        ]:
            assert (
                client.request(method, path, json=body, headers={"Origin": ORIGIN}).status_code
                == 401
            )


def test_platform_http_origin_input_validation_pagination_and_no_tenant_bypass(
    identity_session, setup, clients
):
    body = {
        "name": "Client",
        "slug": "client",
        "owner_email": "owner@example.test",
        "enabled_modules": ["booking"],
    }
    with clients() as client:
        for headers in ({}, {"Origin": "https://untrusted.example"}):
            assert (
                client.post("/platform/organizations", json=body, headers=headers).status_code
                == 403
            )
        for extra in ({"actor_id": str(setup.owner)}, {"platform_admin": True}):
            assert (
                client.post(
                    "/platform/organizations", json={**body, **extra}, headers={"Origin": ORIGIN}
                ).status_code
                == 422
            )
        for changes in ({"slug": "not valid"}, {"owner_email": "bad"}, {"name": "   "}):
            assert (
                client.post(
                    "/platform/organizations", json={**body, **changes}, headers={"Origin": ORIGIN}
                ).status_code
                == 422
            )
        response = client.post("/platform/organizations", json=body, headers={"Origin": ORIGIN})
        assert response.status_code == 201
        assert set(response.json()) == {"id", "name", "slug", "enabled_modules"}
        org = response.json()["id"]
        assert client.get(f"/organizations/{org}").status_code == 404
        assert client.get(f"/organizations/{org}/modules").status_code == 404
        assert (
            client.post(
                "/platform/organizations", json=body, headers={"Origin": ORIGIN}
            ).status_code
            == 409
        )
        assert client.get("/platform/organizations?limit=1&offset=1").json() == []
        assert client.get("/platform/organizations?limit=101").status_code == 422
        assert len(client.get("/platform/organizations?limit=1").json()) == 1
        for headers in ({}, {"Origin": "https://untrusted.example"}):
            assert (
                client.put(
                    f"/platform/organizations/{org}/modules/booking",
                    json={"enabled": False},
                    headers=headers,
                ).status_code
                == 403
            )
        assert (
            client.put(
                f"/platform/organizations/{org}/modules/booking",
                json={"enabled": "false"},
                headers={"Origin": ORIGIN},
            ).status_code
            == 422
        )
        assert client.get(f"/platform/organizations/{org}/modules").json()["enabled_modules"] == [
            "booking"
        ]
    with clients("owner@example.test") as client:
        # Tenant role payloads and permission catalogs cannot mint platform authority.
        assert (
            client.post(
                f"/organizations/{org}/roles",
                json={"name": "Escalate", "permissions": ["platform.admin"]},
                headers={"Origin": ORIGIN},
            ).status_code
            == 422
        )
        assert (
            client.post(
                f"/organizations/{org}/roles",
                json={"name": "Escalate", "permissions": [], "platform_admin": True},
                headers={"Origin": ORIGIN},
            ).status_code
            == 422
        )
        assert client.put(
            f"/organizations/{org}/modules/booking",
            json={"enabled": True},
            headers={"Origin": ORIGIN},
        ).status_code in (404, 405)
    with identity_session.begin():
        assert identity_session.scalar(select(func.count()).select_from(PlatformAdminGrant)) == 1


def test_guard_enable_disable_and_tenant_scoping_without_relogin(identity_session, setup, clients):
    org = onboard(identity_session, setup)["id"]
    other = onboard(identity_session, setup, slug="other", owner_email="ordinary@example.test")[
        "id"
    ]
    with clients("owner@example.test") as client:
        assert client.get(f"/organizations/{org}/test-booking").status_code == 200
        assert client.get(f"/organizations/{other}/modules").status_code == 404
        assert client.get(f"/organizations/{other}/test-booking").status_code == 404
        services.set_entitlement(
            identity_session,
            actor_id=setup.operator,
            organization_id=org,
            module_code="booking",
            enabled=False,
        )
        assert client.get(f"/organizations/{org}/test-booking").status_code == 403
        assert client.get(f"/organizations/{org}/modules").json()["enabled_modules"] == []
        services.set_entitlement(
            identity_session,
            actor_id=setup.operator,
            organization_id=org,
            module_code="booking",
            enabled=True,
        )
        assert client.get(f"/organizations/{org}/test-booking").status_code == 200
        identity.archive_organization(identity_session, organization_id=org)
        assert client.get(f"/organizations/{org}/modules").status_code == 404
        assert client.get(f"/organizations/{org}/test-booking").status_code == 404
    with pytest.raises(Inaccessible):
        services.set_entitlement(
            identity_session,
            actor_id=setup.operator,
            organization_id=org,
            module_code="booking",
            enabled=False,
        )
    with identity_session.begin():
        assert identity_session.get(Organization, org) is not None
        assert identity_session.get(ModuleEntitlement, (org, "booking")).enabled is True
        with pytest.raises(Inaccessible):
            services.require_entitlement(
                identity_session, organization_id=org, module_code="booking"
            )


def test_tenant_module_read_requires_permission_not_just_membership(
    identity_session, setup, clients
):
    org = onboard(identity_session, setup)["id"]
    identity.add_membership(identity_session, organization_id=org, user_id=setup.ordinary)
    with clients("ordinary@example.test") as client:
        assert client.get(f"/organizations/{org}/modules").status_code == 403
        assert client.get(f"/organizations/{org}/test-booking").status_code == 403


@pytest.mark.parametrize("code", ["unknown", "pos", "chatbot", "unified_inbox"])
def test_database_rejects_unsupported_entitlements(identity_session, setup, code):
    org = onboard(identity_session, setup)["id"]
    with pytest.raises(IntegrityError), identity_session.begin():
        identity_session.add(ModuleEntitlement(organization_id=org, module_code=code, enabled=True))
        identity_session.flush()
    assert services.read_entitlements(
        identity_session, actor_id=setup.operator, organization_id=org
    )["enabled_modules"] == ["booking"]


@pytest.mark.parametrize("state", ["missing_marker", "completed_marker", "historical_grant"])
def test_bootstrap_fails_closed_on_history_or_missing_sentinel(identity_session, state):
    user = identity.create_user(identity_session, email="first@example.test", display_name="First")
    with identity_session.begin():
        marker = identity_session.get(BootstrapState, 1)
        if state == "missing_marker":
            identity_session.delete(marker)
        elif state == "completed_marker":
            marker.completed_at = datetime.now(UTC)
        else:
            identity_session.add(PlatformAdminGrant(user_id=user, revoked_at=datetime.now(UTC)))
    expected = StorageUnavailable if state == "missing_marker" else services.BootstrapClosed
    with pytest.raises(expected):
        services.bootstrap_initial(identity_session, email="first@example.test")
    with identity_session.begin():
        assert identity_session.scalar(select(func.count()).select_from(PlatformAdminGrant)) == (
            1 if state == "historical_grant" else 0
        )
        assert identity_session.scalar(select(func.count()).select_from(PlatformAudit)) == 0
