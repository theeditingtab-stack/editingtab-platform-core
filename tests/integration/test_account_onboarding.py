"""CORE-AUTH-004 invitation, recovery, and session lifecycle behavior."""

from contextlib import contextmanager
from datetime import timedelta
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

from editingtab_core.app import create_app
from editingtab_core.auth import repository, services
from editingtab_core.auth.models import (
    LoginSession,
    OrganizationInvitation,
    PasswordCredential,
    PasswordResetToken,
    SecurityAudit,
)
from editingtab_core.auth.provision import provision_user
from editingtab_core.auth.security import (
    COOKIE_NAME,
    AuthenticationError,
    AuthenticationUnavailable,
    Passwords,
    token_digest,
)
from editingtab_core.authorization import services as access
from editingtab_core.authorization.bootstrap import bootstrap
from editingtab_core.authorization.models import MembershipRole, Role
from editingtab_core.authorization.policy import AccessError, Conflict, Inaccessible
from editingtab_core.identity import services as identity
from editingtab_core.identity.models import User

pytestmark = pytest.mark.integration
ORIGIN = "http://127.0.0.1:18080"
PASSWORD = "test-only correct horse battery staple"
NEW_PASSWORD = "test-only newer correct horse battery staple"


@pytest.fixture
def auth_settings(integration_settings):
    return integration_settings.model_copy(update={"auth_allowed_origins": (ORIGIN,)})


@pytest.fixture
def env(identity_session, auth_settings):
    passwords = Passwords()
    owner = provision_user(
        identity_session,
        settings=auth_settings,
        passwords=passwords,
        email="owner@example.test",
        display_name="Owner",
        password=PASSWORD,
    )
    org = bootstrap(
        identity_session,
        settings=auth_settings,
        email="owner@example.test",
        slug="onboarding",
        name="Onboarding",
    )
    return {"owner": owner, "org": org, "passwords": passwords}


@pytest.fixture
def clients(migration_connection, auth_settings):
    @contextmanager
    def make(settings=None):
        app = create_app(settings or auth_settings)
        with TestClient(app, base_url=ORIGIN) as client:
            app.state.session_factory = sessionmaker(
                bind=migration_connection,
                join_transaction_mode="create_savepoint",
                expire_on_commit=False,
            )
            yield client

    return make


def test_invitation_creation_hashes_reissues_and_enforces_active_member(
    identity_session, env, auth_settings
):
    first = services.create_invitation(
        identity_session,
        settings=auth_settings,
        organization_id=env["org"],
        actor_id=env["owner"],
        email=" Employee@Example.Test ",
    )
    second = services.create_invitation(
        identity_session,
        settings=auth_settings,
        organization_id=env["org"],
        actor_id=env["owner"],
        email="employee@example.test",
    )
    with identity_session.begin():
        rows = list(identity_session.scalars(select(OrganizationInvitation)))
        assert len(rows) == 2
        assert rows[0].revoked_at is not None and rows[1].revoked_at is None
        assert all(row.token_digest not in {first["token"], second["token"]} for row in rows)
        assert rows[1].token_digest == token_digest(second["token"])
        assert all(
            first["token"] not in str(row.details)
            for row in identity_session.scalars(select(SecurityAudit))
        )
    user = identity.create_user(
        identity_session, email="active@example.test", display_name="Already active"
    )
    identity.add_membership(identity_session, organization_id=env["org"], user_id=user)
    with pytest.raises(Conflict):
        services.create_invitation(
            identity_session,
            settings=auth_settings,
            organization_id=env["org"],
            actor_id=env["owner"],
            email="active@example.test",
        )


def test_initial_roles_enforce_cross_tenant_and_grant_ceiling(identity_session, env, auth_settings):
    unprivileged = identity.create_user(
        identity_session, email="unprivileged@example.test", display_name="Unprivileged"
    )
    identity.add_membership(identity_session, organization_id=env["org"], user_id=unprivileged)
    with pytest.raises(AccessError):
        services.create_invitation(
            identity_session,
            settings=auth_settings,
            organization_id=env["org"],
            actor_id=unprivileged,
            email="denied@example.test",
        )
    other = bootstrap(
        identity_session,
        settings=auth_settings,
        email="owner@example.test",
        slug="invitation-other",
        name="Other",
    )
    with identity_session.begin():
        foreign_role = identity_session.scalar(select(Role.id).where(Role.organization_id == other))
    with pytest.raises(Inaccessible):
        services.create_invitation(
            identity_session,
            settings=auth_settings,
            organization_id=env["org"],
            actor_id=env["owner"],
            email="foreign-role@example.test",
            role_ids=[foreign_role],
        )
    scoped = services.create_invitation(
        identity_session,
        settings=auth_settings,
        organization_id=env["org"],
        actor_id=env["owner"],
        email="tenant-scoped@example.test",
    )
    with pytest.raises(Inaccessible):
        services.revoke_invitation(
            identity_session,
            organization_id=other,
            actor_id=env["owner"],
            invitation_id=scoped["id"],
        )
    manager = identity.create_user(
        identity_session, email="manager@example.test", display_name="Manager"
    )
    member = identity.add_membership(identity_session, organization_id=env["org"], user_id=manager)
    manager_role = access.create_role(
        identity_session,
        organization_id=env["org"],
        actor_id=env["owner"],
        name="Invitation manager",
        permissions={"core.members.manage": False, "core.roles.assign": False},
    )["id"]
    access.change_assignment(
        identity_session,
        organization_id=env["org"],
        actor_id=env["owner"],
        membership_id=member,
        role_id=manager_role,
    )
    weak = access.create_role(
        identity_session,
        organization_id=env["org"],
        actor_id=env["owner"],
        name="Weak",
        permissions={"core.organization.read": False},
    )["id"]
    with pytest.raises(AccessError):
        services.create_invitation(
            identity_session,
            settings=auth_settings,
            organization_id=env["org"],
            actor_id=manager,
            email="ceiling@example.test",
            role_ids=[weak],
        )


def test_new_and_existing_user_acceptance_restore_without_old_roles(
    identity_session, env, auth_settings
):
    role = access.create_role(
        identity_session,
        organization_id=env["org"],
        actor_id=env["owner"],
        name="Employee",
        permissions={"core.organization.read": False},
    )["id"]
    invitation = services.create_invitation(
        identity_session,
        settings=auth_settings,
        organization_id=env["org"],
        actor_id=env["owner"],
        email="new@example.test",
        role_ids=[role],
    )
    accepted = services.accept_invitation(
        identity_session,
        passwords=env["passwords"],
        token=invitation["token"],
        email="NEW@example.test",
        display_name="New Employee",
        password=PASSWORD,
    )
    with pytest.raises(AuthenticationError):
        services.accept_invitation(
            identity_session,
            passwords=env["passwords"],
            token=invitation["token"],
            email="new@example.test",
        )
    with identity_session.begin():
        user = identity_session.scalar(
            select(User).where(User.normalized_email == "new@example.test")
        )
        assert identity_session.get(PasswordCredential, user.id) is not None
        assert identity_session.get(MembershipRole, (env["org"], accepted["membership_id"], role))

    existing = provision_user(
        identity_session,
        settings=auth_settings,
        passwords=env["passwords"],
        email="existing@example.test",
        display_name="Existing Identity",
        password=PASSWORD,
    )
    membership = access.add_member(
        identity_session,
        organization_id=env["org"],
        actor_id=env["owner"],
        user_id=existing,
        role_ids=[role],
    )["membership_id"]
    access.archive_member(
        identity_session,
        organization_id=env["org"],
        actor_id=env["owner"],
        membership_id=membership,
    )
    restored_invitation = services.create_invitation(
        identity_session,
        settings=auth_settings,
        organization_id=env["org"],
        actor_id=env["owner"],
        email="existing@example.test",
    )
    restored = services.accept_invitation(
        identity_session,
        passwords=env["passwords"],
        token=restored_invitation["token"],
        email="existing@example.test",
        display_name="Must not overwrite",
        password=NEW_PASSWORD,
    )
    with identity_session.begin():
        assert restored["membership_id"] == membership and restored["roles"] == []
        assert identity_session.get(User, existing).display_name == "Existing Identity"
        credential = identity_session.get(PasswordCredential, existing)
        assert env["passwords"].verify(credential.password_hash, PASSWORD)
        assert not env["passwords"].verify(credential.password_hash, NEW_PASSWORD)


def test_expired_revoked_mismatched_and_atomic_invitation(identity_session, env, auth_settings):
    invitation = services.create_invitation(
        identity_session,
        settings=auth_settings,
        organization_id=env["org"],
        actor_id=env["owner"],
        email="expired@example.test",
    )
    with identity_session.begin():
        row = identity_session.get(OrganizationInvitation, invitation["id"])
        now = identity_session.scalar(select(func.clock_timestamp()))
        row.created_at = now - timedelta(seconds=2)
        row.expires_at = now - timedelta(seconds=1)
    with pytest.raises(AuthenticationError):
        services.accept_invitation(
            identity_session,
            passwords=env["passwords"],
            token=invitation["token"],
            email="expired@example.test",
            display_name="Expired",
            password=PASSWORD,
        )
    revoked = services.create_invitation(
        identity_session,
        settings=auth_settings,
        organization_id=env["org"],
        actor_id=env["owner"],
        email="revoked@example.test",
    )
    services.revoke_invitation(
        identity_session,
        organization_id=env["org"],
        actor_id=env["owner"],
        invitation_id=revoked["id"],
    )
    for email in ("wrong@example.test", "revoked@example.test"):
        with pytest.raises(AuthenticationError):
            services.accept_invitation(
                identity_session,
                passwords=env["passwords"],
                token=revoked["token"],
                email=email,
                display_name="Rejected",
                password=PASSWORD,
            )

    atomic = services.create_invitation(
        identity_session,
        settings=auth_settings,
        organization_id=env["org"],
        actor_id=env["owner"],
        email="atomic-invite@example.test",
    )
    original = repository.audit

    def fail(*args, **kwargs):
        original(*args, **kwargs)
        if kwargs.get("action") == "invitation.accepted":
            raise IntegrityError("hidden", {}, Exception("hidden"))

    with (
        patch.object(repository, "audit", side_effect=fail),
        pytest.raises(AuthenticationUnavailable),
    ):
        services.accept_invitation(
            identity_session,
            passwords=env["passwords"],
            token=atomic["token"],
            email="atomic-invite@example.test",
            display_name="Atomic",
            password=PASSWORD,
        )
    with identity_session.begin():
        assert (
            identity_session.scalar(
                select(User.id).where(User.normalized_email == "atomic-invite@example.test")
            )
            is None
        )
        assert identity_session.get(OrganizationInvitation, atomic["id"]).accepted_at is None


def test_password_change_preserves_current_and_revokes_other_sessions(
    identity_session, env, auth_settings
):
    first = services.login(
        identity_session,
        settings=auth_settings,
        passwords=env["passwords"],
        email="owner@example.test",
        password=PASSWORD,
        source="one",
    )
    second = services.login(
        identity_session,
        settings=auth_settings,
        passwords=env["passwords"],
        email="owner@example.test",
        password=PASSWORD,
        source="two",
    )
    with pytest.raises(AuthenticationError):
        services.change_password(
            identity_session,
            passwords=env["passwords"],
            token=first,
            current_password="wrong password long enough",
            new_password=NEW_PASSWORD,
        )
    services.change_password(
        identity_session,
        passwords=env["passwords"],
        token=first,
        current_password=PASSWORD,
        new_password=NEW_PASSWORD,
    )
    assert services.current_user(identity_session, first).id == env["owner"]
    with pytest.raises(AuthenticationError):
        services.current_user(identity_session, second)


def test_reset_is_non_disclosing_single_use_and_revokes_all_sessions(
    identity_session, env, auth_settings
):
    revoked = services.request_password_reset(
        identity_session,
        settings=auth_settings,
        email="owner@example.test",
        source="known",
    )
    unknown = services.request_password_reset(
        identity_session,
        settings=auth_settings,
        email="unknown@example.test",
        source="unknown",
    )
    assert len(revoked) == len(unknown) == 43
    expired = services.request_password_reset(
        identity_session,
        settings=auth_settings,
        email="owner@example.test",
        source="replacement",
    )
    with pytest.raises(AuthenticationError):
        services.reset_password(
            identity_session, passwords=env["passwords"], token=revoked, password=NEW_PASSWORD
        )
    with identity_session.begin():
        row = identity_session.scalar(
            select(PasswordResetToken).where(
                PasswordResetToken.token_digest == token_digest(expired)
            )
        )
        now = identity_session.scalar(select(func.clock_timestamp()))
        row.created_at = now - timedelta(seconds=2)
        row.expires_at = now - timedelta(seconds=1)
    with pytest.raises(AuthenticationError):
        services.reset_password(
            identity_session, passwords=env["passwords"], token=expired, password=NEW_PASSWORD
        )
    known = services.request_password_reset(
        identity_session,
        settings=auth_settings,
        email="owner@example.test",
        source="final",
    )
    session_token = services.login(
        identity_session,
        settings=auth_settings,
        passwords=env["passwords"],
        email="owner@example.test",
        password=PASSWORD,
        source="login",
    )
    services.reset_password(
        identity_session, passwords=env["passwords"], token=known, password=NEW_PASSWORD
    )
    with pytest.raises(AuthenticationError):
        services.reset_password(
            identity_session, passwords=env["passwords"], token=known, password=PASSWORD
        )
    with pytest.raises(AuthenticationError):
        services.current_user(identity_session, session_token)
    with identity_session.begin():
        rows = list(identity_session.scalars(select(PasswordResetToken)))
        assert len(rows) == 3 and sum(row.consumed_at is not None for row in rows) == 1
        assert all(row.token_digest not in {known, unknown, revoked, expired} for row in rows)
        audits = list(identity_session.scalars(select(SecurityAudit)))
        assert all(
            token not in str(row.details)
            for row in audits
            for token in (known, unknown, revoked, expired)
        )


def test_session_ownership_list_selected_all_and_logout(identity_session, env, auth_settings):
    first = services.login(
        identity_session,
        settings=auth_settings,
        passwords=env["passwords"],
        email="owner@example.test",
        password=PASSWORD,
        source="one",
    )
    second = services.login(
        identity_session,
        settings=auth_settings,
        passwords=env["passwords"],
        email="owner@example.test",
        password=PASSWORD,
        source="two",
    )
    listed = services.list_sessions(identity_session, first)
    assert len(listed) == 2 and sum(item["current_session"] for item in listed) == 1
    assert all("token" not in item for item in listed)
    second_id = next(item["id"] for item in listed if not item["current_session"])
    assert services.revoke_selected_session(identity_session, first, second_id) is False
    with pytest.raises(AuthenticationError):
        services.current_user(identity_session, second)
    other = provision_user(
        identity_session,
        settings=auth_settings,
        passwords=env["passwords"],
        email="other-session@example.test",
        display_name="Other",
        password=PASSWORD,
    )
    other_token = services.login(
        identity_session,
        settings=auth_settings,
        passwords=env["passwords"],
        email="other-session@example.test",
        password=PASSWORD,
        source="other",
    )
    with identity_session.begin():
        other_id = identity_session.scalar(
            select(LoginSession.id).where(LoginSession.user_id == other)
        )
    with pytest.raises(AuthenticationError):
        services.revoke_selected_session(identity_session, first, other_id)
    services.revoke_all_sessions(identity_session, first)
    with pytest.raises(AuthenticationError):
        services.current_user(identity_session, first)
    assert services.current_user(identity_session, other_token).id == other


def test_http_origin_token_exposure_and_session_cookie_behavior(clients, env, auth_settings):
    with clients() as client:
        assert (
            client.post(
                "/auth/login",
                json={"email": "owner@example.test", "password": PASSWORD},
                headers={"Origin": ORIGIN},
            ).status_code
            == 204
        )
        assert client.get("/auth/sessions").status_code == 200
        no_origin = client.post(
            "/auth/password/change",
            json={"current_password": PASSWORD, "new_password": NEW_PASSWORD},
        )
        assert no_origin.status_code == 403
        known = client.post(
            "/auth/password/reset/request",
            json={"email": "owner@example.test"},
            headers={"Origin": ORIGIN},
        )
        unknown = client.post(
            "/auth/password/reset/request",
            json={"email": "absent@example.test"},
            headers={"Origin": ORIGIN},
        )
        assert known.status_code == unknown.status_code == 202
        assert set(known.json()) == set(unknown.json()) == {"accepted", "development_token"}
        assert (
            client.post("/auth/sessions/revoke-all", headers={"Origin": ORIGIN}).status_code == 204
        )
        assert client.cookies.get(COOKIE_NAME) is None

    production = auth_settings.model_copy(
        update={"environment": "production", "auth_allowed_origins": ("https://core.example",)}
    )
    with clients(production) as client:
        response = client.post(
            "/auth/password/reset/request",
            json={"email": "owner@example.test"},
            headers={"Origin": "https://core.example"},
        )
        assert response.json() == {"accepted": True}
