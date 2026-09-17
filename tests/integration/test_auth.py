import time
from contextlib import contextmanager
from datetime import timedelta
from unittest.mock import patch

import pytest
from argon2 import PasswordHasher
from fastapi.testclient import TestClient
from sqlalchemy import func, select, update
from sqlalchemy.orm import sessionmaker

from editingtab_core.app import create_app
from editingtab_core.auth import services
from editingtab_core.auth.models import LoginSession, LoginThrottle, PasswordCredential
from editingtab_core.auth.provision import provision_user
from editingtab_core.auth.security import COOKIE_NAME, CredentialConflict, Passwords, token_digest
from editingtab_core.identity import services as identity
from editingtab_core.identity.models import User

pytestmark = pytest.mark.integration
ORIGIN = "http://127.0.0.1:18080"
PASSWORD = "test-only correct horse battery staple"
EMAIL = "Demo+one@example.test"


@pytest.fixture
def passwords():
    return Passwords()


@pytest.fixture
def auth_settings(integration_settings):
    return integration_settings.model_copy(update={"auth_allowed_origins": (ORIGIN,)})


@pytest.fixture
def user_id(identity_session, auth_settings, passwords):
    return provision_user(
        identity_session,
        settings=auth_settings,
        passwords=passwords,
        email=EMAIL,
        display_name="Demo User",
        password=PASSWORD,
    )


@pytest.fixture
def clients(identity_session, migration_connection, auth_settings):
    @contextmanager
    def make(settings=None, source="127.0.0.1"):
        app = create_app(settings or auth_settings)
        with TestClient(app, base_url=ORIGIN, client=(source, 50000)) as client:
            app.state.session_factory = sessionmaker(
                bind=migration_connection,
                join_transaction_mode="create_savepoint",
                expire_on_commit=False,
            )
            yield client

    return make


def login(client, *, email=EMAIL, password=PASSWORD, headers=None):
    return client.post(
        "/auth/login",
        json={"email": email, "password": password},
        headers=headers or {"Origin": ORIGIN},
    )


def test_real_login_hash_digest_cookie_profile_and_logout(
    clients, user_id, identity_session, passwords
):
    with clients() as client:
        assert client.get("/auth/me").status_code == 401
        response = login(client, email="  demo+ONE@EXAMPLE.TEST  ")
        assert response.status_code == 204
        assert response.content == b""
        cookie = response.headers["set-cookie"].lower()
        assert "httponly" in cookie and "samesite=lax" in cookie and "path=/" in cookie
        assert "domain=" not in cookie and "secure" not in cookie
        token = client.cookies.get(COOKIE_NAME)
        assert len(token) == 43
        profile = client.get("/auth/me")
        assert profile.status_code == 200
        assert profile.json() == {"id": str(user_id), "email": EMAIL, "display_name": "Demo User"}
        assert profile.headers["cache-control"] == "no-store"
        with identity_session.begin():
            credential = identity_session.get(PasswordCredential, user_id)
            assert credential.password_hash.startswith("$argon2id$")
            assert PASSWORD not in credential.password_hash
            assert passwords.verify(credential.password_hash, PASSWORD)
            stored = identity_session.scalar(select(LoginSession))
            assert stored.token_digest == token_digest(token)
            assert stored.token_digest != token
            assert stored.expires_at - stored.created_at == timedelta(hours=8)
        assert login(client).status_code == 204
        second_token = client.cookies.get(COOKIE_NAME)
        assert second_token != token
        response = client.post("/auth/logout", headers={"Origin": ORIGIN})
        assert response.status_code == 204
        assert "max-age=0" in response.headers["set-cookie"].lower()
        assert client.cookies.get(COOKIE_NAME) is None
        client.cookies.set(COOKIE_NAME, second_token)
        assert client.get("/auth/me").status_code == 401
        with identity_session.begin():
            rows = identity_session.scalars(select(LoginSession)).all()
            assert len(rows) == 2
            assert all(row.token_digest not in {token, second_token} for row in rows)
            assert sum(row.revoked_at is not None for row in rows) == 1


def test_unknown_wrong_and_credentialless_login_fail_identically(
    clients, user_id, identity_session
):
    identity.create_user(
        identity_session, email="no-password@example.test", display_name="No password"
    )
    with clients() as client:
        responses = [
            login(client, password="incorrect password long enough"),
            login(client, email="unknown@example.test"),
            login(client, email="no-password@example.test"),
        ]
        assert all(r.status_code == 401 for r in responses)
        assert all(r.json() == {"detail": "Authentication failed."} for r in responses)
        assert all("set-cookie" not in r.headers for r in responses)
        with identity_session.begin():
            assert identity_session.scalar(select(func.count()).select_from(LoginSession)) == 0


@pytest.mark.parametrize("state", ["inactive", "archived"])
def test_status_checked_at_login_and_on_existing_sessions(
    clients, user_id, identity_session, state
):
    with clients() as client:
        assert login(client).status_code == 204
        with identity_session.begin():
            user = identity_session.get(User, user_id)
            if state == "inactive":
                user.is_active = False
            else:
                user.deleted_at = func.clock_timestamp()
        assert client.get("/auth/me").status_code == 401
        assert login(client).status_code == 401


@pytest.mark.parametrize("state", ["expired", "revoked"])
def test_expired_and_revoked_sessions_fail(clients, user_id, identity_session, state):
    with clients() as client:
        assert login(client).status_code == 204
        with identity_session.begin():
            row = identity_session.scalar(select(LoginSession))
            now = identity_session.scalar(select(func.clock_timestamp()))
            if state == "expired":
                row.created_at = now - timedelta(hours=2)
                row.expires_at = now - timedelta(hours=1)
            else:
                row.revoked_at = now
        assert client.get("/auth/me").status_code == 401


def test_origin_required_for_login_and_logout(clients, user_id):
    with clients() as client:
        assert login(client).status_code == 204
        for route in ("login", "logout"):
            for headers in (
                {},
                {"Origin": "https://evil.example"},
                [("Origin", ORIGIN), ("Origin", ORIGIN)],
            ):
                response = client.post(
                    f"/auth/{route}", json={"email": EMAIL, "password": PASSWORD}, headers=headers
                )
                assert response.status_code == 403
        assert client.get("/auth/me").status_code == 200
        assert client.post("/auth/logout", headers={"Origin": ORIGIN}).status_code == 204
        assert client.get("/auth/me").status_code == 401


def test_production_cookie_attributes(clients, user_id, auth_settings):
    settings = auth_settings.model_copy(
        update={"environment": "production", "auth_allowed_origins": ("https://demo.example",)}
    )
    with clients(settings) as client:
        response = login(client, headers={"Origin": "https://demo.example"})
        assert response.status_code == 204
        cookie = response.headers["set-cookie"].lower()
        assert "secure" in cookie and "httponly" in cookie and "samesite=lax" in cookie
        assert "domain=" not in cookie and "path=/" in cookie


def test_throttle_shared_across_apps_and_sources_then_recovers(
    clients, user_id, auth_settings, identity_session
):
    settings = auth_settings.model_copy(update={"auth_account_limit": 2})
    with (
        clients(settings, source="127.0.0.1") as first,
        clients(settings, source="127.0.0.2") as second,
    ):
        assert login(first, password="incorrect password long enough").status_code == 401
        assert login(second, password="incorrect password long enough").status_code == 401
        response = login(first)
        assert response.status_code == 429
        assert response.headers["retry-after"] == "300"
        assert login(second).status_code == 429
        with identity_session.begin():
            rows = identity_session.scalars(select(LoginThrottle)).all()
            assert len(rows) == 3  # two source buckets, one normalized account
            assert all(EMAIL.lower() not in row.key for row in rows)
            identity_session.execute(
                update(LoginThrottle).values(
                    expires_at=func.clock_timestamp() - timedelta(seconds=1)
                )
            )
        assert login(second).status_code == 204


def test_source_throttle_ignores_forwarding_headers_and_unknown_accounts(
    clients, auth_settings, identity_session
):
    settings = auth_settings.model_copy(update={"auth_source_limit": 2})
    with clients(settings) as first, clients(settings) as second:
        assert login(first, email="missing1@example.test").status_code == 401
        assert login(second, email="missing2@example.test").status_code == 401
        response = login(
            second,
            email="missing3@example.test",
            headers={
                "Origin": ORIGIN,
                "X-Forwarded-For": "192.0.2.1",
                "Forwarded": "for=192.0.2.2",
            },
        )
        assert response.status_code == 429
        with identity_session.begin():
            assert identity_session.scalar(select(func.count()).select_from(LoginThrottle)) == 3
        with identity_session.begin():
            identity_session.execute(
                update(LoginThrottle).values(
                    expires_at=func.clock_timestamp() - timedelta(seconds=1)
                )
            )
        assert login(first, email="missing3@example.test").status_code == 401
        with identity_session.begin():
            assert identity_session.scalar(select(func.count()).select_from(LoginThrottle)) == 2


def test_successful_login_rehashes_outdated_parameters(clients, user_id, identity_session):
    outdated = PasswordHasher(time_cost=1, memory_cost=8192, parallelism=1).hash(PASSWORD)
    with identity_session.begin():
        identity_session.get(PasswordCredential, user_id).password_hash = outdated
    with clients() as client:
        assert login(client).status_code == 204
    with identity_session.begin():
        current = identity_session.get(PasswordCredential, user_id).password_hash
        assert current != outdated
        assert not Passwords().hasher.check_needs_rehash(current)


def test_provision_never_overwrites_existing_credentials(
    user_id, identity_session, auth_settings, passwords
):
    with identity_session.begin():
        original = identity_session.get(PasswordCredential, user_id).password_hash
    with pytest.raises(CredentialConflict):
        provision_user(
            identity_session,
            settings=auth_settings,
            passwords=passwords,
            email=EMAIL,
            display_name="Changed",
            password="different long password",
        )
    with identity_session.begin():
        assert identity_session.get(PasswordCredential, user_id).password_hash == original
        assert identity_session.get(User, user_id).display_name == "Demo User"


def test_provision_existing_profile_without_granting_membership(
    identity_session, auth_settings, passwords
):
    user_id = identity.create_user(identity_session, email=EMAIL, display_name="Existing")
    assert (
        provision_user(
            identity_session,
            settings=auth_settings,
            passwords=passwords,
            email=EMAIL,
            display_name="Ignored",
            password=PASSWORD,
        )
        == user_id
    )
    with identity_session.begin():
        assert identity_session.get(User, user_id).display_name == "Existing"
        assert identity_session.get(PasswordCredential, user_id) is not None


def test_failed_provision_rolls_back_profile_and_session_remains_usable(
    identity_session, auth_settings, passwords
):
    from sqlalchemy.exc import IntegrityError

    from editingtab_core.auth.security import AuthenticationUnavailable

    original_flush = identity_session.flush

    def fail_credential(*args, **kwargs):
        if any(isinstance(obj, PasswordCredential) for obj in identity_session.new):
            raise IntegrityError("hidden", {}, Exception("hidden"))
        return original_flush(*args, **kwargs)

    with patch.object(identity_session, "flush", side_effect=fail_credential):
        with pytest.raises(AuthenticationUnavailable):
            provision_user(
                identity_session,
                settings=auth_settings,
                passwords=passwords,
                email=EMAIL,
                display_name="Demo",
                password=PASSWORD,
            )
    with identity_session.begin():
        assert identity_session.scalar(select(func.count()).select_from(User)) == 0
    provision_user(
        identity_session,
        settings=auth_settings,
        passwords=passwords,
        email=EMAIL,
        display_name="Demo",
        password=PASSWORD,
    )


def test_failed_login_rolls_back_session_but_preserves_throttle(
    user_id, identity_session, auth_settings, passwords
):
    from sqlalchemy.exc import IntegrityError

    from editingtab_core.auth import repository
    from editingtab_core.auth.security import AuthenticationUnavailable

    original = repository.add_session

    def fail_after_insert(*args, **kwargs):
        original(*args, **kwargs)
        raise IntegrityError("hidden", {}, Exception("hidden"))

    with patch.object(repository, "add_session", side_effect=fail_after_insert):
        with pytest.raises(AuthenticationUnavailable):
            services.login(
                identity_session,
                settings=auth_settings,
                passwords=passwords,
                email=EMAIL,
                password=PASSWORD,
                source="127.0.0.1",
            )
    with identity_session.begin():
        assert identity_session.scalar(select(func.count()).select_from(LoginSession)) == 0
        assert identity_session.scalar(select(func.count()).select_from(LoginThrottle)) == 2
    token = services.login(
        identity_session,
        settings=auth_settings,
        passwords=passwords,
        email=EMAIL,
        password=PASSWORD,
        source="127.0.0.1",
    )
    assert services.current_user(identity_session, token).id == user_id


def test_throttle_window_expires_with_database_clock(clients, auth_settings):
    settings = auth_settings.model_copy(update={"auth_account_limit": 1, "auth_window_seconds": 1})
    with clients(settings) as client:
        assert login(client, email="absent@example.test").status_code == 401
        assert login(client, email="absent@example.test").status_code == 429
        time.sleep(1.1)
        assert login(client, email="absent@example.test").status_code == 401


def test_unknown_user_performs_dummy_verification(clients):
    with clients() as client:
        with patch.object(
            client.app.state.passwords, "verify", wraps=client.app.state.passwords.verify
        ) as verify:
            assert login(client, email="unknown@example.test").status_code == 401
            verify.assert_called_once_with(None, PASSWORD)
