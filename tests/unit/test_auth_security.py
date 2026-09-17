from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy.exc import OperationalError

from editingtab_core.app import create_app
from editingtab_core.auth.provision import require_local
from editingtab_core.auth.security import Passwords, token_digest, validate_password
from editingtab_core.config import Settings
from editingtab_core.database import get_session

ORIGIN = "http://127.0.0.1:18080"


@pytest.mark.parametrize("length", [0, 14, 1025])
def test_password_length_rejected(length):
    with pytest.raises(ValueError, match="15 to 1024"):
        validate_password("a" * length)


@pytest.mark.parametrize("password", ["a" * 15, "a" * 1024, " long unicode \u2764 password "])
def test_password_length_and_unicode_accepted(password):
    validate_password(password)


def test_long_password_is_not_truncated():
    passwords = Passwords()
    password = "a" * 1023 + "b"
    encoded = passwords.hash(password)
    assert encoded.startswith("$argon2id$")
    assert passwords.verify(encoded, password)
    assert not passwords.verify(encoded, "a" * 1024)
    with patch("argon2.PasswordHasher.verify", return_value=False) as verify:
        assert not passwords.verify(None, password)
        verify.assert_called_once()


@pytest.mark.parametrize("environment", [None, "production", "development", "test"])
def test_secure_cookie_only_disabled_in_explicit_local_mode(environment):
    kwargs = {"environment": environment} if environment else {}
    settings = Settings(_env_file=None, db_password="unit-only", **kwargs)
    assert settings.auth_secure_cookie is (environment not in {"development", "test"})
    if environment not in {"development", "test"}:
        with pytest.raises(ValueError):
            require_local(settings)
    else:
        require_local(settings)


@pytest.mark.parametrize(
    "origin",
    [
        "*",
        "null",
        "https://host/path",
        "https://user:pass@host",
        "https://host/",
        "http://host",
        "https://*.host",
    ],
)
def test_production_rejects_unsafe_origins(origin):
    with pytest.raises(ValidationError):
        Settings(
            _env_file=None,
            environment="production",
            db_password="unit-only",
            auth_allowed_origins=[origin],
        )


def test_production_does_not_accept_insecure_override(monkeypatch):
    monkeypatch.setenv("CORE_AUTH_SECURE_COOKIE", "false")
    settings = Settings(
        _env_file=None,
        environment="production",
        db_password="unit-only",
        auth_allowed_origins=["https://demo.example"],
    )
    assert settings.auth_secure_cookie


@pytest.mark.parametrize(
    "field,value",
    [
        ("auth_session_seconds", 0),
        ("auth_session_seconds", 604801),
        ("auth_window_seconds", 0),
        ("auth_source_limit", 0),
        ("auth_account_limit", 101),
    ],
)
def test_auth_configuration_bounds(field, value):
    with pytest.raises(ValidationError):
        Settings(_env_file=None, db_password="unit-only", **{field: value})


def test_origin_and_invalid_payloads_do_not_touch_database_or_echo_input(settings, caplog):
    app = create_app(settings.model_copy(update={"auth_allowed_origins": (ORIGIN,)}))
    session = MagicMock()
    app.dependency_overrides[get_session] = lambda: session
    sentinel = "never-echo-this-password"
    with TestClient(app) as client:
        for route in ("login", "logout"):
            for headers in ({}, {"Origin": "null"}, {"Origin": "https://attacker.example"}):
                response = client.post(
                    f"/auth/{route}", json={"password": sentinel}, headers=headers
                )
                assert response.status_code == 403
                assert response.headers["cache-control"] == "no-store"
        response = client.post(
            "/auth/login",
            content='{"password":"' + sentinel + '"',
            headers={"Origin": ORIGIN, "Content-Type": "application/json"},
        )
        assert response.status_code == 422
        assert sentinel not in response.text + caplog.text
        response = client.post("/auth/login", content="x" * 16385, headers={"Origin": ORIGIN})
        assert response.status_code == 413
    session.execute.assert_not_called()
    session.begin.assert_not_called()


def test_database_failure_never_authenticates_or_leaks(settings, caplog):
    app = create_app(settings.model_copy(update={"auth_allowed_origins": (ORIGIN,)}))
    session = MagicMock()
    session.in_transaction.return_value = False
    sentinel = "secret-driver-detail"
    session.begin.side_effect = OperationalError("sql", {}, Exception(sentinel))
    app.dependency_overrides[get_session] = lambda: session
    with TestClient(app) as client:
        client.cookies.set("editingtab_session", "a" * 43)
        responses = [
            client.get("/auth/me"),
            client.post(
                "/auth/login",
                json={"email": "demo@example.test", "password": "a" * 15},
                headers={"Origin": ORIGIN},
            ),
            client.post("/auth/logout", headers={"Origin": ORIGIN}),
        ]
        for response in responses:
            assert response.status_code == 503
            assert sentinel not in response.text + caplog.text
            assert "set-cookie" not in response.headers


def test_token_parser_rejects_unbounded_or_malformed_tokens():
    assert token_digest("a" * 43) is not None
    for value in (None, "", "a" * 10000, "!" * 43):
        assert token_digest(value) is None


def test_cli_uses_secure_confirmation_and_never_echoes_secrets(settings, monkeypatch, capsys):
    from editingtab_core.auth import provision

    monkeypatch.setattr(
        "sys.argv", ["provision", "--email", "demo@example.test", "--display-name", "Demo"]
    )
    monkeypatch.setattr(provision, "load_settings", lambda: settings)
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    with patch.object(
        provision.getpass,
        "getpass",
        side_effect=["private-input-password", "different-confirmation"],
    ) as prompt:
        with patch.object(provision, "build_engine") as build:
            assert provision.main() == 1
            assert prompt.call_count == 2
            build.assert_not_called()
    captured = capsys.readouterr()
    assert "private-input-password" not in captured.out + captured.err
    assert "different-confirmation" not in captured.out + captured.err


def test_cli_rejects_password_arguments_without_echoing_them(monkeypatch, capsys):
    from editingtab_core.auth import provision

    monkeypatch.setattr(
        "sys.argv",
        [
            "provision",
            "--email",
            "demo@example.test",
            "--display-name",
            "Demo",
            "--password",
            "never-echo-argument",
        ],
    )
    with pytest.raises(SystemExit) as error:
        provision.main()
    assert error.value.code == 2
    captured = capsys.readouterr()
    assert "never-echo-argument" not in captured.out + captured.err


def test_empty_origin_allowlist_fails_closed(settings):
    with TestClient(create_app(settings)) as client:
        assert client.post("/auth/login", headers={"Origin": ORIGIN}).status_code == 403
