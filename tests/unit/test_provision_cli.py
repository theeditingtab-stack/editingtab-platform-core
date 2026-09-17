"""CLI diagnostics use synthetic inputs and never connect to a real database."""

from unittest.mock import MagicMock

import pytest
from argon2.exceptions import HashingError
from sqlalchemy.exc import OperationalError

from editingtab_core.auth import provision
from editingtab_core.auth.security import AuthenticationUnavailable, CredentialConflict
from editingtab_core.config import ConfigurationError
from editingtab_core.identity.errors import IdentityStorageError, InvalidIdentity

SENTINEL = "sensitive-input-must-not-be-printed"


@pytest.fixture
def cli(monkeypatch, settings):
    monkeypatch.setattr(
        "sys.argv", ["provision", "--email", "demo@example.test", "--display-name", "Demo"]
    )
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr(provision, "load_settings", lambda: settings)
    prompt = MagicMock(side_effect=[SENTINEL, SENTINEL])
    monkeypatch.setattr(provision.getpass, "getpass", prompt)
    engine = MagicMock()
    monkeypatch.setattr(provision, "build_engine", engine)
    monkeypatch.setattr(provision, "Session", MagicMock())
    monkeypatch.setattr(provision, "Passwords", MagicMock())
    operation = MagicMock()
    monkeypatch.setattr(provision, "provision_user", operation)
    return prompt, engine, operation


@pytest.mark.parametrize(
    "error,category",
    [
        (CredentialConflict(SENTINEL), "Credentials already exist"),
        (provision.UnavailableIdentity(SENTINEL), "Identity is inactive or archived"),
        (AuthenticationUnavailable(SENTINEL), "Database unavailable or migration missing"),
        (IdentityStorageError(SENTINEL), "Database unavailable or migration missing"),
        (
            OperationalError(SENTINEL, {}, Exception(SENTINEL)),
            "Database unavailable or migration missing",
        ),
        (HashingError(SENTINEL), "Password hashing unavailable"),
        (InvalidIdentity(SENTINEL), "Invalid email or display name"),
    ],
)
def test_cli_categorizes_errors_without_raw_details(cli, capsys, error, category):
    _, engine, operation = cli
    operation.side_effect = error
    assert provision.main() == 1
    output = capsys.readouterr()
    assert category in output.err
    assert SENTINEL not in output.out + output.err
    engine.return_value.dispose.assert_called_once()
    assert operation.call_count == 1  # No retry, reset, or credential replacement.


@pytest.mark.parametrize("length", [0, 14, 1025])
def test_invalid_length_stops_before_database_access(cli, capsys, length):
    prompt, engine, operation = cli
    prompt.side_effect = ["x" * length, "x" * length]
    assert provision.main() == 1
    assert "Password length invalid; use 15-1024 characters" in capsys.readouterr().err
    engine.assert_not_called()
    operation.assert_not_called()


def test_confirmation_mismatch_is_specific_and_safe(cli, capsys):
    prompt, engine, operation = cli
    prompt.side_effect = [SENTINEL, SENTINEL + "different"]
    assert provision.main() == 1
    output = capsys.readouterr()
    assert "Password confirmation mismatch" in output.err
    assert SENTINEL not in output.out + output.err
    engine.assert_not_called()
    operation.assert_not_called()


def test_configuration_failure_precedes_password_prompt(cli, capsys, monkeypatch):
    prompt, engine, operation = cli
    monkeypatch.setattr(
        provision, "load_settings", MagicMock(side_effect=ConfigurationError(SENTINEL))
    )
    assert provision.main() == 1
    output = capsys.readouterr()
    assert "Configuration invalid" in output.err
    assert SENTINEL not in output.out + output.err
    prompt.assert_not_called()
    engine.assert_not_called()
    operation.assert_not_called()


def test_fresh_terminal_requires_explicit_environment(cli, capsys, monkeypatch):
    from editingtab_core.config import load_settings

    prompt, engine, operation = cli
    monkeypatch.setattr(provision, "load_settings", load_settings)
    monkeypatch.setenv("CORE_DB_PASSWORD", "synthetic-test-only")
    assert provision.main() == 1
    assert "Development/test environment required" in capsys.readouterr().err
    prompt.assert_not_called()
    engine.assert_not_called()
    monkeypatch.setenv("CORE_ENVIRONMENT", "development")
    assert provision.main() == 0
    operation.assert_called_once()
