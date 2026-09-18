import hashlib
import importlib.util
from pathlib import Path

import pytest
from pydantic import SecretStr, ValidationError

from editingtab_core.config import Settings
from editingtab_core.internal.booking import trusted_transport, valid_service

CURRENT = "current-test-only-" + "c" * 32
PREVIOUS = "previous-test-only-" + "p" * 32


def configured(settings):
    return settings.model_copy(
        update={
            "booking_service_current_digest": SecretStr(
                hashlib.sha256(CURRENT.encode()).hexdigest()
            ),
            "booking_service_previous_digest": SecretStr(
                hashlib.sha256(PREVIOUS.encode()).hexdigest()
            ),
        }
    )


@pytest.mark.parametrize(
    "value,expected",
    [
        (None, False),
        ("", False),
        ("Basic abc", False),
        ("Bearer " + CURRENT, True),
        ("Bearer " + PREVIOUS, True),
        ("Bearer " + "x" * 43, False),
        ("Bearer " + "x" * 10000, False),
        ("Bearer short", False),
        ("Bearer " + "?" * 43, False),
    ],
)
def test_service_credentials(settings, value, expected):
    assert valid_service(configured(settings), value) is expected


def test_missing_current_disables_even_previous(settings):
    settings = configured(settings).model_copy(update={"booking_service_current_digest": None})
    assert not valid_service(settings, "Bearer " + PREVIOUS)
    assert not valid_service(
        settings.model_copy(update={"booking_service_previous_digest": None}), "Bearer " + CURRENT
    )


@pytest.mark.parametrize("value", ["not-a-digest", "a" * 63, "A" * 64, "g" * 64, ""])
def test_malformed_configuration(value):
    with pytest.raises(ValidationError):
        Settings(_env_file=None, db_password="test-only", booking_service_current_digest=value)


def test_config_hides_digests(settings):
    settings = configured(settings)
    assert settings.booking_service_current_digest.get_secret_value() not in repr(settings)
    assert "booking_service_current_digest" not in settings.model_dump()


@pytest.mark.parametrize(
    "scheme,peer,production,allowed",
    [
        ("http", "127.0.0.1", False, True),
        ("http", "::1", False, True),
        ("http", "10.0.0.1", False, False),
        ("http", "127.0.0.1", True, False),
        ("https", "10.0.0.1", True, True),
    ],
)
def test_transport(settings, scheme, peer, production, allowed):
    if production:
        settings = settings.model_copy(update={"environment": "production"})
    assert trusted_transport({"scheme": scheme, "client": (peer, 100)}, settings) is allowed


def test_helper_exclusive_matching_files_without_output(tmp_path, capsys):
    path = Path(__file__).resolve().parents[2] / "scripts/init-booking-credential.py"
    spec = importlib.util.spec_from_file_location("credential_setup", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    raw, digest = module.create_pair(tmp_path / "private")
    raw_value = raw.read_bytes()
    assert len(raw_value) >= 43
    assert hashlib.sha256(raw_value).hexdigest() == digest.read_text()
    assert capsys.readouterr().out == ""
    with pytest.raises(FileExistsError):
        module.create_pair(tmp_path / "private")
    assert raw.read_bytes() == raw_value
    # Either existing counterpart blocks setup without creating the other file.
    second = tmp_path / "second"
    second.mkdir()
    (second / "booking-service.sha256").write_text("existing test value")
    with pytest.raises(FileExistsError):
        module.create_pair(second)
    assert not (second / "booking-service.secret").exists()


@pytest.mark.parametrize(
    "case",
    ["duplicate_service", "duplicate_session", "oversized_body", "invalid_json", "forwarded_http"],
)
def test_exact_guard_safe_errors_and_no_database_access(settings, case):
    from unittest.mock import patch

    from fastapi.testclient import TestClient

    from editingtab_core.app import create_app
    from editingtab_core.internal.booking import PATH

    config = configured(settings)
    peer = "10.0.0.2" if case == "forwarded_http" else "127.0.0.1"
    headers = [
        ("Authorization", "Bearer " + CURRENT),
        ("X-Core-Session", "s" * 43),
        ("Content-Type", "application/json"),
    ]
    body = b"{}"
    status, code = 422, "invalid_authorization_request"
    if case == "duplicate_service":
        headers.append(headers[0])
        status, code = 401, "invalid_service_credentials"
    elif case == "duplicate_session":
        headers.append(headers[1])
        status, code = 401, "invalid_user_session"
    elif case == "oversized_body":
        body = b"x" * 4097
    elif case == "invalid_json":
        body = b"not-json"
    else:
        headers.append(("X-Forwarded-Proto", "https"))
        headers.append(("X-Forwarded-For", "127.0.0.1"))
        status, code = 401, "invalid_service_credentials"
    with TestClient(create_app(config), client=(peer, 1)) as client:
        with patch("editingtab_core.internal.booking.auth_repo.authenticated_user") as lookup:
            response = client.post(PATH, headers=headers, content=body)
            assert response.status_code == status
            assert response.json() == {"error": code}
            assert response.headers["cache-control"] == "no-store"
            assert CURRENT not in response.text and "s" * 43 not in response.text
            lookup.assert_not_called()
