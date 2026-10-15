"""Secret-safe HTTP contract tests for one-time platform setup."""

from hashlib import sha256
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient
from pydantic import SecretStr

from editingtab_core.app import create_app
from editingtab_core.auth.security import SetupThrottled
from editingtab_core.database import get_session

ORIGIN = "http://127.0.0.1:18080"
TOKEN = "a" * 43


def configured(settings):
    return settings.model_copy(
        update={
            "auth_allowed_origins": (ORIGIN,),
            "setup_token_digest": SecretStr(sha256(TOKEN.encode("ascii")).hexdigest()),
        }
    )


def test_setup_status_exposes_one_boolean_without_authentication(settings):
    app = create_app(configured(settings))
    session = MagicMock()
    app.dependency_overrides[get_session] = lambda: session
    with (
        patch(
            "editingtab_core.platform.services.setup_status",
            return_value={"setup_required": True},
        ) as status,
        TestClient(app) as client,
    ):
        response = client.get("/platform/setup/status")
    assert response.status_code == 200
    assert response.json() == {"setup_required": True}
    assert response.headers["cache-control"] == "no-store"
    status.assert_called_once_with(session)


def test_setup_requires_allowed_origin_before_parsing_or_database_access(settings, caplog):
    app = create_app(configured(settings))
    session = MagicMock()
    app.dependency_overrides[get_session] = lambda: session
    sentinel = "setup-secret-that-must-not-leak"
    body = {
        "email": "admin@example.test",
        "password": "valid initial password",
        "password_confirmation": "valid initial password",
        "setup_token": sentinel,
    }
    with TestClient(app) as client:
        response = client.post("/platform/setup", json=body)
        invalid = client.post(
            "/platform/setup",
            content='{"setup_token":"' + sentinel + '",',
            headers={"Origin": ORIGIN, "Content-Type": "application/json"},
        )
    assert response.status_code == 403
    assert invalid.status_code == 422
    assert sentinel not in response.text + invalid.text + caplog.text
    session.begin.assert_not_called()


def test_setup_passes_secrets_only_to_core_service_and_returns_no_identity(settings):
    app = create_app(configured(settings))
    session = MagicMock()
    app.dependency_overrides[get_session] = lambda: session
    with (
        patch(
            "editingtab_core.platform.services.web_setup_initial",
            return_value={"initialized": True},
        ) as setup,
        TestClient(app) as client,
    ):
        response = client.post(
            "/platform/setup",
            headers={"Origin": ORIGIN},
            json={
                "email": "Chosen.Admin@example.test",
                "password": "valid initial password",
                "password_confirmation": "valid initial password",
                "setup_token": TOKEN,
            },
        )
    assert response.status_code == 201
    assert response.json() == {"initialized": True}
    assert response.headers["cache-control"] == "no-store"
    assert setup.call_args.kwargs["email"] == "Chosen.Admin@example.test"
    assert setup.call_args.kwargs["password"] == "valid initial password"
    assert setup.call_args.kwargs["setup_token"] == TOKEN


def test_setup_throttle_returns_setup_window_without_exposing_input(settings):
    app = create_app(configured(settings).model_copy(update={"setup_window_seconds": 617}))
    app.dependency_overrides[get_session] = lambda: MagicMock()
    with (
        patch(
            "editingtab_core.platform.services.web_setup_initial",
            side_effect=SetupThrottled("hidden"),
        ),
        TestClient(app) as client,
    ):
        response = client.post(
            "/platform/setup",
            headers={"Origin": ORIGIN},
            json={
                "email": "admin@example.test",
                "password": "valid initial password",
                "password_confirmation": "valid initial password",
                "setup_token": TOKEN,
            },
        )
    assert response.status_code == 429
    assert response.headers["retry-after"] == "617"
    assert response.json() == {"detail": "Try again later."}
