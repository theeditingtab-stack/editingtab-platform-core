from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient
from sqlalchemy.exc import OperationalError

from editingtab_core.app import create_app
from editingtab_core.database import get_session


def test_live_does_not_connect_and_engine_is_disposed(settings):
    with patch("editingtab_core.app.build_engine") as build:
        engine = build.return_value
        app = create_app(settings)
        build.assert_not_called()
        with TestClient(app) as client:
            assert client.get("/health/live").json() == {"status": "alive"}
            assert client.get("/health/live").status_code == 200
            engine.connect.assert_not_called()
            engine.dispose.assert_not_called()
        engine.dispose.assert_called_once()


def test_readiness_success_is_mocked(settings):
    session = MagicMock()
    session.execute.return_value.scalar_one.return_value = 1
    app = create_app(settings)
    app.dependency_overrides[get_session] = lambda: session
    with TestClient(app) as client:
        response = client.get("/health/ready")
    assert response.status_code == 200
    assert response.json() == {"status": "ready"}
    assert str(session.execute.call_args.args[0]) == "SELECT 1"


def test_readiness_failure_is_generic_and_can_recover(settings, caplog):
    password = settings.db_password.get_secret_value()
    session = MagicMock()
    session.execute.side_effect = OperationalError(
        "SELECT 1", {}, Exception(f"connection failed: {password}")
    )
    app = create_app(settings)
    app.dependency_overrides[get_session] = lambda: session
    with TestClient(app) as client:
        response = client.get("/health/ready")
        assert response.status_code == 503
        assert response.json() == {"status": "unavailable"}
        assert password not in response.text + caplog.text
        assert client.get("/health/live").status_code == 200
        session.execute.side_effect = None
        assert client.get("/health/ready").status_code == 200


def test_session_closes_after_failure(settings):
    app = create_app(settings)
    with TestClient(app) as client:
        session = MagicMock()
        session.execute.side_effect = OperationalError("SELECT 1", {}, Exception("test"))
        factory = MagicMock()
        factory.return_value.__enter__.return_value = session
        app.state.session_factory = factory
        assert client.get("/health/ready").status_code == 503
        factory.return_value.__exit__.assert_called_once()
        session.commit.assert_not_called()
