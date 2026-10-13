import pytest
from pydantic import ValidationError

from editingtab_core.config import ConfigurationError, Settings, load_settings


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("environment", "unknown"),
        ("db_port", 0),
        ("db_port", 65536),
        ("db_connect_timeout", 1),
        ("db_connect_timeout", 11),
        ("db_host", "host1,host2"),
        ("db_name", "not a database"),
        ("db_username", " "),
        ("service_name", ""),
        ("db_password", ""),
        ("db_password", "REPLACE_WITH_GENERATED_LOCAL_PASSWORD"),
    ],
)
def test_invalid_settings(field, value):
    values = {"db_password": "test-only-secret", field: value}
    with pytest.raises(ValidationError):
        Settings(_env_file=None, **values)


def test_password_required():
    with pytest.raises(ValidationError):
        Settings(_env_file=None)


def test_managed_postgres_connection_string_is_secret_and_uses_psycopg():
    secret = "postgresql://core_user:p%40ss@db.internal:5432/editingtab_core"
    settings = Settings(_env_file=None, environment="production", database_dsn=secret)

    url = settings.database_url()
    assert url.drivername == "postgresql+psycopg"
    assert url.host == "db.internal"
    assert url.password == "p@ss"
    assert secret not in repr(settings)
    assert "database_dsn" not in settings.model_dump()


def test_database_credential_sources_are_mutually_exclusive():
    with pytest.raises(ValidationError):
        Settings(
            _env_file=None,
            db_password="unit-only",
            database_dsn="postgresql://user:password@db.internal:5432/editingtab_core",
        )


def test_production_component_database_target_must_be_explicit():
    with pytest.raises(ValidationError):
        Settings(_env_file=None, environment="production", db_password="unit-only")


def test_url_preserves_special_characters(settings):
    url = settings.database_url()
    assert url.password == "unit-only-P@ss:/%#'secret"
    assert url.username == "editingtab_test"
    assert url.database == "editingtab_core_test"
    assert url.host == "127.0.0.1"
    assert url.port == 15433
    assert url.drivername == "postgresql+psycopg"
    assert url.password not in str(url)
    assert url.password not in repr(settings)
    assert "db_password" not in settings.model_dump()
    assert url.password not in settings.model_dump_json()


def test_environment_prefix(monkeypatch):
    monkeypatch.setenv("CORE_DB_PASSWORD", "test-only")
    monkeypatch.setenv("CORE_DB_PORT", "25432")
    monkeypatch.setenv("CORE_ENVIRONMENT", "test")
    settings = load_settings(env_file=None)
    assert settings.db_port == 25432
    assert settings.environment == "test"


def test_validation_does_not_echo_input(monkeypatch):
    sentinel = "credential-like-invalid-value"
    monkeypatch.setenv("CORE_DB_PASSWORD", sentinel)
    monkeypatch.setenv("CORE_DB_PORT", sentinel)
    with pytest.raises(ConfigurationError) as error:
        load_settings(env_file=None)
    assert sentinel not in str(error.value)
    assert error.value.__suppress_context__ is True


def test_malformed_complex_environment_value_is_sanitized(monkeypatch):
    sentinel = "credential-like-invalid-origin"
    monkeypatch.setenv("CORE_DB_PASSWORD", "test-only")
    monkeypatch.setenv("CORE_AUTH_ALLOWED_ORIGINS", f"[{sentinel}]")
    with pytest.raises(ConfigurationError) as error:
        load_settings(env_file=None)
    assert sentinel not in str(error.value)
    assert error.value.__suppress_context__ is True


def test_default_settings_do_not_read_dotenv(tmp_path):
    (tmp_path / ".env").write_text("CORE_DB_PASSWORD=should-not-be-read\n")
    with pytest.raises(ValidationError):
        Settings()
