from pathlib import Path

import pytest
from alembic.config import Config

from editingtab_core.config import Settings
from editingtab_core.database import build_engine

ROOT = Path(__file__).resolve().parents[2]


def explicit_test_settings(values: dict[str, str]) -> Settings:
    required = ("HOST", "PORT", "NAME", "USERNAME", "PASSWORD")
    if any(not values.get(f"CORE_TEST_DB_{key}") for key in required):
        raise ValueError("Integration tests require every explicit CORE_TEST_DB_ setting")
    if (
        values["CORE_TEST_DB_HOST"] not in {"127.0.0.1", "localhost"}
        or values["CORE_TEST_DB_NAME"] != "editingtab_core_test"
        or values["CORE_TEST_DB_USERNAME"] != "editingtab_test"
        or values["CORE_TEST_DB_PORT"] == "15432"
    ):
        raise ValueError("Refusing a non-isolated integration database")
    return Settings(
        _env_file=None,
        environment="test",
        db_host=values["CORE_TEST_DB_HOST"],
        db_port=values["CORE_TEST_DB_PORT"],
        db_name=values["CORE_TEST_DB_NAME"],
        db_username=values["CORE_TEST_DB_USERNAME"],
        db_password=values["CORE_TEST_DB_PASSWORD"],
    )


@pytest.fixture
def integration_settings(pytestconfig):
    return explicit_test_settings(pytestconfig.core_test_environment)


@pytest.fixture
def integration_engine(integration_settings):
    engine = build_engine(integration_settings)
    try:
        yield engine
    finally:
        engine.dispose()


@pytest.fixture
def migration_config(integration_settings):
    config = Config(str(ROOT / "alembic.ini"))
    config.attributes["settings"] = integration_settings
    return config
