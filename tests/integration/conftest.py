from pathlib import Path
from uuid import uuid4

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import text
from sqlalchemy.orm import Session

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
def migration_config(integration_settings, migration_connection):
    config = Config(str(ROOT / "alembic.ini"))
    config.attributes["settings"] = integration_settings
    config.attributes["connection"] = migration_connection
    return config


@pytest.fixture
def migration_connection(integration_engine):
    # A new transactional schema never changes existing test tables or public.
    # Identity guard is checked before DDL, in addition to explicit settings.
    schema = f"core_test_{uuid4().hex}"
    with integration_engine.connect() as connection:
        outer = connection.begin()
        try:
            identity = connection.execute(text("SELECT current_database(), current_user")).one()
            if tuple(identity) != ("editingtab_core_test", "editingtab_test"):
                raise ValueError("Refusing schema setup outside the isolated test database")
            connection.exec_driver_sql(f'CREATE SCHEMA "{schema}"')
            connection.exec_driver_sql(f'SET LOCAL search_path TO "{schema}"')
            connection.info["core_test_schema"] = schema
            yield connection
        finally:
            intact = outer.is_active
            if intact:
                outer.rollback()
            assert intact, "Test code ended the outer isolation transaction"
    with integration_engine.connect() as connection:
        assert (
            connection.execute(
                text("SELECT count(*) FROM pg_namespace WHERE nspname = :schema"),
                {"schema": schema},
            ).scalar_one()
            == 0
        ), "Transactional test schema was not rolled back"


@pytest.fixture
def identity_session(migration_config, migration_connection):
    command.upgrade(migration_config, "head")
    # Service begin/commit/rollback remain real; only the outer transaction is
    # fixture-owned. A failed service rolls back its savepoint, not other setup.
    with Session(
        bind=migration_connection,
        join_transaction_mode="create_savepoint",
        expire_on_commit=False,
    ) as session:
        yield session
