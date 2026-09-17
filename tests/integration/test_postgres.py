import io

import pytest
from alembic import command
from fastapi.testclient import TestClient
from sqlalchemy import inspect, text

from editingtab_core.app import create_app

pytestmark = pytest.mark.integration


def test_real_database_connectivity(integration_engine):
    with integration_engine.connect() as connection:
        assert connection.execute(text("SELECT 1")).scalar_one() == 1
        assert (
            connection.execute(text("SELECT current_database()")).scalar_one()
            == "editingtab_core_test"
        )
        assert connection.execute(text("SELECT current_user")).scalar_one() == "editingtab_test"
        assert connection.dialect.server_version_info[0] == 17


def test_real_migrations_upgrade_current_and_repeat(migration_config, integration_engine):
    command.upgrade(migration_config, "head")
    output = io.StringIO()
    migration_config.stdout = output
    command.current(migration_config, verbose=True)
    assert "0001_foundation (head)" in output.getvalue()
    command.upgrade(migration_config, "head")
    with integration_engine.connect() as connection:
        assert connection.execute(
            text("SELECT version_num FROM alembic_version")
        ).scalars().all() == ["0001_foundation"]
        assert inspect(connection).get_table_names() == ["alembic_version"]


def test_real_readiness(integration_settings):
    with TestClient(create_app(integration_settings)) as client:
        assert client.get("/health/ready").status_code == 200
        assert client.get("/health/ready").json() == {"status": "ready"}
