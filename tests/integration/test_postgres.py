import io

import pytest
from alembic import command
from alembic.script import ScriptDirectory
from fastapi.testclient import TestClient
from sqlalchemy import inspect, text

from editingtab_core.app import create_app
from editingtab_core.identity.models import Base

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


def test_real_migrations_upgrade_current_and_repeat(migration_config, migration_connection):
    connection = migration_connection
    schema = connection.info["core_test_schema"]
    assert inspect(connection).get_table_names(schema=schema) == []
    command.upgrade(migration_config, "0001_foundation")
    assert (
        connection.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
        == "0001_foundation"
    )
    assert inspect(connection).get_table_names(schema=schema) == ["alembic_version"]

    command.upgrade(migration_config, "head")
    expected_head = ScriptDirectory.from_config(migration_config).get_current_head()
    assert expected_head == "0002_core_identity"
    output = io.StringIO()
    migration_config.stdout = output
    command.current(migration_config, verbose=True)
    assert f"{expected_head} (head)" in output.getvalue()
    command.upgrade(migration_config, "head")
    assert connection.execute(text("SELECT version_num FROM alembic_version")).scalars().all() == [
        expected_head
    ]
    inspector = inspect(connection)
    assert set(inspector.get_table_names(schema=schema)) == {
        "alembic_version",
        *Base.metadata.tables,
    }
    for table in Base.metadata.tables:
        columns = {column["name"]: column for column in inspector.get_columns(table, schema=schema)}
        assert set(columns) == set(Base.metadata.tables[table].columns.keys())
        for field in ("created_at", "updated_at", "deleted_at"):
            assert columns[field]["type"].timezone is True
        assert inspector.get_pk_constraint(table, schema=schema)["constrained_columns"] == ["id"]
    constraints = inspector.get_unique_constraints("core_memberships", schema=schema)
    assert any(row["column_names"] == ["organization_id", "user_id"] for row in constraints)
    assert all(
        foreign_key["options"]["ondelete"] == "RESTRICT"
        for foreign_key in inspector.get_foreign_keys("core_memberships", schema=schema)
    )


def test_real_readiness(integration_settings):
    with TestClient(create_app(integration_settings)) as client:
        assert client.get("/health/ready").status_code == 200
        assert client.get("/health/ready").json() == {"status": "ready"}
