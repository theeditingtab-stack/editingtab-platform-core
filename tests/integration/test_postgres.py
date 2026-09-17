import io

import pytest
from alembic import command
from alembic.script import ScriptDirectory
from fastapi.testclient import TestClient
from sqlalchemy import DateTime, inspect, text
from sqlalchemy.orm import Session

from editingtab_core.app import create_app
from editingtab_core.identity import services as identity
from editingtab_core.identity.models import Base, User

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

    command.upgrade(migration_config, "0002_core_identity")
    assert (
        connection.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
        == "0002_core_identity"
    )
    assert set(inspect(connection).get_table_names(schema=schema)) == {
        "alembic_version",
        "core_users",
        "core_organizations",
        "core_memberships",
    }
    with Session(bind=connection, join_transaction_mode="create_savepoint") as session:
        existing_id = identity.create_user(
            session, email="preserved@example.test", display_name="Preserved"
        )
    command.upgrade(migration_config, "head")
    with Session(bind=connection, join_transaction_mode="create_savepoint") as session:
        assert session.get(User, existing_id).email == "preserved@example.test"
    expected_head = ScriptDirectory.from_config(migration_config).get_current_head()
    assert expected_head == "0003_password_sessions"
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
        model = Base.metadata.tables[table]
        for column in model.columns:
            if isinstance(column.type, DateTime):
                assert columns[column.name]["type"].timezone is True
        assert inspector.get_pk_constraint(table, schema=schema)["constrained_columns"] == list(
            model.primary_key.columns.keys()
        )
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
