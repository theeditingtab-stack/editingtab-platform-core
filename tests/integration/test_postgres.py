import io

import pytest
from alembic import command
from alembic.script import ScriptDirectory
from fastapi.testclient import TestClient
from sqlalchemy import DateTime, inspect, select, text
from sqlalchemy.orm import Session

from editingtab_core.app import create_app
from editingtab_core.auth.models import PasswordCredential
from editingtab_core.auth.security import Passwords
from editingtab_core.authorization import repository as authorization_repo
from editingtab_core.authorization.models import (
    MembershipRole,
    PermissionDefinition,
    Role,
    RolePermission,
)
from editingtab_core.authorization.policy import BOOKING_INVENTORY_PERMISSIONS
from editingtab_core.identity import services as identity
from editingtab_core.identity.models import Base, Membership, User

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
    command.upgrade(migration_config, "0003_password_sessions")
    with Session(bind=connection, join_transaction_mode="create_savepoint") as session:
        org_id = identity.create_organization(session, name="Preserved", slug="preserved")
        member_id = identity.add_membership(session, organization_id=org_id, user_id=existing_id)
        with session.begin():
            session.add(
                PasswordCredential(
                    user_id=existing_id,
                    password_hash=Passwords().hash("synthetic preserved password"),
                )
            )
    command.upgrade(migration_config, "0006_booking_authorization")
    from uuid import uuid4

    owned_id, role_id, booking_role_id = org_id, uuid4(), uuid4()
    connection.execute(
        text(
            "INSERT INTO core_roles "
            "(id, organization_id, name, normalized_name, provisioning_kind) "
            "VALUES (:id, :org, 'Booking inventory administrator', "
            "'booking inventory administrator', 'booking_inventory')"
        ),
        {"id": booking_role_id, "org": org_id},
    )
    connection.execute(
        text(
            "INSERT INTO core_roles (id, organization_id, name, normalized_name) "
            "VALUES (:id, :org, 'Preserved', 'preserved')"
        ),
        {"id": role_id, "org": org_id},
    )
    connection.execute(
        text(
            "INSERT INTO core_membership_roles (organization_id, membership_id, role_id) "
            "VALUES (:org, :member, :role)"
        ),
        {"org": org_id, "member": member_id, "role": role_id},
    )
    legacy_owner_permissions = {
        "core.organization.read",
        "core.members.read",
        "core.roles.read",
        "core.roles.manage",
    }
    preserved_codes = legacy_owner_permissions
    for code in preserved_codes:
        connection.execute(
            text(
                "INSERT INTO core_role_permissions (organization_id, role_id, code) "
                "VALUES (:org, :role, :code)"
            ),
            {"org": org_id, "role": role_id, "code": code},
        )
    for code in BOOKING_INVENTORY_PERMISSIONS:
        connection.execute(
            text(
                "INSERT INTO core_role_permissions (organization_id, role_id, code) "
                "VALUES (:org, :role, :code)"
            ),
            {"org": org_id, "role": booking_role_id, "code": code},
        )
    command.upgrade(migration_config, "0007_permission_registry")
    assert (
        connection.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
        == "0007_permission_registry"
    )
    command.upgrade(migration_config, "head")
    granular_operations = {
        "core.roles.create",
        "core.roles.update",
        "core.roles.archive",
        "core.roles.assign",
    }
    migrated_codes = preserved_codes | granular_operations | {"core.members.manage"}
    with Session(bind=connection, join_transaction_mode="create_savepoint") as session:
        assert session.get(Role, role_id).organization_id == owned_id
        assert (
            session.scalar(
                select(MembershipRole.role_id).where(MembershipRole.organization_id == owned_id)
            )
            == role_id
        )
        assert (
            set(
                session.scalars(
                    select(RolePermission.code).where(RolePermission.role_id == role_id)
                )
            )
            == migrated_codes
        )
        assert (
            set(
                session.scalars(
                    select(RolePermission.code).where(
                        RolePermission.role_id == role_id,
                        RolePermission.can_grant.is_(True),
                    )
                )
            )
            == migrated_codes
        )
        assert dict(
            session.execute(
                select(RolePermission.code, RolePermission.can_grant).where(
                    RolePermission.role_id == booking_role_id
                )
            ).all()
        ) == dict.fromkeys(BOOKING_INVENTORY_PERMISSIONS, False)
        assert authorization_repo.has_administrator(session, org_id)
        definitions = session.scalars(select(PermissionDefinition)).all()
        assert len(definitions) == 20
        assert {row.code for row in definitions} >= preserved_codes
        assert session.get(User, existing_id).email == "preserved@example.test"
        assert session.get(Membership, member_id).user_id == existing_id
        assert Passwords().verify(
            session.get(PasswordCredential, existing_id).password_hash,
            "synthetic preserved password",
        )
    expected_head = ScriptDirectory.from_config(migration_config).get_current_head()
    assert expected_head == "0010_account_onboarding"
    output = io.StringIO()
    migration_config.stdout = output
    command.current(migration_config, verbose=True)
    assert f"{expected_head} (head)" in output.getvalue()
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


def test_empty_0008_downgrade_and_reupgrade(migration_config, migration_connection):
    command.upgrade(migration_config, "head")
    command.downgrade(migration_config, "0007_permission_registry")
    assert (
        migration_connection.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
        == "0007_permission_registry"
    )
    assert "can_grant" not in {
        column["name"]
        for column in inspect(migration_connection).get_columns("core_role_permissions")
    }
    command.upgrade(migration_config, "head")
    assert (
        migration_connection.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
        == "0010_account_onboarding"
    )


def test_real_readiness(integration_settings):
    with TestClient(create_app(integration_settings)) as client:
        assert client.get("/health/ready").status_code == 200
        assert client.get("/health/ready").json() == {"status": "ready"}
