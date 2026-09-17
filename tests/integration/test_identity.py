"""Real PostgreSQL transactions and constraints; no mocked database/session."""

from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest
from sqlalchemy import delete, event, func, select
from sqlalchemy.exc import IntegrityError

from editingtab_core.identity import repository, services
from editingtab_core.identity.errors import (
    IdentityConflict,
    IdentityNotFound,
    IdentityStorageError,
    IdentityUnavailable,
)
from editingtab_core.identity.models import Membership, Organization, User

pytestmark = pytest.mark.integration


def seed(session):
    organization_id = services.create_organization(session, name="Safari Lodge", slug="safari")
    user_id = services.create_user(session, email="Desk+Bookings@Example.COM", display_name="Desk")
    membership_id = services.add_membership(
        session, organization_id=organization_id, user_id=user_id
    )
    return organization_id, user_id, membership_id


def test_identifiers_timestamps_and_normal_reads(identity_session):
    session = identity_session
    organization_id, user_id, membership_id = seed(session)
    assert all(isinstance(value, UUID) for value in (organization_id, user_id, membership_id))
    with session.begin():
        organization = repository.get_organization(session, organization_id)
        user = repository.get_user(session, user_id)
        assert organization.slug == "safari"
        assert user.email == "Desk+Bookings@Example.COM"
        assert user.normalized_email == "desk+bookings@example.com"
        assert repository.get_user_by_normalized_email(session, user.normalized_email).id == user_id
        for record in (organization, user, session.get(Membership, membership_id)):
            assert record.created_at.utcoffset() is not None
            assert record.updated_at.utcoffset() is not None
            assert record.deleted_at is None


def test_slug_uniqueness_reserved_after_archive(identity_session):
    session = identity_session
    organization_id = services.create_organization(session, name="First", slug=" SAFARI ")
    for archived in (False, True):
        if archived:
            services.archive_organization(session, organization_id=organization_id)
        with pytest.raises(IdentityConflict, match="slug is already reserved"):
            services.create_organization(session, name="Another", slug="safari")
        assert not session.in_transaction()
    with session.begin():
        assert session.scalar(select(func.count()).select_from(Organization)) == 1
        assert repository.get_organization(session, organization_id) is None


def test_email_uniqueness_reserved_after_archive(identity_session):
    session = identity_session
    user_id = services.create_user(session, email=" Alice+desk@Example.com ", display_name="Alice")
    for archived in (False, True):
        if archived:
            with session.begin():
                session.get(User, user_id).deleted_at = datetime.now(UTC)
        with pytest.raises(IdentityConflict, match="Email identity is already reserved") as error:
            services.create_user(session, email="alice+DESK@example.COM", display_name="Duplicate")
        assert "Alice" not in str(error.value)
        assert "example" not in str(error.value)
        assert error.value.__suppress_context__
        assert not session.in_transaction()
    with session.begin():
        assert session.scalar(select(func.count()).select_from(User)) == 1
        assert repository.get_user(session, user_id) is None
        assert repository.get_user_by_normalized_email(session, "alice+desk@example.com") is None


def test_one_user_in_two_organizations(identity_session):
    session = identity_session
    first, user_id, membership_id = seed(session)
    second = services.create_organization(session, name="Second", slug="second")
    other_membership = services.add_membership(session, organization_id=second, user_id=user_id)
    assert membership_id != other_membership
    assert [row.id for row in services.list_active_memberships(session, organization_id=first)] == [
        membership_id
    ]
    assert [
        row.id for row in services.list_active_memberships(session, organization_id=second)
    ] == [other_membership]

    services.archive_organization(session, organization_id=first)
    assert services.list_active_memberships(session, organization_id=first) == []
    assert (
        services.get_membership(
            session, organization_id=second, membership_id=other_membership
        ).user_id
        == user_id
    )
    with session.begin():
        assert repository.get_user(session, user_id).is_active is True


def test_duplicate_add_and_restore_reuse_one_row(identity_session):
    session = identity_session
    organization_id, user_id, membership_id = seed(session)
    before = services.get_membership(
        session, organization_id=organization_id, membership_id=membership_id
    )
    assert (
        services.add_membership(session, organization_id=organization_id, user_id=user_id)
        == membership_id
    )
    services.archive_membership(
        session, organization_id=organization_id, membership_id=membership_id
    )
    assert services.list_active_memberships(session, organization_id=organization_id) == []
    with session.begin():
        record = session.get(Membership, membership_id)
        archived_at = record.deleted_at
        assert archived_at.utcoffset() is not None
        assert session.scalar(select(func.count()).select_from(Membership)) == 1
    services.archive_membership(
        session, organization_id=organization_id, membership_id=membership_id
    )
    with session.begin():
        assert session.get(Membership, membership_id).deleted_at == archived_at
    assert (
        services.add_membership(session, organization_id=organization_id, user_id=user_id)
        == membership_id
    )
    after = services.get_membership(
        session, organization_id=organization_id, membership_id=membership_id
    )
    assert after.created_at == before.created_at
    assert after.updated_at >= before.updated_at
    with session.begin():
        assert session.scalar(select(func.count()).select_from(Membership)) == 1
        assert session.get(Membership, membership_id).deleted_at is None


def test_cross_organization_read_and_archive_rejected(identity_session):
    session = identity_session
    organization_b, _, membership_b = seed(session)
    organization_a = services.create_organization(session, name="Other", slug="other")
    with session.begin():
        assert (
            repository.get_active_membership(
                session, organization_id=organization_a, membership_id=membership_b
            )
            is None
        )
    with pytest.raises(IdentityNotFound):
        services.get_membership(session, organization_id=organization_a, membership_id=membership_b)
    with pytest.raises(IdentityNotFound):
        services.archive_membership(
            session, organization_id=organization_a, membership_id=membership_b
        )
    assert (
        services.get_membership(
            session, organization_id=organization_b, membership_id=membership_b
        ).id
        == membership_b
    )


@pytest.mark.parametrize("state", ["organization", "user", "inactive_user", "membership"])
def test_active_membership_filtering_and_record_retention(identity_session, state):
    session = identity_session
    organization_id, user_id, membership_id = seed(session)
    if state == "organization":
        services.archive_organization(session, organization_id=organization_id)
        services.archive_organization(session, organization_id=organization_id)
    elif state == "membership":
        services.archive_membership(
            session, organization_id=organization_id, membership_id=membership_id
        )
    else:
        with session.begin():
            user = session.get(User, user_id)
            if state == "user":
                user.deleted_at = datetime.now(UTC)
            else:
                user.is_active = False
    assert services.list_active_memberships(session, organization_id=organization_id) == []
    with pytest.raises(IdentityNotFound):
        services.get_membership(
            session, organization_id=organization_id, membership_id=membership_id
        )
    with session.begin():
        assert session.get(Organization, organization_id) is not None
        assert session.get(User, user_id) is not None
        assert session.get(Membership, membership_id) is not None


@pytest.mark.parametrize("state", ["organization", "user", "inactive_user", "missing_user"])
def test_add_or_restore_requires_available_parents(identity_session, state):
    session = identity_session
    organization_id, user_id, membership_id = seed(session)
    services.archive_membership(
        session, organization_id=organization_id, membership_id=membership_id
    )
    if state == "organization":
        services.archive_organization(session, organization_id=organization_id)
    elif state == "missing_user":
        user_id = uuid4()
    else:
        with session.begin():
            user = session.get(User, user_id)
            if state == "user":
                user.deleted_at = datetime.now(UTC)
            else:
                user.is_active = False
    with pytest.raises(IdentityUnavailable):
        services.add_membership(session, organization_id=organization_id, user_id=user_id)
    with session.begin():
        assert session.get(Membership, membership_id).deleted_at is not None
        assert session.scalar(select(func.count()).select_from(Membership)) == 1


def test_database_rejects_duplicate_pairs_and_missing_parents(identity_session):
    session = identity_session
    organization_id, user_id, _ = seed(session)
    with pytest.raises(IntegrityError):
        with session.begin():
            repository.create_membership(session, organization_id=organization_id, user_id=user_id)
    with pytest.raises(IntegrityError):
        with session.begin():
            repository.create_membership(session, organization_id=organization_id, user_id=uuid4())
    assert len(services.list_active_memberships(session, organization_id=organization_id)) == 1


def test_database_normalization_constraints_cannot_be_bypassed(identity_session):
    session = identity_session
    with pytest.raises(IntegrityError):
        with session.begin():
            repository.create_organization(session, name="Invalid", slug="UPPERCASE")
    with pytest.raises(IntegrityError):
        with session.begin():
            repository.create_user(
                session,
                email="Alice@Example.com",
                normalized_email="different@example.com",
                display_name="Invalid",
            )
    assert services.create_user(session, email="valid@example.com", display_name="Valid")


def test_foreign_keys_do_not_cascade_hard_deletes(identity_session):
    session = identity_session
    organization_id, user_id, membership_id = seed(session)
    for model, identifier in ((Organization, organization_id), (User, user_id)):
        with pytest.raises(IntegrityError):
            with session.begin():
                session.execute(delete(model).where(model.id == identifier))
    assert (
        services.get_membership(
            session, organization_id=organization_id, membership_id=membership_id
        ).id
        == membership_id
    )


def test_failed_write_removes_flushed_rows_and_session_is_reusable(identity_session, monkeypatch):
    session = identity_session
    services.create_user(session, email="existing@example.com", display_name="Existing")
    original = repository.create_user

    def insert_then_conflict(session, **values):
        original(session, **values)  # Actually flushed to PostgreSQL before the failure.
        return original(
            session,
            email="existing@example.com",
            normalized_email="existing@example.com",
            display_name="Conflict",
        )

    with monkeypatch.context() as patch:
        patch.setattr(repository, "create_user", insert_then_conflict)
        with pytest.raises(IdentityConflict):
            services.create_user(session, email="partial@example.com", display_name="Partial")
    assert not session.in_transaction()
    with session.begin():
        assert repository.get_user_by_normalized_email(session, "partial@example.com") is None
        assert session.scalar(select(func.count()).select_from(User)) == 1
    assert services.create_user(session, email="partial@example.com", display_name="Retry")


def test_services_own_savepoint_commit_and_rollback(identity_session):
    session = identity_session
    connection = session.get_bind()
    events = []

    def released(connection, name, context):
        events.append("commit")

    def rolled_back(connection, name, context):
        events.append("rollback")

    event.listen(connection, "release_savepoint", released)
    event.listen(connection, "rollback_savepoint", rolled_back)
    try:
        services.create_organization(session, name="First", slug="first")
        with pytest.raises(IdentityConflict):
            services.create_organization(session, name="Duplicate", slug="first")
        assert events == ["commit", "rollback"]
        assert not session.in_transaction()
        assert connection.in_transaction()  # Fixture isolation remains intact.
        assert services.create_organization(session, name="Second", slug="second")
    finally:
        event.remove(connection, "release_savepoint", released)
        event.remove(connection, "rollback_savepoint", rolled_back)


def test_service_does_not_commit_callers_pending_work(identity_session):
    session = identity_session
    with session.begin():
        pending = repository.create_organization(session, name="Caller", slug="caller")
        with pytest.raises(IdentityStorageError, match="without an active transaction"):
            services.create_user(session, email="unexpected@example.com", display_name="Unexpected")
        assert pending in session
        assert session.in_transaction()
    with session.begin():
        assert session.scalar(select(func.count()).select_from(User)) == 0
