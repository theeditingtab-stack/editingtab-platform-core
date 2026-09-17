"""Internal operations; callers must provide an idle Session, not a caller transaction."""

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from editingtab_core.authorization.services import (
    before_membership_archive,
    before_membership_restore,
)
from editingtab_core.identity import repository
from editingtab_core.identity.errors import (
    IdentityConflict,
    IdentityNotFound,
    IdentityStorageError,
    IdentityUnavailable,
)
from editingtab_core.identity.models import Membership
from editingtab_core.identity.normalization import clean_name, normalize_email, normalize_slug


@dataclass(frozen=True)
class MembershipInfo:
    id: UUID
    organization_id: UUID
    user_id: UUID
    created_at: datetime
    updated_at: datetime


def _membership_info(membership: Membership) -> MembershipInfo:
    return MembershipInfo(
        membership.id,
        membership.organization_id,
        membership.user_id,
        membership.created_at,
        membership.updated_at,
    )


@contextmanager
def _transaction(session: Session) -> Iterator[None]:
    # Do not silently commit or roll back a caller's unrelated pending work.
    if session.in_transaction():
        raise IdentityStorageError(
            "Identity operations require a session without an active transaction."
        )
    try:
        with session.begin():
            yield
    except IntegrityError as error:
        constraint = getattr(getattr(error.orig, "diag", None), "constraint_name", None)
        messages = {
            "uq_core_organizations_slug": "Organization slug is already reserved.",
            "uq_core_users_normalized_email": "Email identity is already reserved.",
            "uq_core_memberships_organization_user": "Membership already exists.",
        }
        if constraint in messages:
            raise IdentityConflict(messages[constraint]) from None
        raise IdentityStorageError("Identity change could not be saved.") from None
    except SQLAlchemyError:
        raise IdentityStorageError("Identity operation could not be completed.") from None


def create_organization(session: Session, *, name: str, slug: str) -> UUID:
    with _transaction(session):
        organization = repository.create_organization(
            session, name=clean_name(name), slug=normalize_slug(slug)
        )
        result = organization.id
    return result


def create_user(session: Session, *, email: str, display_name: str) -> UUID:
    with _transaction(session):
        display_email, normalized = normalize_email(email)
        user = repository.create_user(
            session,
            email=display_email,
            normalized_email=normalized,
            display_name=clean_name(display_name),
        )
        result = user.id
    return result


def add_membership(session: Session, *, organization_id: UUID, user_id: UUID) -> UUID:
    with _transaction(session):
        # Consistent parent lock order serializes add/restore against archiving.
        organization = repository.get_organization(session, organization_id, lock=True)
        user = repository.get_user(session, user_id, lock=True)
        if organization is None or user is None or not user.is_active:
            raise IdentityUnavailable("Organization or user is unavailable for membership.")
        membership = repository._membership_pair_including_archived(
            session, organization_id=organization_id, user_id=user_id
        )
        if membership is None:
            membership = repository.create_membership(
                session, organization_id=organization_id, user_id=user_id
            )
        elif membership.deleted_at is not None:
            before_membership_restore(session, organization_id, membership.id)
            membership.deleted_at = None
            session.flush()
        result = membership.id
    return result


def get_membership(
    session: Session, *, organization_id: UUID, membership_id: UUID
) -> MembershipInfo:
    with _transaction(session):
        membership = repository.get_active_membership(
            session, organization_id=organization_id, membership_id=membership_id
        )
        if membership is None:
            raise IdentityNotFound("Active membership was not found.")
        result = _membership_info(membership)
    return result


def list_active_memberships(session: Session, *, organization_id: UUID) -> list[MembershipInfo]:
    with _transaction(session):
        result = [
            _membership_info(membership)
            for membership in repository.list_active_memberships(
                session, organization_id=organization_id
            )
        ]
    return result


def archive_organization(session: Session, *, organization_id: UUID) -> None:
    with _transaction(session):
        organization = repository._organization_including_archived(session, organization_id)
        if organization is None:
            raise IdentityNotFound("Organization was not found.")
        if organization.deleted_at is None:
            organization.deleted_at = datetime.now(UTC)


def archive_membership(
    session: Session, *, organization_id: UUID, membership_id: UUID, actor_id: UUID | None = None
) -> None:
    with _transaction(session):
        organization = repository._organization_including_archived(session, organization_id)
        if organization is None:
            raise IdentityNotFound("Membership was not found.")
        membership = repository._membership_including_archived(
            session, organization_id=organization_id, membership_id=membership_id
        )
        if membership is None:
            raise IdentityNotFound("Membership was not found.")
        if membership.deleted_at is None:
            before_membership_archive(session, organization, membership, actor_id)
            membership.deleted_at = datetime.now(UTC)
