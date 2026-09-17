"""Explicit Core queries. No commits, rollbacks, hard deletes, or authorization."""

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from editingtab_core.identity.models import Membership, Organization, User


def create_organization(session: Session, *, name: str, slug: str) -> Organization:
    organization = Organization(name=name, slug=slug)
    session.add(organization)
    session.flush()
    return organization


def create_user(session: Session, *, email: str, normalized_email: str, display_name: str) -> User:
    user = User(email=email, normalized_email=normalized_email, display_name=display_name)
    session.add(user)
    session.flush()
    return user


def get_organization(session: Session, organization_id: UUID, *, lock: bool = False):
    query = select(Organization).where(
        Organization.id == organization_id, Organization.deleted_at.is_(None)
    )
    if lock:
        query = query.with_for_update()
    return session.scalar(query.execution_options(populate_existing=True))


def get_user(session: Session, user_id: UUID, *, lock: bool = False):
    query = select(User).where(User.id == user_id, User.deleted_at.is_(None))
    if lock:
        query = query.with_for_update()
    return session.scalar(query.execution_options(populate_existing=True))


def get_user_by_normalized_email(session: Session, normalized_email: str) -> User | None:
    return session.scalar(
        select(User)
        .where(User.normalized_email == normalized_email, User.deleted_at.is_(None))
        .execution_options(populate_existing=True)
    )


def _active_memberships(organization_id: UUID):
    return (
        select(Membership)
        .join(Organization, Membership.organization_id == Organization.id)
        .join(User, Membership.user_id == User.id)
        .where(
            Membership.organization_id == organization_id,
            Membership.deleted_at.is_(None),
            Organization.deleted_at.is_(None),
            User.deleted_at.is_(None),
            User.is_active.is_(True),
        )
        .execution_options(populate_existing=True)
    )


def get_active_membership(
    session: Session, *, organization_id: UUID, membership_id: UUID
) -> Membership | None:
    return session.scalar(
        _active_memberships(organization_id).where(Membership.id == membership_id)
    )


def list_active_memberships(session: Session, *, organization_id: UUID) -> list[Membership]:
    return list(
        session.scalars(
            _active_memberships(organization_id).order_by(Membership.created_at, Membership.id)
        )
    )


def _organization_including_archived(session: Session, organization_id: UUID):
    # Internal archive path only. Never use this as an active-organization check.
    return session.scalar(
        select(Organization)
        .where(Organization.id == organization_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )


def _membership_pair_including_archived(
    session: Session, *, organization_id: UUID, user_id: UUID
) -> Membership | None:
    return session.scalar(
        select(Membership)
        .where(Membership.organization_id == organization_id, Membership.user_id == user_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )


def _membership_including_archived(
    session: Session, *, organization_id: UUID, membership_id: UUID
) -> Membership | None:
    return session.scalar(
        select(Membership)
        .where(Membership.organization_id == organization_id, Membership.id == membership_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )


def create_membership(session: Session, *, organization_id: UUID, user_id: UUID) -> Membership:
    membership = Membership(organization_id=organization_id, user_id=user_id)
    session.add(membership)
    session.flush()
    return membership
