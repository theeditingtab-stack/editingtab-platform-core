"""Explicit authentication queries; transaction ownership belongs to services."""

from datetime import timedelta
from hashlib import sha256
from uuid import UUID

from sqlalchemy import case, delete, func, select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from editingtab_core.auth.models import (
    InvitationRole,
    LoginSession,
    LoginThrottle,
    OrganizationInvitation,
    PasswordCredential,
    PasswordResetToken,
    SecurityAudit,
)
from editingtab_core.identity.models import Membership, Organization, User
from editingtab_core.platform.models import ModuleEntitlement, PlatformAdminGrant


def credential_for_login(session: Session, normalized_email: str):
    return session.execute(
        select(User, PasswordCredential)
        .join(PasswordCredential)
        .where(User.normalized_email == normalized_email)
        .with_for_update()
        .execution_options(populate_existing=True)
    ).one_or_none()


def authenticated_user(session: Session, digest: str):
    return session.scalar(
        select(User)
        .join(LoginSession, LoginSession.user_id == User.id)
        .where(
            LoginSession.token_digest == digest,
            LoginSession.revoked_at.is_(None),
            LoginSession.expires_at > func.clock_timestamp(),
            User.deleted_at.is_(None),
            User.is_active.is_(True),
        )
        .execution_options(populate_existing=True)
    )


def authenticated_session(session: Session, digest: str, *, lock: bool = False):
    query = (
        select(User, LoginSession)
        .join(LoginSession, LoginSession.user_id == User.id)
        .where(
            LoginSession.token_digest == digest,
            LoginSession.revoked_at.is_(None),
            LoginSession.expires_at > func.clock_timestamp(),
            User.deleted_at.is_(None),
            User.is_active.is_(True),
        )
        .execution_options(populate_existing=True)
    )
    if lock:
        query = query.with_for_update()
    return session.execute(query).one_or_none()


def active_organization_memberships(session: Session, user_id: UUID):
    """Return only current tenant relationships, ordered by stable public slug."""
    return list(
        session.execute(
            select(Membership, Organization)
            .join(Organization, Organization.id == Membership.organization_id)
            .where(
                Membership.user_id == user_id,
                Membership.deleted_at.is_(None),
                Organization.deleted_at.is_(None),
            )
            .order_by(Organization.slug, Organization.id)
            .execution_options(populate_existing=True)
        )
    )


def enabled_modules(session: Session, organization_id: UUID, supported_modules):
    return list(
        session.scalars(
            select(ModuleEntitlement.module_code)
            .where(
                ModuleEntitlement.organization_id == organization_id,
                ModuleEntitlement.enabled.is_(True),
                ModuleEntitlement.module_code.in_(supported_modules),
            )
            .order_by(ModuleEntitlement.module_code)
        )
    )


def has_platform_admin_grant(session: Session, user_id: UUID) -> bool:
    return (
        session.scalar(
            select(PlatformAdminGrant.id).where(
                PlatformAdminGrant.user_id == user_id,
                PlatformAdminGrant.revoked_at.is_(None),
            )
        )
        is not None
    )


def add_session(session: Session, *, user_id: UUID, digest: str, seconds: int):
    now = session.scalar(select(func.clock_timestamp()))
    session.add(
        LoginSession(
            user_id=user_id,
            token_digest=digest,
            created_at=now,
            expires_at=now + timedelta(seconds=seconds),
        )
    )
    session.flush()


def revoke_session(session: Session, digest: str):
    session.execute(
        update(LoginSession)
        .where(LoginSession.token_digest == digest, LoginSession.revoked_at.is_(None))
        .values(revoked_at=func.clock_timestamp())
    )


def active_sessions(session: Session, user_id: UUID):
    return list(
        session.scalars(
            select(LoginSession)
            .where(
                LoginSession.user_id == user_id,
                LoginSession.revoked_at.is_(None),
                LoginSession.expires_at > func.clock_timestamp(),
            )
            .order_by(LoginSession.created_at.desc(), LoginSession.id)
        )
    )


def revoke_user_sessions(session: Session, user_id: UUID, *, except_id: UUID | None = None) -> int:
    query = update(LoginSession).where(
        LoginSession.user_id == user_id, LoginSession.revoked_at.is_(None)
    )
    if except_id is not None:
        query = query.where(LoginSession.id != except_id)
    return session.execute(query.values(revoked_at=func.clock_timestamp())).rowcount


def revoke_owned_session(session: Session, user_id: UUID, session_id: UUID) -> bool:
    result = session.execute(
        update(LoginSession)
        .where(
            LoginSession.id == session_id,
            LoginSession.user_id == user_id,
            LoginSession.revoked_at.is_(None),
        )
        .values(revoked_at=func.clock_timestamp())
    )
    return result.rowcount == 1


def audit(
    session, *, action: str, target_id: UUID, actor_id=None, organization_id=None, details=None
):
    session.add(
        SecurityAudit(
            action=action,
            target_id=target_id,
            actor_id=actor_id,
            organization_id=organization_id,
            details=details or {},
        )
    )
    session.flush()


def invitation_by_digest(session: Session, digest: str, *, lock: bool = False):
    query = select(OrganizationInvitation).where(OrganizationInvitation.token_digest == digest)
    if lock:
        query = query.with_for_update()
    return session.scalar(query.execution_options(populate_existing=True))


def invitation_roles(session: Session, invitation_id: UUID):
    return list(
        session.scalars(
            select(InvitationRole.role_id)
            .where(InvitationRole.invitation_id == invitation_id)
            .order_by(InvitationRole.role_id)
        )
    )


def reset_by_digest(session: Session, digest: str, *, lock: bool = False):
    query = select(PasswordResetToken).where(PasswordResetToken.token_digest == digest)
    if lock:
        query = query.with_for_update()
    return session.scalar(query.execution_options(populate_existing=True))


def purge_expired_throttles(session: Session):
    # Bound maintenance work per request. SKIP LOCKED avoids blocking other workers.
    keys = (
        select(LoginThrottle.key)
        .where(LoginThrottle.expires_at <= func.clock_timestamp())
        .order_by(LoginThrottle.expires_at)
        .limit(100)
        .with_for_update(skip_locked=True)
    )
    session.execute(
        delete(LoginThrottle).where(LoginThrottle.key.in_(keys)),
        execution_options={"synchronize_session": False},
    )


def consume_bucket(session: Session, *, kind: str, value: str, limit: int, window: int) -> bool:
    key = kind + ":" + sha256(value.encode("utf-8")).hexdigest()
    now = func.clock_timestamp()
    expired = LoginThrottle.expires_at <= now
    statement = (
        insert(LoginThrottle)
        .values(key=key, attempts=1, expires_at=now + timedelta(seconds=window))
        .on_conflict_do_update(
            index_elements=[LoginThrottle.key],
            set_={
                "attempts": case(
                    (expired, 1), else_=func.least(LoginThrottle.attempts + 1, limit + 1)
                ),
                "expires_at": case(
                    (expired, now + timedelta(seconds=window)), else_=LoginThrottle.expires_at
                ),
            },
        )
        .returning(LoginThrottle.attempts)
    )
    return session.scalar(statement) <= limit
