"""Authentication services own transactions; callers supply an idle session."""

import secrets
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import timedelta
from uuid import UUID

from argon2.exceptions import HashingError
from sqlalchemy import func, select, update
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from editingtab_core.auth import repository
from editingtab_core.auth.models import (
    InvitationRole,
    OrganizationInvitation,
    PasswordCredential,
    PasswordResetToken,
)
from editingtab_core.auth.security import (
    AuthenticationError,
    AuthenticationUnavailable,
    LoginThrottled,
    Passwords,
    token_digest,
    validate_password,
)
from editingtab_core.authorization import repository as authorization_repository
from editingtab_core.authorization import services as authorization_services
from editingtab_core.authorization.policy import MEMBER_MANAGE, AccessError, Conflict
from editingtab_core.config import Settings
from editingtab_core.identity.errors import InvalidIdentity
from editingtab_core.identity.models import Membership, User
from editingtab_core.identity.normalization import clean_name, normalize_email
from editingtab_core.platform.services import SUPPORTED_MODULES


@dataclass(frozen=True)
class Profile:
    id: UUID
    email: str
    display_name: str


@contextmanager
def transaction(session: Session):
    if session.in_transaction():
        raise AuthenticationUnavailable("Authentication unavailable.")
    try:
        with session.begin():
            yield
    except (SQLAlchemyError, HashingError):
        raise AuthenticationUnavailable("Authentication unavailable.") from None


def login(
    session: Session,
    *,
    settings: Settings,
    passwords: Passwords,
    email: str,
    password: str,
    source: str,
) -> str:
    try:
        _, normalized = normalize_email(email)
    except InvalidIdentity:
        normalized = "invalid-email"
    # Commit attempt counters independently of authentication success/failure.
    with transaction(session):
        repository.purge_expired_throttles(session)
        allowed = repository.consume_bucket(
            session,
            kind="s",
            value=source,
            limit=settings.auth_source_limit,
            window=settings.auth_window_seconds,
        )
        if allowed:
            allowed = repository.consume_bucket(
                session,
                kind="a",
                value=normalized,
                limit=settings.auth_account_limit,
                window=settings.auth_window_seconds,
            )
    if not allowed:
        raise LoginThrottled("Try again later.")
    try:
        validate_password(password)
    except ValueError:
        # Invalid lengths cannot ever be provisioned. Still do bounded dummy work.
        passwords.verify(None, "invalid-password-input")
        raise AuthenticationError("Invalid credentials.") from None
    with transaction(session):
        row = repository.credential_for_login(session, normalized)
        user, credential = row if row is not None else (None, None)
        valid = passwords.verify(credential.password_hash if credential else None, password)
        if not valid or user is None or not user.is_active or user.deleted_at is not None:
            raise AuthenticationError("Invalid credentials.")
        if passwords.hasher.check_needs_rehash(credential.password_hash):
            credential.password_hash = passwords.hash(password)
        token = secrets.token_urlsafe(32)
        repository.add_session(
            session,
            user_id=user.id,
            digest=token_digest(token),
            seconds=settings.auth_session_seconds,
        )
    return token


def current_user(session: Session, token: str | None) -> Profile:
    digest = token_digest(token)
    if digest is None:
        raise AuthenticationError("Authentication required.")
    with transaction(session):
        user = repository.authenticated_user(session, digest)
        if user is None:
            raise AuthenticationError("Authentication required.")
        profile = Profile(user.id, user.email, user.display_name)
    return profile


def access_context(session: Session, token: str | None):
    """Build current authorization context from database state, never session claims."""
    with transaction(session):
        user, _ = _session_identity(session, token)
        organizations = []
        for membership, organization in repository.active_organization_memberships(
            session, user.id
        ):
            organizations.append(
                {
                    "organization_id": organization.id,
                    "name": organization.name,
                    "slug": organization.slug,
                    "membership_id": membership.id,
                    "roles": [
                        {"role_id": role.id, "role_name": role.name}
                        for role in authorization_repository.membership_roles(
                            session, organization.id, membership.id
                        )
                    ],
                    "effective_permissions": sorted(
                        authorization_repository.effective_permissions(
                            session, organization.id, user.id
                        )
                    ),
                    "effective_grant_authority": sorted(
                        authorization_repository.effective_grant_authority(
                            session, organization.id, user.id
                        )
                    ),
                    "enabled_modules": repository.enabled_modules(
                        session, organization.id, SUPPORTED_MODULES
                    ),
                }
            )
        return {
            "user": {
                "user_id": user.id,
                "email": user.email,
                "display_name": user.display_name,
            },
            "is_platform_admin": repository.has_platform_admin_grant(session, user.id),
            "organizations": organizations,
        }


def logout(session: Session, token: str | None) -> None:
    digest = token_digest(token)
    if digest is not None:
        with transaction(session):
            repository.revoke_session(session, digest)


def _session_identity(session: Session, token: str | None, *, lock: bool = False):
    digest = token_digest(token)
    if digest is None:
        raise AuthenticationError("Authentication required.")
    row = repository.authenticated_session(session, digest, lock=lock)
    if row is None:
        raise AuthenticationError("Authentication required.")
    return row


def list_sessions(session: Session, token: str | None):
    with transaction(session):
        user, current = _session_identity(session, token)
        return [
            {
                "id": item.id,
                "created_at": item.created_at,
                "expires_at": item.expires_at,
                "current_session": item.id == current.id,
            }
            for item in repository.active_sessions(session, user.id)
        ]


def revoke_selected_session(session: Session, token: str | None, session_id: UUID) -> bool:
    with transaction(session):
        user, current = _session_identity(session, token, lock=True)
        if not repository.revoke_owned_session(session, user.id, session_id):
            raise AuthenticationError("Session unavailable.")
        repository.audit(
            session,
            action="sessions.revoked",
            actor_id=user.id,
            target_id=user.id,
            details={"scope": "selected", "count": 1},
        )
        return session_id == current.id


def revoke_all_sessions(session: Session, token: str | None) -> None:
    with transaction(session):
        user, _ = _session_identity(session, token, lock=True)
        count = repository.revoke_user_sessions(session, user.id)
        repository.audit(
            session,
            action="sessions.revoked",
            actor_id=user.id,
            target_id=user.id,
            details={"scope": "all", "count": count},
        )


def change_password(
    session: Session,
    *,
    passwords: Passwords,
    token: str | None,
    current_password: str,
    new_password: str,
) -> None:
    validate_password(current_password)
    validate_password(new_password)
    with transaction(session):
        user, current = _session_identity(session, token, lock=True)
        credential = session.get(PasswordCredential, user.id, with_for_update=True)
        if credential is None or not passwords.verify(credential.password_hash, current_password):
            raise AuthenticationError("Authentication failed.")
        credential.password_hash = passwords.hash(new_password)
        count = repository.revoke_user_sessions(session, user.id, except_id=current.id)
        repository.audit(
            session,
            action="password.changed",
            actor_id=user.id,
            target_id=user.id,
            details={"other_sessions_revoked": count},
        )
        repository.audit(
            session,
            action="sessions.revoked",
            actor_id=user.id,
            target_id=user.id,
            details={"scope": "other", "count": count, "reason": "password_change"},
        )


def create_invitation(
    session: Session,
    *,
    settings: Settings,
    organization_id: UUID,
    actor_id: UUID,
    email: str,
    role_ids=(),
):
    _, normalized = normalize_email(email)
    token = secrets.token_urlsafe(32)
    with transaction(session):
        authorization_services.authorize(
            session, organization_id, actor_id, MEMBER_MANAGE, lock=True
        )
        roles = authorization_services._initial_roles(session, organization_id, actor_id, role_ids)
        user = session.scalar(
            select(User).where(
                User.normalized_email == normalized,
                User.deleted_at.is_(None),
                User.is_active.is_(True),
            )
        )
        if user is not None:
            membership = session.scalar(
                select(Membership).where(
                    Membership.organization_id == organization_id,
                    Membership.user_id == user.id,
                    Membership.deleted_at.is_(None),
                )
            )
            if membership is not None:
                raise Conflict()
        replaced = list(
            session.scalars(
                select(OrganizationInvitation).where(
                    OrganizationInvitation.organization_id == organization_id,
                    OrganizationInvitation.normalized_email == normalized,
                    OrganizationInvitation.accepted_at.is_(None),
                    OrganizationInvitation.revoked_at.is_(None),
                )
            )
        )
        session.execute(
            update(OrganizationInvitation)
            .where(
                OrganizationInvitation.organization_id == organization_id,
                OrganizationInvitation.normalized_email == normalized,
                OrganizationInvitation.accepted_at.is_(None),
                OrganizationInvitation.revoked_at.is_(None),
            )
            .values(revoked_at=func.clock_timestamp())
        )
        for old in replaced:
            repository.audit(
                session,
                action="invitation.revoked",
                actor_id=actor_id,
                organization_id=organization_id,
                target_id=old.id,
                details={"reason": "reissued"},
            )
        now = session.scalar(select(func.clock_timestamp()))
        invitation = OrganizationInvitation(
            organization_id=organization_id,
            normalized_email=normalized,
            inviter_id=actor_id,
            token_digest=token_digest(token),
            created_at=now,
            expires_at=now + timedelta(seconds=settings.auth_invitation_seconds),
        )
        session.add(invitation)
        session.flush()
        session.add_all(
            InvitationRole(
                organization_id=organization_id,
                invitation_id=invitation.id,
                role_id=role.id,
            )
            for role in roles
        )
        repository.audit(
            session,
            action="invitation.created",
            actor_id=actor_id,
            organization_id=organization_id,
            target_id=invitation.id,
            details={"role_ids": [str(role.id) for role in roles]},
        )
        result = {
            "id": invitation.id,
            "email": normalized,
            "created_at": invitation.created_at,
            "expires_at": invitation.expires_at,
            "role_ids": [role.id for role in roles],
            "token": token,
        }
    return result


def list_invitations(session: Session, *, organization_id: UUID, actor_id: UUID):
    with transaction(session):
        authorization_services.authorize(session, organization_id, actor_id, MEMBER_MANAGE)
        rows = session.scalars(
            select(OrganizationInvitation)
            .where(OrganizationInvitation.organization_id == organization_id)
            .order_by(OrganizationInvitation.created_at.desc(), OrganizationInvitation.id)
        )
        return [
            {
                "id": row.id,
                "email": row.normalized_email,
                "created_at": row.created_at,
                "expires_at": row.expires_at,
                "accepted_at": row.accepted_at,
                "revoked_at": row.revoked_at,
                "role_ids": repository.invitation_roles(session, row.id),
            }
            for row in rows
        ]


def revoke_invitation(
    session: Session, *, organization_id: UUID, actor_id: UUID, invitation_id: UUID
) -> None:
    with transaction(session):
        authorization_services.authorize(
            session, organization_id, actor_id, MEMBER_MANAGE, lock=True
        )
        invitation = session.scalar(
            select(OrganizationInvitation)
            .where(
                OrganizationInvitation.id == invitation_id,
                OrganizationInvitation.organization_id == organization_id,
            )
            .with_for_update()
        )
        if invitation is None:
            from editingtab_core.authorization.policy import Inaccessible

            raise Inaccessible()
        if invitation.accepted_at is None and invitation.revoked_at is None:
            invitation.revoked_at = session.scalar(select(func.clock_timestamp()))
            repository.audit(
                session,
                action="invitation.revoked",
                actor_id=actor_id,
                organization_id=organization_id,
                target_id=invitation.id,
            )


def accept_invitation(
    session: Session,
    *,
    passwords: Passwords,
    token: str,
    email: str,
    display_name: str | None = None,
    password: str | None = None,
):
    try:
        _, normalized = normalize_email(email)
    except InvalidIdentity:
        raise AuthenticationError("Invitation unavailable.") from None
    digest = token_digest(token)
    if digest is None:
        raise AuthenticationError("Invitation unavailable.")
    with transaction(session):
        invitation = repository.invitation_by_digest(session, digest, lock=True)
        now = session.scalar(select(func.clock_timestamp()))
        if (
            invitation is None
            or invitation.normalized_email != normalized
            or invitation.accepted_at is not None
            or invitation.revoked_at is not None
            or invitation.expires_at <= now
        ):
            raise AuthenticationError("Invitation unavailable.")
        try:
            authorization_services.authorize(
                session, invitation.organization_id, invitation.inviter_id, MEMBER_MANAGE
            )
            roles = authorization_services._initial_roles(
                session,
                invitation.organization_id,
                invitation.inviter_id,
                repository.invitation_roles(session, invitation.id),
            )
        except AccessError:
            raise AuthenticationError("Invitation unavailable.") from None
        user = session.scalar(
            select(User)
            .where(User.normalized_email == normalized, User.deleted_at.is_(None))
            .with_for_update()
        )
        if user is None:
            if display_name is None or password is None:
                raise AuthenticationError("Invitation requires account setup.")
            try:
                cleaned_name = clean_name(display_name)
            except InvalidIdentity:
                raise AuthenticationError("Invitation unavailable.") from None
            user = User(email=normalized, normalized_email=normalized, display_name=cleaned_name)
            session.add(user)
            session.flush()
            session.add(PasswordCredential(user_id=user.id, password_hash=passwords.hash(password)))
        else:
            if not user.is_active:
                raise AuthenticationError("Invitation unavailable.")
            credential = session.get(PasswordCredential, user.id)
            if credential is None:
                if password is None:
                    raise AuthenticationError("Invitation requires account setup.")
                session.add(
                    PasswordCredential(user_id=user.id, password_hash=passwords.hash(password))
                )
        membership = session.scalar(
            select(Membership)
            .where(
                Membership.organization_id == invitation.organization_id,
                Membership.user_id == user.id,
            )
            .with_for_update()
        )
        if membership is not None and membership.deleted_at is None:
            raise AuthenticationError("Invitation unavailable.")
        result = authorization_services._activate_member(
            session,
            invitation.organization_id,
            invitation.inviter_id,
            membership,
            user,
            roles,
        )
        invitation.accepted_at = now
        repository.audit(
            session,
            action="invitation.accepted",
            actor_id=user.id,
            organization_id=invitation.organization_id,
            target_id=invitation.id,
            details={"membership_id": str(result["membership_id"])},
        )
        return result


def request_password_reset(
    session: Session, *, settings: Settings, email: str, source: str
) -> str | None:
    try:
        _, normalized = normalize_email(email)
    except InvalidIdentity:
        normalized = "invalid-email"
    token = secrets.token_urlsafe(32)
    with transaction(session):
        repository.purge_expired_throttles(session)
        allowed = repository.consume_bucket(
            session,
            kind="r",
            value=source,
            limit=settings.auth_source_limit,
            window=settings.auth_window_seconds,
        )
        if allowed:
            allowed = repository.consume_bucket(
                session,
                kind="p",
                value=normalized,
                limit=settings.auth_account_limit,
                window=settings.auth_window_seconds,
            )
    if not allowed:
        raise LoginThrottled("Try again later.")
    with transaction(session):
        user = session.scalar(
            select(User).where(
                User.normalized_email == normalized,
                User.deleted_at.is_(None),
                User.is_active.is_(True),
            )
        )
        if user is not None and session.get(PasswordCredential, user.id) is not None:
            session.execute(
                update(PasswordResetToken)
                .where(
                    PasswordResetToken.user_id == user.id,
                    PasswordResetToken.consumed_at.is_(None),
                    PasswordResetToken.revoked_at.is_(None),
                )
                .values(revoked_at=func.clock_timestamp())
            )
            now = session.scalar(select(func.clock_timestamp()))
            session.add(
                PasswordResetToken(
                    user_id=user.id,
                    token_digest=token_digest(token),
                    created_at=now,
                    expires_at=now + timedelta(seconds=settings.auth_password_reset_seconds),
                )
            )
    if (
        settings.environment in {"development", "test"}
        and "environment" in settings.model_fields_set
    ):
        return token
    return None


def reset_password(session: Session, *, passwords: Passwords, token: str, password: str) -> None:
    validate_password(password)
    digest = token_digest(token)
    if digest is None:
        raise AuthenticationError("Reset unavailable.")
    with transaction(session):
        reset = repository.reset_by_digest(session, digest, lock=True)
        now = session.scalar(select(func.clock_timestamp()))
        if (
            reset is None
            or reset.consumed_at is not None
            or reset.revoked_at is not None
            or reset.expires_at <= now
        ):
            raise AuthenticationError("Reset unavailable.")
        user = session.scalar(
            select(User)
            .where(User.id == reset.user_id, User.deleted_at.is_(None), User.is_active.is_(True))
            .with_for_update()
        )
        credential = session.get(PasswordCredential, reset.user_id, with_for_update=True)
        if user is None or credential is None:
            raise AuthenticationError("Reset unavailable.")
        credential.password_hash = passwords.hash(password)
        reset.consumed_at = now
        count = repository.revoke_user_sessions(session, user.id)
        repository.audit(
            session,
            action="password.reset",
            target_id=user.id,
            details={"sessions_revoked": count},
        )
        repository.audit(
            session,
            action="sessions.revoked",
            target_id=user.id,
            details={"scope": "all", "count": count, "reason": "password_reset"},
        )
