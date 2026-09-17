"""Authentication services own transactions; callers supply an idle session."""

import secrets
from contextlib import contextmanager
from dataclasses import dataclass
from uuid import UUID

from argon2.exceptions import HashingError
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from editingtab_core.auth import repository
from editingtab_core.auth.security import (
    AuthenticationError,
    AuthenticationUnavailable,
    LoginThrottled,
    Passwords,
    token_digest,
    validate_password,
)
from editingtab_core.config import Settings
from editingtab_core.identity.errors import InvalidIdentity
from editingtab_core.identity.normalization import normalize_email


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


def logout(session: Session, token: str | None) -> None:
    digest = token_digest(token)
    if digest is not None:
        with transaction(session):
            repository.revoke_session(session, digest)
