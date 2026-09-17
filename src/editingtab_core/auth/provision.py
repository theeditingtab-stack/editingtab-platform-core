"""Explicit local-only provisioning. No password arguments and no default account."""

import argparse
import getpass
import sys
import warnings

from argon2.exceptions import HashingError
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from editingtab_core.auth.models import PasswordCredential
from editingtab_core.auth.security import (
    MAX_PASSWORD_LENGTH,
    MIN_PASSWORD_LENGTH,
    AuthenticationUnavailable,
    CredentialConflict,
    Passwords,
    validate_password,
)
from editingtab_core.auth.services import transaction
from editingtab_core.config import ConfigurationError, Settings, load_settings
from editingtab_core.database import build_engine
from editingtab_core.identity import services as identity
from editingtab_core.identity.errors import IdentityError, IdentityStorageError, InvalidIdentity
from editingtab_core.identity.models import User
from editingtab_core.identity.normalization import normalize_email


class LocalProvisioningError(ValueError):
    """Static, safe CLI guidance; never constructed from submitted values."""


class UnavailableIdentity(CredentialConflict):
    """An inactive or archived identity must not receive credentials."""


def require_local(settings: Settings):
    if (
        settings.environment not in {"development", "test"}
        or "environment" not in settings.model_fields_set
    ):
        raise LocalProvisioningError(
            "Development/test environment required; set CORE_ENVIRONMENT in this terminal."
        )


def provision_user(
    session: Session,
    *,
    settings: Settings,
    passwords: Passwords,
    email: str,
    display_name: str,
    password: str,
):
    require_local(settings)
    _, normalized = normalize_email(email)
    encoded = passwords.hash(password)
    with transaction(session):
        user = session.scalar(
            select(User).where(User.normalized_email == normalized).with_for_update()
        )
        if user is not None:
            if not user.is_active or user.deleted_at is not None:
                raise UnavailableIdentity("Identity is unavailable for local provisioning.")
            user_id = user.id
            if session.get(PasswordCredential, user_id) is not None:
                raise CredentialConflict("Credentials already exist; nothing was replaced.")
        else:
            # Reuse the identity service inside this service's owning transaction.
            # Its commit releases a savepoint; both profile and credential commit together.
            with Session(
                bind=session.connection(),
                join_transaction_mode="create_savepoint",
                expire_on_commit=False,
            ) as identity_session:
                user_id = identity.create_user(
                    identity_session, email=email, display_name=display_name
                )
        session.add(PasswordCredential(user_id=user_id, password_hash=encoded))
        session.flush()
    return user_id


class SafeParser(argparse.ArgumentParser):
    def error(self, message):
        self.exit(
            2, "Invalid arguments; use --help. Passwords are accepted only at the secure prompt.\n"
        )


def failure_message(error: Exception) -> str:
    # Only this private CLI input error has a printable, controlled message.
    # Never render SQLAlchemy, configuration, hashing, or domain exceptions.
    if isinstance(error, LocalProvisioningError):
        return str(error)
    if isinstance(error, ConfigurationError):
        return "Configuration invalid; check CORE_ settings in this terminal and the local .env."
    if isinstance(error, UnavailableIdentity):
        return "Identity is inactive or archived; no credentials were changed."
    if isinstance(error, CredentialConflict):
        return "Credentials already exist; use login. No credentials were changed."
    if isinstance(error, (AuthenticationUnavailable, IdentityStorageError, SQLAlchemyError)):
        return (
            "Database unavailable or migration missing; "
            "check local database settings and migrations."
        )
    if isinstance(error, HashingError):
        return "Password hashing unavailable; check local resources and the locked installation."
    if isinstance(error, (getpass.GetPassWarning, EOFError)):
        return "Secure password entry unavailable; use an interactive local terminal."
    if isinstance(error, InvalidIdentity):
        return "Invalid email or display name; check the supplied identity fields."
    if isinstance(error, IdentityError):
        return "Identity operation failed; review the existing identity before retrying."
    return "Invalid provisioning input; check configuration and identity fields."


def main() -> int:
    parser = SafeParser(description="Provision one local login user; grants no administrator role.")
    parser.add_argument("--email", required=True)
    parser.add_argument("--display-name", required=True)
    args = parser.parse_args()
    engine = None
    try:
        settings = load_settings()
        require_local(settings)
        if not sys.stdin.isatty():
            raise LocalProvisioningError(
                "Secure password entry requires an interactive local terminal."
            )
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            password = getpass.getpass("Password (15-1024 characters): ")
            confirmation = getpass.getpass("Confirm password: ")
        if password != confirmation:
            raise LocalProvisioningError(
                "Password confirmation mismatch; retry both secure prompts."
            )
        if not MIN_PASSWORD_LENGTH <= len(password) <= MAX_PASSWORD_LENGTH:
            raise LocalProvisioningError(
                "Password length invalid; "
                f"use {MIN_PASSWORD_LENGTH}-{MAX_PASSWORD_LENGTH} characters."
            )
        try:
            validate_password(password)
        except ValueError:
            raise LocalProvisioningError(
                "Password invalid; enter valid Unicode characters."
            ) from None
        engine = build_engine(settings)
        with Session(engine, expire_on_commit=False) as session:
            provision_user(
                session,
                settings=settings,
                passwords=Passwords(),
                email=args.email,
                display_name=args.display_name,
                password=password,
            )
        print("Local login user provisioned; no administrator permissions granted.")
        return 0
    except (
        ValueError,
        IdentityError,
        AuthenticationUnavailable,
        CredentialConflict,
        getpass.GetPassWarning,
        EOFError,
        SQLAlchemyError,
        HashingError,
    ) as error:
        print(f"Provisioning failed: {failure_message(error)}", file=sys.stderr)
        return 1
    finally:
        if engine is not None:
            engine.dispose()


if __name__ == "__main__":
    raise SystemExit(main())
