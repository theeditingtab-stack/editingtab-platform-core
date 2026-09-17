"""Temporary local diagnostic: no writes, sessions, rehashing, or HTTP endpoint."""

import getpass
import sys
import warnings

from argon2.exceptions import HashingError
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from editingtab_core.auth.provision import SafeParser, require_local
from editingtab_core.auth.security import Passwords
from editingtab_core.config import load_settings
from editingtab_core.database import build_engine
from editingtab_core.identity.errors import InvalidIdentity
from editingtab_core.identity.normalization import normalize_email


def inspect_password(engine, *, email: str, password: str, passwords: Passwords):
    _, normalized = normalize_email(email)
    with engine.connect() as connection:
        transaction = connection.begin()
        try:
            # Enforced by PostgreSQL, not only by a promise to avoid ORM writes.
            connection.execute(text("SET TRANSACTION READ ONLY"))
            row = connection.execute(
                text(
                    "SELECT u.is_active, u.deleted_at IS NOT NULL AS archived, c.password_hash "
                    "FROM core_users u LEFT JOIN core_password_credentials c ON c.user_id = u.id "
                    "WHERE u.normalized_email = :email"
                ),
                {"email": normalized},
            ).one_or_none()
            encoded = row.password_hash if row is not None else None
            eligible = bool(row is not None and row.is_active and not row.archived and encoded)
            matched = passwords.verify(encoded, password)
            return eligible, matched
        finally:
            transaction.rollback()


def main() -> int:
    parser = SafeParser(description="Read-only local password diagnostic; no login or reset.")
    parser.add_argument("--email", required=True)
    args = parser.parse_args()
    engine = None
    try:
        settings = load_settings()
        require_local(settings)
        if settings.db_host not in {"127.0.0.1", "localhost", "::1"}:
            raise ValueError("Local database required")
        if not sys.stdin.isatty():
            raise ValueError("Interactive terminal required")
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            password = getpass.getpass("Password to verify: ")
        engine = build_engine(settings)
        eligible, matched = inspect_password(
            engine, email=args.email, password=password, passwords=Passwords()
        )
        print("User eligible:", "yes" if eligible else "no")
        print("Password:", "match" if matched else "no-match")
        return 0
    except (
        ValueError,
        InvalidIdentity,
        SQLAlchemyError,
        HashingError,
        getpass.GetPassWarning,
        EOFError,
    ):
        print(
            "Diagnostic unavailable; check explicit local development/test configuration, "
            "database access, and interactive input.",
            file=sys.stderr,
        )
        return 1
    finally:
        if engine is not None:
            engine.dispose()


if __name__ == "__main__":
    raise SystemExit(main())
