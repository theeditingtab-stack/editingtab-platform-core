"""Hashing helpers never truncate passwords or expose secrets in representations."""

import re
import secrets
from hashlib import sha256

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from argon2.profiles import RFC_9106_LOW_MEMORY

MIN_PASSWORD_LENGTH = 15
MAX_PASSWORD_LENGTH = 1024
COOKIE_NAME = "editingtab_session"


class AuthenticationError(Exception):
    """Generic authentication rejection."""


class AuthenticationUnavailable(Exception):
    """Safe database/hash failure."""


class LoginThrottled(Exception):
    """A temporary rate limit, independent of account existence."""


class CredentialConflict(Exception):
    """Provisioning must never replace existing credentials."""


def validate_password(password: str) -> None:
    if not MIN_PASSWORD_LENGTH <= len(password) <= MAX_PASSWORD_LENGTH:
        raise ValueError("Passwords must contain 15 to 1024 characters.")
    try:
        password.encode("utf-8")
    except UnicodeError:
        raise ValueError("Password must be valid Unicode.") from None


class Passwords:
    def __init__(self):
        self.hasher = PasswordHasher.from_parameters(RFC_9106_LOW_MEMORY)
        self._dummy = self.hasher.hash(secrets.token_urlsafe(32))

    def verify(self, encoded: str | None, password: str) -> bool:
        try:
            valid = self.hasher.verify(encoded or self._dummy, password)
            return bool(encoded) and valid
        except (VerificationError, InvalidHashError):
            return False

    def hash(self, password: str) -> str:
        validate_password(password)
        return self.hasher.hash(password)


def token_digest(token: str | None) -> str | None:
    if token is None or re.fullmatch(r"[A-Za-z0-9_-]{43}", token) is None:
        return None
    return sha256(token.encode("ascii")).hexdigest()
