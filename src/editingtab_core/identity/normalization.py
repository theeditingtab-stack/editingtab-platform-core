"""Checkpoint policy, not deliverability verification or provider-specific rewriting."""

import re

from editingtab_core.identity.errors import InvalidIdentity


def normalize_slug(value: str) -> str:
    slug = value.strip().lower()
    if len(slug) > 63 or re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", slug) is None:
        raise InvalidIdentity("Organization slug must contain letters, digits and single hyphens.")
    return slug


def normalize_email(value: str) -> tuple[str, str]:
    email = value.strip()
    if (
        len(email) > 254
        or email.count("@") != 1
        or any(not 33 <= ord(char) <= 126 for char in email)
        or not all(email.split("@"))
    ):
        raise InvalidIdentity("A supported email address is required.")
    # ASCII-only policy keeps Python and PostgreSQL C-collation lowercase identical.
    # Dots and plus-addressing are retained; casing is preserved in the display value.
    return email, email.lower()


def clean_name(value: str) -> str:
    value = value.strip()
    if not 1 <= len(value) <= 200 or any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise InvalidIdentity("A nonblank name of at most 200 characters is required.")
    return value
