"""Explicit, audited platform administrator recovery command."""

import getpass
import sys

from sqlalchemy.orm import Session

from editingtab_core.auth.provision import SafeParser
from editingtab_core.auth.security import Passwords
from editingtab_core.authorization.policy import AccessError
from editingtab_core.config import load_settings
from editingtab_core.database import build_engine
from editingtab_core.platform.services import recover_platform_admin

CONFIRMATION = "RECOVER PLATFORM ADMIN"


def main():
    SafeParser(description="Controlled platform administrator recovery.").parse_args()
    engine = None
    password = None
    confirmation = None
    try:
        if not sys.stdin.isatty():
            print("Interactive operator confirmation required.", file=sys.stderr)
            return 1
        print(
            "This resets access only for the recorded initial administrator and revokes sessions."
        )
        if input(f"Type {CONFIRMATION}: ") != CONFIRMATION:
            print("Not confirmed; nothing changed.")
            return 1
        password = getpass.getpass("Recovery password: ")
        confirmation = getpass.getpass("Confirm recovery password: ")
        if password != confirmation:
            print("Passwords did not match; nothing changed.", file=sys.stderr)
            return 1
        settings = load_settings()
        engine = build_engine(settings)
        with Session(engine, expire_on_commit=False) as session:
            recover_platform_admin(session, passwords=Passwords(), password=password)
        print("Platform administrator recovery completed and audited.")
        return 0
    except (ValueError, AccessError):
        print(
            "Recovery unavailable; check administrator state, configuration, and migrations.",
            file=sys.stderr,
        )
        return 1
    except (EOFError, KeyboardInterrupt):
        print("Not confirmed; nothing changed.", file=sys.stderr)
        return 1
    finally:
        password = None
        confirmation = None
        if engine is not None:
            engine.dispose()


if __name__ == "__main__":
    raise SystemExit(main())
