"""Interactive operator command; never called by startup, migrations, or HTTP."""

import getpass
import sys

from sqlalchemy.orm import Session

from editingtab_core.auth.provision import SafeParser
from editingtab_core.auth.security import Passwords
from editingtab_core.authorization.policy import AccessError
from editingtab_core.config import load_settings
from editingtab_core.database import build_engine
from editingtab_core.platform.services import (
    PLATFORM_ADMIN_EMAIL,
    BootstrapClosed,
    bootstrap_initial,
)

CONFIRMATION = "GRANT INITIAL PLATFORM ADMIN"


def main():
    parser = SafeParser(description="One-time designated platform administrator bootstrap.")
    parser.parse_args()
    engine = None
    password = None
    confirmation = None
    try:
        if not sys.stdin.isatty():
            print("Interactive operator confirmation required.", file=sys.stderr)
            return 1
        settings = load_settings()
        print(f"This creates or grants separate platform authority to {PLATFORM_ADMIN_EMAIL}.")
        if input(f"Type {CONFIRMATION}: ") != CONFIRMATION:
            print("Not confirmed; nothing changed.")
            return 1
        password = getpass.getpass("Initial administrator password: ")
        confirmation = getpass.getpass("Confirm initial administrator password: ")
        if password != confirmation:
            print("Passwords did not match; nothing changed.", file=sys.stderr)
            return 1
        engine = build_engine(settings)
        with Session(engine, expire_on_commit=False) as session:
            bootstrap_initial(
                session,
                passwords=Passwords(),
                password=password,
                display_name="The Editing Tab Platform Administrator",
            )
        print("Initial platform administrator granted. Operator bootstrap is now closed.")
        return 0
    except BootstrapClosed:
        print(
            "Initial bootstrap is permanently closed; controlled recovery is separate.",
            file=sys.stderr,
        )
        return 1
    except (ValueError, AccessError):
        print(
            "Bootstrap unavailable; check active user, configuration, and migrations.",
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
