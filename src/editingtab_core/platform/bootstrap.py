"""Interactive operator command; never called by startup, migrations, or HTTP."""

import sys

from sqlalchemy.orm import Session

from editingtab_core.auth.provision import SafeParser
from editingtab_core.authorization.policy import AccessError
from editingtab_core.config import load_settings
from editingtab_core.database import build_engine
from editingtab_core.platform.services import BootstrapClosed, bootstrap_initial

CONFIRMATION = "GRANT INITIAL PLATFORM ADMIN"


def main():
    parser = SafeParser(description="One-time operator bootstrap for an existing active user.")
    parser.add_argument("--email", required=True)
    args = parser.parse_args()
    engine = None
    try:
        if not sys.stdin.isatty():
            print("Interactive operator confirmation required.", file=sys.stderr)
            return 1
        settings = load_settings()
        print("This grants separate platform authority to the explicitly selected user.")
        print("Confirm the target email supplied in --email before continuing.")
        if input(f"Type {CONFIRMATION}: ") != CONFIRMATION:
            print("Not confirmed; nothing changed.")
            return 1
        engine = build_engine(settings)
        with Session(engine, expire_on_commit=False) as session:
            bootstrap_initial(session, email=args.email)
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
        if engine is not None:
            engine.dispose()


if __name__ == "__main__":
    raise SystemExit(main())
