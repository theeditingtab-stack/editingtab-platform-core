"""Fail-fast production migration entry point; never creates or wipes a database."""

import subprocess
import sys

from editingtab_core.config import ConfigurationError, load_settings


def main() -> int:
    try:
        settings = load_settings(env_file=None)
        if settings.environment != "production":
            raise ConfigurationError("CORE_ENVIRONMENT must be production.")
    except ConfigurationError as error:
        print(f"Migration configuration invalid: {error}", file=sys.stderr)
        return 1

    result = subprocess.run([sys.executable, "-m", "alembic", "upgrade", "head"], check=False)
    if result.returncode != 0:
        print("Core migration failed; application startup must not continue.", file=sys.stderr)
        return result.returncode or 1
    print("Core migrations reached head.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
