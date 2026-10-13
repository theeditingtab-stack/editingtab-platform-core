"""Validate production configuration without printing values or opening connections."""

import sys

from editingtab_core.config import ConfigurationError, load_settings


def main() -> int:
    try:
        settings = load_settings(env_file=None)
        if settings.environment != "production":
            raise ConfigurationError("CORE_ENVIRONMENT must be production.")
        if not settings.auth_allowed_origins:
            raise ConfigurationError("Configure at least one exact HTTPS browser origin.")
        if settings.booking_service_current_digest is None:
            raise ConfigurationError("Configure the Booking service credential digest.")
        if not settings.booking_service_private_networks:
            raise ConfigurationError("Configure the private Booking service network.")
    except ConfigurationError as error:
        print(f"Production configuration invalid: {error}", file=sys.stderr)
        return 1

    print("Production configuration is valid.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
