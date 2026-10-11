#!/bin/sh
set -eu

if [ -n "${CORE_DB_PASSWORD_FILE:-}" ]; then
    [ -r "$CORE_DB_PASSWORD_FILE" ] || { echo "Core database secret file is unavailable." >&2; exit 1; }
    CORE_DB_PASSWORD="$(cat "$CORE_DB_PASSWORD_FILE")"
    export CORE_DB_PASSWORD
fi

if [ -n "${CORE_BOOKING_SERVICE_CURRENT_DIGEST_FILE:-}" ]; then
    [ -r "$CORE_BOOKING_SERVICE_CURRENT_DIGEST_FILE" ] || { echo "Core service digest file is unavailable." >&2; exit 1; }
    CORE_BOOKING_SERVICE_CURRENT_DIGEST="$(cat "$CORE_BOOKING_SERVICE_CURRENT_DIGEST_FILE")"
    export CORE_BOOKING_SERVICE_CURRENT_DIGEST
fi

if [ -n "${CORE_BOOKING_SERVICE_PREVIOUS_DIGEST_FILE:-}" ]; then
    [ -r "$CORE_BOOKING_SERVICE_PREVIOUS_DIGEST_FILE" ] || { echo "Previous Core service digest file is unavailable." >&2; exit 1; }
    CORE_BOOKING_SERVICE_PREVIOUS_DIGEST="$(cat "$CORE_BOOKING_SERVICE_PREVIOUS_DIGEST_FILE")"
    export CORE_BOOKING_SERVICE_PREVIOUS_DIGEST
fi

if [ "${CORE_ENVIRONMENT:-}" = "production" ]; then
    python scripts/validate-production-config.py
fi

exec "$@"
