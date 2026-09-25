# Local development (Windows PowerShell)

Run commands from the project root in VS Code or PowerShell. Docker Desktop must be running with Linux containers. The application uses Python 3.12; an existing Python interpreter may bootstrap uv. Nothing here initializes Git or changes GitHub.

## Prepare the environment

If uv is not installed, install it in a workspace-local bootstrap virtual environment:

```powershell
python -m venv .tools/bootstrap
& ./.tools/bootstrap/Scripts/python.exe -m pip --isolated --disable-pip-version-check --no-cache-dir install uv==0.12.15
```

Use the following in each new shell. The helper keeps uv's cache and managed Python installation inside the workspace and makes the local uv executable available if installed above:

```powershell
. ./scripts/use-tools.ps1
uv python install 3.12
uv sync --locked
uv run --locked python --version
uv run --locked python scripts/init-dev.py
```

The initializer securely generates a local development password, creates `.env` exclusively, never prints its password, and never overwrites an existing file. `.env.example` documents non-secret placeholders; copying its placeholder password without replacing it will fail application validation. `.env`, virtual environments, caches, and local editor files are ignored. Do not display resolved Compose configuration or commit credentials.

Settings use `CORE_`: `ENVIRONMENT` (development/test/production), `SERVICE_NAME`, `DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USERNAME`, `DB_PASSWORD`, and `DB_CONNECT_TIMEOUT` (integer seconds, 2Ã¢â‚¬â€œ10; default 3). Environment variables override `.env`. The local Compose development database/user are fixed at `editingtab_core` / `editingtab_dev`; application settings support other deployments.

## Start development PostgreSQL and migrate (manual opt-in)

```powershell
./scripts/start-db.ps1
uv run --locked alembic upgrade head
uv run --locked alembic current
```

The helper checks resource ownership and host-port conflicts before starting `db` under Compose project `editingtab-core-dev`. It never stops unrelated services. If a conflict is reported, choose a free port; do not delete volumes or stop unrelated containers.

Development binds `127.0.0.1:15432` to container port `5432` and persists data in `editingtab-core-dev_core_postgres_data`. Set `CORE_DB_PORT` in `.env` before startup, or use an explicit PowerShell override in the same shell used for migrations/API:

```powershell
$env:CORE_DB_PORT = '25432'
./scripts/start-db.ps1
uv run --locked alembic upgrade head
```

Use a free port, keep the internal container port at 5432, and keep application/Compose settings consistent. Changing an environment password does not rotate the password already stored in PostgreSQL; preserve the original local secret and do not reset data to fix credentials.

Revision `0001_foundation` is intentionally empty. Revision `0002_core_identity` adds Core organizations, users, and memberships; `0003_password_sessions` adds credentials, sessions, and login throttles. `0004_organization_roles` adds organization roles, scoped assignments, and audit records. Revision `0005_platform_onboarding` adds separate platform authority, bootstrap history, entitlements, and platform audit. Review it before manually upgrading development; Codex did not apply CORE-006 to development. See the [eight-step platform walkthrough](core-006-platform.md#manual-powershell-walkthrough). Startup neither creates tables nor runs migrations. Repeating `upgrade head` is safe; do not downgrade or reset development data.

## Start and check the API

Use an available API port; 18080 was used for checkpoint verification because 8000 was occupied.

```powershell
$env:CORE_ENVIRONMENT = 'development'
$env:CORE_AUTH_ALLOWED_ORIGINS = '["http://127.0.0.1:18080"]'
uv run --locked uvicorn editingtab_core.app:create_app --factory --host 127.0.0.1 --port 18080 --no-proxy-headers
```

In another project-root PowerShell terminal:

```powershell
Invoke-RestMethod http://127.0.0.1:18080/health/live
Invoke-RestMethod http://127.0.0.1:18080/health/ready
```

Liveness returns HTTP 200 with `{"status":"alive"}` without database access. Readiness executes `SELECT 1` and returns HTTP 200 with `{"status":"ready"}` or HTTP 503 with `{"status":"unavailable"}`. Errors reveal no connection details. Database work runs in worker threads, sessions close reliably, and the engine is disposed at application shutdown. No permissive CORS or debug mode is enabled.

Connection and pool waits use the configured timeout; queries have a matching PostgreSQL statement timeout, with TCP failure settings as additional protection. These are component timeouts, not an unconditional end-to-end network deadline: DNS, retries, and operating-system behavior can add delay. Local outage behavior was measured; production timeout policy remains deployment work.

## Checks and isolated integration tests

```powershell
. ./scripts/use-tools.ps1
uv sync --locked
uv run --locked ruff check .
uv run --locked ruff format --check .
uv run --locked pytest -m 'not integration'
./scripts/start-db.ps1 -TestDatabase
./scripts/test-integration.ps1
```

Unit checks include the database configuration guard tests; no database is required. Real integration tests are marked `integration` and require `--integration` plus every explicit `CORE_TEST_DB_` setting. The test helper sets host, port, name, username, and the public test-only password for its process and restores prior values afterward. It never loads developer credentials.

The test service uses `editingtab_core_test` / `editingtab_test`, loopback host port 15433, and tmpfs storage. No development volume is mounted. Its data is disposable and lost when stopped. To choose a different free test port:

```powershell
$env:CORE_TEST_DB_PORT = '25433'
./scripts/start-db.ps1 -TestDatabase
./scripts/test-integration.ps1 -Port 25433
```

The runner defaults to 15433; pass the same overridden port explicitly. Tests reject nonlocal hosts, incorrect database/user names, and development port 15432; they never fall back to development settings. Ordinary tests create private schemas inside rollback-only outer transactions, verify actual database/user identity before DDL, and leave existing schemas untouched. Service commits and failures use real PostgreSQL savepoints. The concurrent-administrator test creates, commits, and removes only its own random schema in the guarded test database so separate connections can share state. No database resets or downgrades run; tests intentionally verify that restrictive foreign keys reject parent hard deletion. Enabled integration tests fail if configuration is missing or PostgreSQL is unavailable. They verify baseline-to-head migration, repeated upgrade, constraints, scoped identity services, rollback, and real readiness. See [CORE-003 identity](core-003-identity.md) for policies and results.

## Authentication demo

See [CORE-004 authentication](core-004-authentication.md) for cookie/origin configuration, secure local user provisioning, and complete login, profile, logout, and revoked-cookie replay commands. No account is created automatically. Authentication identifies the user; CORE-005 separately enforces organization permissions. See [authorization setup and walkthrough](core-005-authorization.md).

## Outage check and stopping

With the API still running, stop only this project's development database, then restore it even if a check fails:

```powershell
try {
    docker compose stop db
    Invoke-RestMethod http://127.0.0.1:18080/health/live
    try {
        Invoke-WebRequest -UseBasicParsing http://127.0.0.1:18080/health/ready
    } catch {
        [int]$_.Exception.Response.StatusCode # Expected: 503
    }
} finally {
    docker compose start --wait db
}
Invoke-RestMethod http://127.0.0.1:18080/health/ready
```

Expect liveness 200 throughout and readiness 200 Ã¢â€ â€™ 503 Ã¢â€ â€™ 200 without restarting the API. Stop the API with Ctrl+C. Stop project databases without deleting the persistent development data:

```powershell
docker compose --profile test stop db db-test
```

Do not use prune or volume-removal commands. Stopping the test service discards its tmpfs data; restart and rerun integration tests when needed.
## Core / Booking authorization

Current head is `0007_permission_registry`; it creates the Core-owned permission definition registry and registers the reviewed Core/Booking vocabulary without granting new permissions. Review [CORE-AUTH-001](core-auth-001-permission-registry.md) before manually upgrading development. Use the [CORE-007 contract walkthrough](booking-authorization-contract.md#manual-powershell-walkthrough) for ignored local credential setup, API restart, and explicit inventory permission provisioning. Do not repeat user/organization/platform bootstrap. The internal route remains disabled when no current service digest is configured.
