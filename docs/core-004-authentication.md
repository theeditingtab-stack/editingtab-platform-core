> Historical CORE-004 handoff. CORE-005 added [organization roles and enforced permissions](core-005-authorization.md). CORE-AUTH-004 now adds [production account onboarding and session lifecycle](core-auth-004-account-onboarding.md). Public organization routes require current membership/permissions, and the Origin guard also covers `/organizations`.

# CORE-004: Password authentication and revocable sessions

The Editing Tab now provides `POST /auth/login`, `POST /auth/logout`, and `GET /auth/me`. Authentication identifies a user; it grants no organization or platform administration permission. Organization management endpoints, roles, invitations, public signup, account recovery, Booking, and frontend remain unimplemented. CORE-003 is committed at `711716e` and verified according to the user.

## Storage and transactions

Migration `0003_password_sessions` follows the unchanged `0002_core_identity`. It adds Core-owned `core_password_credentials` (one credential per user), `core_login_sessions` (UUID, user reference, unique token digest, creation/expiry/revocation timestamps), and `core_login_throttles` (hashed bucket key, bounded attempt count, expiry). Foreign keys restrict deletion; profiles and memberships retain their existing soft-delete and uniqueness policies. All timestamps are timezone-aware.

Passwords use `argon2-cffi` Argon2id with RFC 9106 low-memory parameters: 64 MiB, three passes, parallelism four, random salts. Accepted passwords contain 15?1024 Unicode characters. Spaces are preserved; no normalization or truncation occurs. Invalid Unicode is rejected. Successful login rehashes outdated parameters. Unknown users and credentialless profiles perform dummy verification; incorrect passwords and inactive/archived users receive the same generic 401 response. This reduces obvious timing differences; it is not a constant-time network guarantee. Email lookup uses the existing ASCII normalization without removing dots or plus-addressing.

Each successful login generates a fresh 256-bit opaque token. Only its SHA-256 digest is persisted. Login returns 204 with a cookie, never a token in JSON. Sessions have an absolute lifetime (eight hours by default), with no sliding refresh. `/auth/me` returns only `id`, `email`, and `display_name`; absent, invalid, expired, or revoked sessions return 401. Every lookup checks current user activity and archival state. Disabling/archiving blocks existing sessions while that state holds; this checkpoint does not permanently revoke all sessions on a user lifecycle change. Logout is idempotent, marks a matching session revoked, clears the browser cookie, and returns 204. Other devices' sessions remain independent.

Repositories never commit. Services require idle sessions and own their transactions. A login attempt's throttle transaction commits before password verification, including for failed logins. Rehash and session insertion commit together. SQLAlchemy failures roll back and return a generic 503 without driver details. Logout does not claim successful revocation after a database failure. Local provisioning wraps the existing identity service in a savepoint so profile and credential creation commit atomically. No tables or migrations run at API startup.

## Cookie, Origin, and source policy

The `editingtab_session` cookie is HttpOnly, SameSite=Lax, Path=/, with no Domain attribute. Secure is mandatory unless `CORE_ENVIRONMENT` is explicitly `development` or `test`. Omission of the environment also keeps Secure enabled. There is no insecure-cookie override for production. Auth responses use `Cache-Control: no-store`.

Login and logout require exactly one `Origin` header matching an explicitly configured origin. Missing, duplicate, `null`, or untrusted origins return 403 before body parsing or database access. No Referer fallback is used. The allowlist defaults to empty, failing closed; it is a JSON array of exact origins without trailing slash, path, credentials, or wildcard. Secure mode allows HTTPS origins only. CLI clients must send Origin too. SameSite is an additional defense, not the sole CSRF protection. Auth request bodies are limited to 16 KiB and validation errors do not echo input. Future cookie-authenticated mutation routes must apply this protection explicitly; the current guard covers `/auth/`.

Do not enable credentialed wildcard CORS. Run Uvicorn with `--no-proxy-headers`, as below: client-source throttling uses the ASGI peer address and never reads forwarding headers itself. Deploying behind a proxy needs a separately reviewed trusted-proxy and ingress design; until then proxy peers share a source bucket. Do not enable arbitrary forwarded-header trust. HTTPS termination and browser deployment have not been provisioned or verified here.

| Environment variable | Default / bounds |
| --- | --- |
| `CORE_AUTH_ALLOWED_ORIGINS` | `[]`; local example `["http://127.0.0.1:18080"]` |
| `CORE_AUTH_SESSION_SECONDS` | 28800; 60?604800 |
| `CORE_AUTH_WINDOW_SECONDS` | 300; 1?3600 |
| `CORE_AUTH_ACCOUNT_LIMIT` | 5; 1?100 |
| `CORE_AUTH_SOURCE_LIMIT` | 30; 1?1000 |

PostgreSQL atomic upserts count all attempts, including successes, across workers. Fixed windows are independent for normalized account and socket-source address; an exhausted source cannot create more account buckets. Counters saturate at limit + 1. A blocked request receives generic 429 with a conservative Retry-After; blocked attempts do not extend the window. Unknown accounts have the same policy. Expiry uses database wall-clock time. Each attempt cleans at most 100 expired buckets with SKIP LOCKED; there is no in-memory identity map or permanent account lockout. Bucket keys are hashes, not anonymization or encryption. Distributed abuse, shared NAT fairness, capacity monitoring, and ingress limits remain deployment work. Session records are retained after expiry/revocation; a controlled retention job remains future work.

## Review and local verification (PowerShell)

Run from the project root:

```powershell
. ./scripts/use-tools.ps1
uv sync --locked
uv run --locked ruff check .
uv run --locked ruff format --check .
uv run --locked pytest -m 'not integration'
./scripts/start-db.ps1 -TestDatabase
./scripts/test-integration.ps1
```

Tests use the guarded isolated PostgreSQL database and rollback-only private schemas. They cover baseline -> identity -> auth migrations, preserved identity data, repeated head upgrades, real hash/digest storage, login/logout/me, status/expiry/revocation, CSRF, shared counters between app instances, timed recovery, rollback, and credential provisioning. Separate app instances use separate Sessions bound to the fixture's transactional connection; this verifies persisted shared state, not a concurrent multi-process load test. Existing identity, configuration, health, and database safety checks remain. CI already discovers these tests in its PostgreSQL job; no workflow weakening or production secrets are needed.

After review, the user may migrate development and provision one local user manually:

```powershell
. ./scripts/use-tools.ps1
$env:CORE_ENVIRONMENT = 'development'
$env:CORE_AUTH_ALLOWED_ORIGINS = '["http://127.0.0.1:18080"]'
./scripts/start-db.ps1
uv run --locked alembic upgrade head
uv run --locked alembic current
uv run --locked python -m editingtab_core.auth.provision --email 'demo@example.test' --display-name 'Demo User'
uv run --locked uvicorn editingtab_core.app:create_app --factory --host 127.0.0.1 --port 18080 --no-proxy-headers
```

The CLI prompts securely for password and confirmation; it refuses noninteractive password input and has no password argument. It grants no memberships or administrator role, creates no default credentials, and refuses to overwrite existing credentials. An existing active credentialless profile may receive a credential without changing its display name. Explicit development/test mode is required. `.env.example` configures the local origin for newly initialized files; an existing `.env` is preserved, so set the environment variable above or update it yourself. Codex did not migrate development or provision a development account.

In another PowerShell terminal, log in without placing a password in history, command arguments, or a file:

```powershell
$baseUrl = 'http://127.0.0.1:18080'
$baseUri = [Uri]$baseUrl
$originHeaders = @{ Origin = $baseUri.GetLeftPart([System.UriPartial]::Authority) }
$securePassword = Read-Host 'Demo password' -AsSecureString
$credential = [System.Management.Automation.PSCredential]::new('demo@example.test', $securePassword)
try {
    $body = @{ email = $credential.UserName; password = $credential.GetNetworkCredential().Password } | ConvertTo-Json -Compress
    $login = Invoke-WebRequest -UseBasicParsing -Uri "$baseUrl/auth/login" -Method Post -ContentType 'application/json; charset=utf-8' -Body ([System.Text.Encoding]::UTF8.GetBytes($body)) -Headers $originHeaders -SessionVariable authSession
    $login.StatusCode # 204; do not print the response headers or cookie jar
} finally {
    Remove-Variable body, credential, securePassword -ErrorAction SilentlyContinue
}
Invoke-RestMethod -Uri "$baseUrl/auth/me" -WebSession $authSession # Minimal profile

# Copy the current cookie in memory only, so it can be replayed after logout.
$replaySession = [Microsoft.PowerShell.Commands.WebRequestSession]::new()
$cookie = $authSession.Cookies.GetCookies($baseUri)['editingtab_session']
$replaySession.Cookies.Add([System.Net.Cookie]::new('editingtab_session', $cookie.Value, '/', $baseUri.Host))
Remove-Variable cookie
$logout = Invoke-WebRequest -UseBasicParsing -Uri "$baseUrl/auth/logout" -Method Post -Headers $originHeaders -WebSession $authSession
$logout.StatusCode # 204
try {
    $null = Invoke-WebRequest -UseBasicParsing -Uri "$baseUrl/auth/me" -WebSession $replaySession
    throw 'Unexpected authentication with a revoked session'
} catch {
    if ($null -eq $_.Exception.Response) { throw }
    [int]$_.Exception.Response.StatusCode # Expected: 401
} finally {
    Remove-Variable replaySession, authSession, login, logout -ErrorAction SilentlyContinue
}
```

Passwords and cookies necessarily exist briefly in process memory; the commands do not print or persist them. Do not use verbose HTTP tracing or dump these variables. Use the same origin and host spelling in both terminals. A 403 means origin configuration/header mismatch; a 429 means wait for the configured window, not bypass the limiter.

## Verification and remaining work

Executed locally with Python 3.12.14:

- `uv sync --locked`: passed, 39 resolved packages / 38 installed packages checked.
- `ruff check .` and `ruff format --check .`: passed; 42 Python files formatted.
- `pytest -m 'not integration'`: 75 passed, including five database safety tests.
- `scripts/test-integration.ps1`: 45 passed (40 real PostgreSQL tests plus five repeated safety tests).
- Migration verification: preserved `0001_foundation` and `0002_core_identity`, retained an existing user through upgrade to `0003_password_sessions`, confirmed current head, and successfully repeated the upgrade in private test schemas.
- `git diff --check`: passed. All three documented PowerShell code blocks parsed successfully.

Initial verification found a new test-module naming collision and formatting violations; both were corrected before the passing checks. No checks were weakened. The interactive development provisioning/login walkthrough and production HTTPS/browser behavior were not executed; development migration/provisioning remains deliberately manual. Multi-process load testing is outside this checkpoint. GitHub Actions for CORE-004 has not run; the user must review, commit, and push manually. No development migration, default account, new Docker resource, commit, push, or GitHub setting change was performed.

Before public deployment: roles and explicit permissions, trusted organization context, platform/client privilege separation, HTTPS and proxy policy, account recovery and mailbox verification, password change and session-wide revocation policy, compromised-password screening, MFA policy, security audit/retention, load testing, monitoring, backups and restore verification. This checkpoint provides authentication, not tenant authorization or public-deployment readiness. Stop after CORE-004.


## CORE-004-FIX: Local provisioning diagnosis

A read-only development check found `0003_password_sessions` applied and no `demo@example.test` user (therefore no associated credential; active/archived state is not applicable). The original failure cannot be identified from the old generic message. No password was requested or inspected, and no development data was written. Missing/invalid local environment is checked before prompting, whereas confirmation, password validation, identity conflicts, and database operations can fail afterward.

The local CLI now reports safe categories for invalid length, mismatched confirmation, required development/test mode, existing credentials, unavailable identities, and database/migration failure. It never prints raw exceptions. HTTP login responses and password policy are unchanged. Existing credentials must be used for login; this helper cannot reset or replace them.

In a **fresh terminal**, start from the project root, dot-source `scripts/use-tools.ps1`, and explicitly set `$env:CORE_ENVIRONMENT = 'development'` before running the provisioning command shown above. Settings in an already-running API terminal do not transfer to this terminal. The CLI loads the root `.env` itself, with this terminal's environment variables taking precedence. Preserve the intended database host/port overrides if using a non-default setup. `CORE_AUTH_ALLOWED_ORIGINS` is needed in the API's environment for HTTP login, not to provision a user. Keep the API running and use the existing secure-prompt login/logout/replay commands above. Leave interactive password entry to the user.

CORE-004-FIX verification: Ruff lint and formatting passed; 88 unit/safety tests passed (including 13 focused CLI diagnostic tests); all 45 isolated PostgreSQL/safety tests passed; `git diff --check` passed. No interactive provisioning was attempted, and the original failure cause remains unknown until the user retries with the improved diagnostics. Only `auth/provision.py`, `tests/unit/test_provision_cli.py`, and this handoff changed during the fix.


## CORE-004-LOGIN-FIX: Existing-user diagnosis

A subsequent read-only development inspection found the demo user present, active, unarchived, and with a recognized Argon2id v19 credential. The expected migration is applied. The inspection terminal's database configuration matches the project's `.env`; this does not establish the already-running API's inherited configuration. Both provisioning and login use `normalize_email` and the same Argon2id helper, with no password trimming or normalization. In the inspected implementation, throttling returns 429, Origin rejection 403, and database failures 503; none explain a login 401. No authentication defect or password match has been confirmed.

A temporary local module provides a read-only check. It requires explicit development/test mode, a loopback database host, and an interactive terminal. It calls the real `Passwords.verify`, prints only eligibility and match/no-match, and rolls back its PostgreSQL read-only transaction. It does not log in, rehash, alter credentials, create sessions, or clear/increment throttles. No diagnostic HTTP endpoint exists.

Run from the project root in a fresh terminal (these values select the standard development database; preserve an intentional non-default host port if applicable):

```powershell
. ./scripts/use-tools.ps1
$env:CORE_ENVIRONMENT = 'development'
$env:CORE_DB_HOST = '127.0.0.1'
$env:CORE_DB_PORT = '15432'
$env:CORE_DB_NAME = 'editingtab_core'
$env:CORE_DB_USERNAME = 'editingtab_dev'
# Use the existing password from the project .env, without displaying it.
Remove-Item Env:CORE_DB_PASSWORD -ErrorAction SilentlyContinue
$env:CORE_AUTH_ALLOWED_ORIGINS = '["http://127.0.0.1:18080"]'
uv run --locked python -m editingtab_core.auth.diagnose --email 'demo@example.test'
```

Enter the password yourself; never send it to Codex. A match proves only that the entered value matches this database credential. If eligible and matching but HTTP login still returns 401, investigate the API process/configuration and the HTTP payload. Non-ASCII passwords should be sent as UTF-8 JSON bytes (`[System.Text.Encoding]::UTF8.GetBytes($body)`) to avoid client encoding differences. No encoding defect has been confirmed here. No-match does not authorize a password reset.

If needed, stop the existing API yourself with Ctrl+C in its original terminal. Then, from the same explicitly configured terminal used for the diagnostic, start:

```powershell
uv run --locked uvicorn editingtab_core.app:create_app --factory --host 127.0.0.1 --port 18080 --no-proxy-headers
```

Verification for this diagnostic addition: 49 focused authentication/provisioning/diagnostic unit tests passed, including real Argon2 matches and non-matches using synthetic passwords, and assertions that the helper issues only read-only setup and SELECT then rolls back. Ruff lint/format passed. The user's interactive password verification was not run. No public authentication behavior or existing database data was changed.
