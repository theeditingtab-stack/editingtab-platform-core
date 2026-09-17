# CORE-006: Platform administration and client onboarding

The Editing Tab now has separate company authority, existing-user onboarding, and module entitlements. This checkpoint does not implement Booking inventory or public deployment readiness. The previous checkpoint is user-verified at `586b66b`, including GitHub Actions. CORE-006 remote CI must run after the user's manual commit/push.

## Authority and transactions

`platform` owns administrator grants, a permanent bootstrap marker, module entitlements, and platform audit. A valid existing session, active/unarchived user, and unrevoked platform grant are required on every platform request. Nothing is embedded in session tokens or inferred from email, domain, first user, or an organization role. Revocation is checked on the next request. Platform users still need their own tenant membership and permissions when using `/organizations` APIs.

The operator CLI takes an explicit existing active user's email and requires interactive confirmation. It is an operator tool, available in explicitly configured deployments, not a development-only promotion shortcut. Its authority comes from access to the server/database configuration, not a browser session. Restrict operator shell/database access accordingly. No credentials are created or modified. It locks the migration-created singleton row and checks both its completion marker and all historical grants in one transaction. Missing state fails closed; competing attempts produce only one grant. Revocation never reopens bootstrap. Do not downgrade/recreate bootstrap history to recover access. Subsequent grants, revocation tooling, and recovery require a separately designed controlled process; no grant-management HTTP API is supplied here.

Bootstrap audit uses `actor_kind=operator_bootstrap`, a null authenticated actor, and the grant target. It does not misidentify the promoted user as the operator or claim to authenticate an OS operator identity. Authenticated onboarding and entitlement audits record the actual session user, organization, action, target, timestamp, and relevant before/after state. They contain identifiers and module state, not passwords or unnecessary personal data.

Onboarding requires an existing active, unarchived owner with a credential record. It atomically creates the organization, membership, explicit four-permission owner role, assignment, requested entitlements, role audits, and platform onboarding audit. The trusted internal owner-construction helper is also used by the existing local organization bootstrap; tenant service authorization is unchanged. Reserved normalized slugs, including archived organizations, return 409 without repair or overwrite. Transaction failures roll back every new record. Services own transactions; no startup migration or bootstrap occurs.

## Modules and API

The central catalog is `booking`, `pos`, `unified_inbox`, and `chatbot`. Only `booking` can currently be enabled. This prepares access control, not a Booking implementation. Omitted modules default to disabled. Unknown modules and unsupported activation return 422; a known unsupported module may remain disabled. Database constraints also enforce the catalog and supported activation. Disabling preserves all data. No-op updates do not create rows, timestamps, or audit events.

| Method and route | Required authority / body |
| --- | --- |
| GET `/platform/organizations?limit=50&offset=0` | Platform grant; active organizations only, limit 1-100, offset 0-100000 |
| POST `/platform/organizations` | Platform grant; `{ "name": "Client", "slug": "client", "owner_email": "owner@example.test", "enabled_modules": ["booking"] }`; modules optional |
| GET `/platform/organizations/{id}/modules` | Platform grant; returns organization ID and enabled module codes |
| PUT `/platform/organizations/{id}/modules/{code}` | Platform grant; `{ "enabled": true }` (strict JSON boolean) |
| GET `/organizations/{id}/modules` | Active membership and `core.organization.read`; same minimal state response |

All mutations use the existing fail-closed Origin allowlist; bodies reject extra fields. Actors come from the session. Unauthenticated requests return 401; authenticated users without platform authority return 403. Tenant inaccessible organizations return 404; members lacking permission return 403. Archived/missing platform organization targets return 404. Database errors are generic 503. Sensitive responses are not cached. There are no destructive organization or tenant entitlement mutation routes.

Future Booking services must first authenticate and enforce their organization-specific permission, then call `platform.services.require_entitlement(session, organization_id=..., module_code="booking")` inside their own transaction. It queries current organization and entitlement state and denies disabled access. It does not replace user authorization or start/commit a transaction. The integration suite composes these checks in a test-only HTTP route; that route is absent from the production factory. Disable applies to subsequent checks; cancellation of already-running operations needs an explicit future Booking policy.

## Manual PowerShell walkthrough

Run from the project root. Keep the existing development database and `.env`; do not repeat initialization or reset data. Use your already provisioned, verified `demo@example.test` as owner below (substitute its actual email if different). Choose a new client slug. Run steps in order; if an operation reports a conflict, inspect existing state instead of trying to regrant or overwrite it. Environment overrides are per terminal: ensure database overrides match the existing local setup and are not stale test settings.

1. **Development migration (terminal B).** Review this change first, then manually upgrade:

   ```powershell
   . ./scripts/use-tools.ps1
   $env:CORE_ENVIRONMENT = 'development'
   uv run --locked alembic upgrade head
   uv run --locked alembic current
   ```

   Expected head: `0005_platform_onboarding`. Codex does not run this against development. In **terminal A**, stop the old API yourself with Ctrl+C and start the updated factory; leave this terminal running throughout steps 2-8:

   ```powershell
   . ./scripts/use-tools.ps1
   $env:CORE_ENVIRONMENT = 'development'
   $env:CORE_AUTH_ALLOWED_ORIGINS = '["http://127.0.0.1:18080"]'
   uv run --locked uvicorn editingtab_core.app:create_app --factory --host 127.0.0.1 --port 18080 --no-proxy-headers
   ```

2. **Provision a separate operator (terminal B).** Enter and confirm its password only in the secure prompts. Existing credentials are not overwritten; do not reprovision your existing owner.

   ```powershell
   uv run --locked python -m editingtab_core.auth.provision --email 'operator@example.test' --display-name 'Local Platform Operator'
   ```

3. **Explicit initial bootstrap (terminal B).** Check the target email and type `GRANT INITIAL PLATFORM ADMIN` when prompted. Only the first successful bootstrap is allowed, including after revocation.

   ```powershell
   uv run --locked python -m editingtab_core.platform.bootstrap --email 'operator@example.test'
   ```

4. **Login with UTF-8 JSON (terminal B).** This helper prompts securely, retains cookies only in memory, and returns only the web session. Do not print session objects or cookie values.

   ```powershell
   $base = 'http://127.0.0.1:18080'
   $origin = @{ Origin = $base }
   function Open-DemoSession([string]$Email) {
       $secure = Read-Host "Password for $Email" -AsSecureString
       $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
       try {
           $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
           $json = @{ email = $Email; password = $plain } | ConvertTo-Json -Compress
           $bytes = [Text.Encoding]::UTF8.GetBytes($json)
           $web = New-Object Microsoft.PowerShell.Commands.WebRequestSession
           $null = Invoke-WebRequest "$base/auth/login" -Method Post -WebSession $web -Headers $origin -ContentType 'application/json; charset=utf-8' -Body $bytes -UseBasicParsing
           return $web
       } finally {
           [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
           if ($bytes) { [Array]::Clear($bytes, 0, $bytes.Length) }
           $plain = $null; $json = $null; $secure = $null
       }
   }
   $operatorSession = Open-DemoSession 'operator@example.test'
   Invoke-RestMethod "$base/platform/organizations?limit=10&offset=0" -WebSession $operatorSession
   ```

5. **Onboard a new demo client with your existing owner (terminal B).** A duplicate slug returns 409 without changes; use a deliberate unused slug only for a genuinely new client.

   ```powershell
   $json = @{ name = 'CORE-006 Demo Client'; slug = 'core-006-demo-client'; owner_email = 'demo@example.test'; enabled_modules = @('booking') } | ConvertTo-Json -Compress
   $client = Invoke-RestMethod "$base/platform/organizations" -Method Post -WebSession $operatorSession -Headers $origin -ContentType 'application/json; charset=utf-8' -Body ([Text.Encoding]::UTF8.GetBytes($json))
   $orgId = $client.id
   $client | Select-Object id, name, slug, enabled_modules
   ```

6. **Verify owner access and Booking entitlement (terminal B).** Use the owner's own password; platform authority is not transferred to them.

   ```powershell
   $ownerSession = Open-DemoSession 'demo@example.test'
   Invoke-RestMethod "$base/organizations/$orgId" -WebSession $ownerSession
   Invoke-RestMethod "$base/organizations/$orgId/roles" -WebSession $ownerSession
   Invoke-RestMethod "$base/organizations/$orgId/modules" -WebSession $ownerSession
   ```

   Expect the owner role's four explicit Core permissions and `enabled_modules` containing `booking`. No Booking endpoint exists yet.

7. **Verify the ordinary owner cannot use platform authority (terminal B).** This prints only the status and fails if the expected denial is absent.

   ```powershell
   $status = $null
   try {
       $response = Invoke-WebRequest "$base/platform/organizations" -WebSession $ownerSession -UseBasicParsing
       $status = [int]$response.StatusCode
   } catch {
       if ($null -eq $_.Exception.Response) { throw 'Request failed before an HTTP response.' }
       $status = [int]$_.Exception.Response.StatusCode
   }
   if ($status -ne 403) { throw "Expected 403; received $status" }
   Write-Output "Owner platform access: HTTP $status"
   ```

8. **Disable and re-enable Booking (terminal B).** The same owner session sees each new state; no login repetition or data deletion is required. End with Booking enabled and revoke the two walkthrough sessions.

   ```powershell
   foreach ($enabled in @($false, $true)) {
       $json = @{ enabled = $enabled } | ConvertTo-Json -Compress
       $null = Invoke-RestMethod "$base/platform/organizations/$orgId/modules/booking" -Method Put -WebSession $operatorSession -Headers $origin -ContentType 'application/json; charset=utf-8' -Body ([Text.Encoding]::UTF8.GetBytes($json))
       $state = Invoke-RestMethod "$base/organizations/$orgId/modules" -WebSession $ownerSession
       if (($state.enabled_modules -contains 'booking') -ne $enabled) { throw 'Entitlement state did not match.' }
       $state
   }
   $null = Invoke-WebRequest "$base/auth/logout" -Method Post -WebSession $ownerSession -Headers $origin -UseBasicParsing
   $null = Invoke-WebRequest "$base/auth/logout" -Method Post -WebSession $operatorSession -Headers $origin -UseBasicParsing
   ```

## Automated verification

No dependencies were added and `uv.lock` is unchanged. Existing CI already runs all integration tests against disposable PostgreSQL 17; no workflow change is necessary. Run from a project-root PowerShell terminal, independently of API terminal A:

```powershell
. ./scripts/use-tools.ps1
uv sync --locked
uv run --locked ruff check .
uv run --locked ruff format --check .
uv run --locked pytest -m 'not integration'
./scripts/test-integration.ps1
git diff --check
```

The integration helper supplies only explicit test database settings on port 15433. If the previously configured test service is stopped, use `./scripts/start-db.ps1 -TestDatabase` before the integration helper. Do not substitute development credentials. Migration tests upgrade baseline through all revisions, preserve identity/credentials/memberships/roles, verify current head, and repeat the upgrade inside an isolated schema. Concurrency tests use independent connections and remove only their newly created test schema.

Executed locally with Python 3.12.14: locked sync, Ruff lint, Ruff format check (67 files), 104 unit/safety tests, and 106 integration-suite tests (101 real PostgreSQL tests plus five repeated safety checks) passed. Migration checks reported `0005_platform_onboarding` and repeated upgrade succeeded. The concurrent bootstrap and existing last-administrator race tests passed using independent database connections. Initial lint line-length failures were corrected before the passing final checks. The manual development walkthrough and remote CI are user-run checks, not claims of agent execution.

## Remaining requirements

Invitations, public signup, recovery (including platform administrator recovery), email delivery, platform MFA, further grant/revocation tooling, custom domain verification, Booking inventory/reservations and feature permissions, frontend, HTTPS deployment, monitoring, backups and restore testing remain future checkpoints. Backup/recovery targets and costs require decisions; synchronization is not a backup. OTA access and offline conflicts remain unresolved as described in the project brief. This checkpoint neither removes those requirements nor promises the two-week planning target.
