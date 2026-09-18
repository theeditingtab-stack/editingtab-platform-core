# Core / Booking authorization contract (v1)

CORE-007 implements only Core's side. Booking's inspected integration document described a proposed connection; its repository was not modified. Core and Booking are separate applications with separate databases. Booking must never connect to Core's database or infer authority from stored external UUIDs.

## Exact request and response

`POST /internal/v1/booking/authorize`, `Content-Type: application/json`

Required headers (values below are placeholders, not credentials):

```text
Authorization: Bearer <Booking service secret>
X-Core-Session: <existing opaque Core user session token>
```

```json
{"organization_id":"<UUID>","permission":"booking.inventory.read"}
```

Only `booking.inventory.read` and `booking.inventory.manage` are accepted. No actor/user ID, additional fields, or other module/Core permissions are accepted. The body is bounded to 4096 bytes. Duplicate credential headers are rejected. Browser cookies never authenticate this endpoint. Origin is not required on this exact service-authenticated route; all existing browser mutation Origin checks remain unchanged.

Success is HTTP 200 with exactly:

```json
{"authorized":true,"user_id":"<verified UUID>","organization_id":"<verified UUID>","permission":"booking.inventory.read"}
```

Every response from this endpoint has `Cache-Control: no-store`. Errors have only `{"error":"<code>"}`:

| HTTP | Code | Meaning |
| --- | --- | --- |
| 401 | `invalid_service_credentials` | Missing/invalid service credential, disabled integration, or unacceptable transport |
| 401 | `invalid_user_session` | Missing/malformed/expired/revoked session, inactive or archived user |
| 404 | `organization_not_accessible` | Missing/archived organization, absent/archived membership, or another organization's identifier |
| 403 | `permission_denied` | Active member does not hold the requested Booking permission |
| 403 | `module_disabled` | Booking entitlement is not enabled |
| 422 | `invalid_authorization_request` | Invalid JSON/body, extra fields, invalid UUID, unsupported permission, oversized body, or wrong method |
| 503 | `authorization_unavailable` | Core could not safely complete database authorization |

Transport and Booking service authentication run before parsing the body or inspecting user/tenant data. Session-header syntax and request validation follow, then current database session/user state, active membership/organization, permission union, and Booking entitlement. Platform grants alone never bypass tenant membership or permission checks. No passwords, profile data, tokens, or broad permission sets are returned. Do not log request bodies or either credential header. Validation responses never include supplied values.

There is no positive authorization cache. Every request rechecks database state; logout, session expiry, role/assignment revocation, archival, and disabled entitlements affect the next request. This is a point-in-time decision, not a cross-database transaction or lock on subsequent Booking work.

## Service credential and transport

Core accepts SHA-256 digests through these optional private deployment settings:

- `CORE_BOOKING_SERVICE_CURRENT_DIGEST`: lowercase 64-character hexadecimal digest. If absent, access is disabled, even if a previous digest is configured. Other Core features continue working.
- `CORE_BOOKING_SERVICE_PREVIOUS_DIGEST`: optional previous digest during rotation.

Settings hide digests from representations and dumps. Both supplied digest comparisons use constant-time comparison. Raw secrets must be 43-128 URL-safe ASCII characters (`A-Z`, `a-z`, digits, `_`, `-`); malformed/oversized credentials fail before hashing/database work. Generate at least 32 random bytes, never a human password. The two slots identify only the single Booking service and authorize only this Booking permission contract, not tenant or platform APIs.

Local setup, from the Core root:

```powershell
. ./scripts/use-tools.ps1
uv run --locked python scripts/init-booking-credential.py
```

This writes `.secrets/booking-service.secret` (raw, 32 random bytes encoded URL-safe) and `.secrets/booking-service.sha256` (matching digest), prints only relative paths/instructions, and never edits `.env` or Booking. `.secrets/` is ignored. Exclusive creation refuses either existing file. If disk/permission failure interrupts creation, inspect the new files locally; the helper retains placeholders rather than deleting files. Never overwrite a working pair to fix setup. Restrict the directory's Windows ACL to the operator; Git ignore is not access control.

Securely transfer the raw secret to Booking's private configuration through the deployment secret manager or another authenticated encrypted channel in a later Booking task. Core only needs the digest. Do not put secrets in command arguments, URLs, tickets, logs, documentation, or Git.

Rotation: generate a new pair in controlled private storage (preserve the old files; the helper intentionally refuses overwrites). Deploy Core with new=current and old=previous digests, deploy Booking with the new raw secret, verify calls, then remove Core's previous digest and retire the old secret. Restart/redeploy Core to load changed configuration. Do not leave old credentials enabled indefinitely; incidents may require immediate removal rather than an overlap. This checkpoint does not modify Booking or automate transfer.

Deployed calls require **direct HTTPS over a private network**. Core accepts HTTPS as reported by its trusted server transport; do not enable arbitrary proxy-header trust. Run with `--no-proxy-headers`. A future TLS-terminating proxy arrangement requires an explicitly reviewed trusted transport design; untrusted `X-Forwarded-Proto` is not a workaround. Plain HTTP is permitted only with explicitly selected development/test mode and a loopback peer. Bind the local API to loopback.

The public production gateway must not route `/internal` paths. Restrict the private listener to Booking and redact `Authorization`, `X-Core-Session`, cookies, and request bodies from gateway/APM/access/debug logs. Network isolation does not replace the service credential. There are no request-controlled outbound URLs; Core makes no outbound request here.

## Explicit initial Booking permission delegation

Migration `0006_booking_authorization` expands the permission CHECK constraint and adds nullable role provenance with a per-organization uniqueness constraint. It grants nothing. Existing and newly created owner roles retain their four explicit Core permissions, and enabling Booking grants no user permission.

A platform operator explicitly calls:

```text
POST /platform/organizations/{organization_id}/booking-inventory-administrator
Origin: <configured browser origin>
Cookie: <existing authenticated operator session>
```

```json
{"membership_id":"<active organization administrator membership UUID>"}
```

It requires current platform authority, active organization, enabled Booking, an active same-organization membership/user, and the recipient's current `core.roles.manage` permission. It locks the organization inside the transaction and creates/updates only the marked `Booking inventory administrator` role with the two explicit Booking permissions. A same-name unmarked role, renamed/archived marked role, or marked role carrying unrelated permissions causes 409; nothing is taken over. Tenant role APIs cannot set the provenance marker or platform privileges.

Assignment, permission changes, and audits commit atomically. Role audits record the actual operator and permission changes; platform audit targets the membership and records assigned state, role ID and permissions. Matching reruns make no changes or audit entries. Explicit reruns can restore missing Booking permissions/assignments on the still-designated active role; updating a shared role affects its existing assignees, so operators must review those assignments. There is no automatic regrant on startup, migration, or entitlement enablement. Tenant removal/revocation remains effective until an explicitly authorized provisioning/delegation action.

Success returns organization ID, membership ID, role ID and the two permission codes. This is a platform provisioning response, not the minimal internal authorization response. Normal tenant role APIs retain grant ceilings and last-admin checks; after provisioning, the recipient may delegate the Booking permissions they hold.

## Booking client obligations and versioning

The future Booking client must use a fixed configured HTTPS Core base URL, certificate verification, bounded connect/read/total timeouts (initial target: connect 2 seconds, total 5 seconds; verify against deployment), and no redirect following. Forward only the existing user token and Booking service credential to the fixed route. Do not forward browser-supplied service credentials. Do not cache positive decisions or retry indefinitely.

Validate HTTP status, JSON shape, `authorized` being exactly true, requested organization/permission matching the verified response, and a valid user UUID. Treat 401/403/404 as explicit denials. Treat 422 as a contract/request defect. Treat 503, timeouts, network/TLS failures, malformed responses, unexpected status/redirect, and invalid IDs as unavailable/unverifiable authorization. Distinguish denials from availability failures for user-facing errors and monitoring, but fail closed in both cases. Never fabricate an allow decision on Core downtime. Booking must still scope every database operation to the verified organization and implement its browser CSRF policy. Do not reuse decisions across later requests/jobs.

`/internal/v1` freezes this request/success/error shape, permission scope, and authentication semantics. Breaking changes require a separately versioned route and coordinated rollout. Additive permission support must be explicitly documented/tested by both repositories; v1 callers cannot assume arbitrary future codes are accepted. No client implementation is claimed here.

## Manual PowerShell walkthrough

Use the existing operator, owner, organization and enabled entitlement. Do not rerun user provisioning, onboarding, or platform bootstrap. Run from the Core root. Existing `.env` stays private. Use terminal A for the API and terminal B for verification.

1. **Prepare the new migration and local service credential (terminal B).** Review the migration, then run manually against development. The helper is one-time; if the pair already exists, skip its command after verifying its provenance locally.

   ```powershell
   . ./scripts/use-tools.ps1
   $env:CORE_ENVIRONMENT = 'development'
   uv run --locked alembic upgrade head
   uv run --locked alembic current
   uv run --locked python scripts/init-booking-credential.py
   ```

   Expected head: `0006_booking_authorization`. Neither command was run against development by Codex.

2. **Restart the API yourself in terminal A and leave it running.** Stop the previous process with Ctrl+C; load only the digest without printing it. Environment settings in terminal B do not configure terminal A.

   ```powershell
   . ./scripts/use-tools.ps1
   $env:CORE_ENVIRONMENT = 'development'
   $env:CORE_AUTH_ALLOWED_ORIGINS = '["http://127.0.0.1:18080"]'
   $env:CORE_BOOKING_SERVICE_CURRENT_DIGEST = (Get-Content -Raw .secrets/booking-service.sha256).Trim()
   [Environment]::SetEnvironmentVariable('CORE_BOOKING_SERVICE_PREVIOUS_DIGEST', $null)
   uv run --locked uvicorn editingtab_core.app:create_app --factory --host 127.0.0.1 --port 18080 --no-proxy-headers
   ```

3. **Login securely in terminal B.** Keep both sessions in memory; never print them.

   ```powershell
   $base = 'http://127.0.0.1:18080'
   $origin = @{ Origin = $base }
   function Open-CoreSession([string]$Email) {
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
   $operatorSession = Open-CoreSession 'operator@example.test'
   $ownerSession = Open-CoreSession 'demo@example.test'
   $owner = Invoke-RestMethod "$base/auth/me" -WebSession $ownerSession
   $offset = 0; $client = $null
   do {
       $page = Invoke-RestMethod "$base/platform/organizations?limit=100&offset=$offset" -WebSession $operatorSession
       $client = $page | Where-Object slug -eq 'core-006-demo-client'
       $offset += 100
   } while (-not $client -and $page.Count -eq 100)
   if (-not $client) { throw 'Existing demo organization not found; do not create a replacement.' }
   $orgId = $client.id
   $offset = 0; $member = $null
   do {
       $page = Invoke-RestMethod "$base/organizations/$orgId/members?limit=100&offset=$offset" -WebSession $ownerSession
       $member = $page | Where-Object user_id -eq $owner.id
       $offset += 100
   } while (-not $member -and $page.Count -eq 100)
   if (-not $member) { throw 'Existing owner membership not found.' }
   $state = Invoke-RestMethod "$base/organizations/$orgId/modules" -WebSession $ownerSession
   if ($state.enabled_modules -notcontains 'booking') { throw 'Booking must already be enabled; review platform state.' }
   ```

4. **Load the raw credential privately and demonstrate initial denial.** This helper prints only verified success fields or the error code/status, not headers. Before the first explicit grant the expected response is `403 permission_denied`; on a later walkthrough rerun, skip that initial-denial assertion if permission was already deliberately provisioned.

   ```powershell
   $serviceSecret = (Get-Content -Raw .secrets/booking-service.secret).Trim()
   $userToken = $ownerSession.Cookies.GetCookies([uri]$base)['editingtab_session'].Value
   $internalHeaders = @{ Authorization = "Bearer $serviceSecret"; 'X-Core-Session' = $userToken }
   $body = @{ organization_id = $orgId; permission = 'booking.inventory.read' }
   function Test-CoreDecision([hashtable]$Headers, [hashtable]$Body, [int]$ExpectedStatus, [string]$ExpectedCode = '') {
       $bytes = [Text.Encoding]::UTF8.GetBytes(($Body | ConvertTo-Json -Compress))
       $result = $null
       try {
           $response = Invoke-WebRequest "$base/internal/v1/booking/authorize" -Method Post -Headers $Headers -ContentType 'application/json; charset=utf-8' -Body $bytes -UseBasicParsing
           $status = [int]$response.StatusCode
           $result = $response.Content | ConvertFrom-Json
       } catch {
           if ($null -eq $_.Exception.Response) { throw 'Core authorization transport failure; fail closed.' }
           $status = [int]$_.Exception.Response.StatusCode
           try { $result = $_.ErrorDetails.Message | ConvertFrom-Json } catch { throw 'Unverifiable Core response; fail closed.' }
       }
       if ($status -ne $ExpectedStatus) { throw "Unexpected authorization status: $status" }
       if ($status -eq 200) {
           if ($result.authorized -ne $true -or $result.organization_id -ne $Body.organization_id -or $result.permission -ne $Body.permission -or $result.user_id -ne $owner.id) { throw 'Authorization response mismatch.' }
           $result | Select-Object authorized, user_id, organization_id, permission
       } else {
           if ($result.error -ne $ExpectedCode) { throw 'Unexpected authorization error code.' }
           [pscustomobject]@{ Status = $status; Error = $result.error }
       }
   }
   Test-CoreDecision $internalHeaders $body 403 'permission_denied'
   ```

5. **Explicitly provision the existing owner, then authorize.** This uses the operator session and existing Origin policy. Matching reruns are idempotent; conflicts require review, not role takeover.

   ```powershell
   $json = @{ membership_id = $member.id } | ConvertTo-Json -Compress
   Invoke-RestMethod "$base/platform/organizations/$orgId/booking-inventory-administrator" -Method Post -WebSession $operatorSession -Headers $origin -ContentType 'application/json; charset=utf-8' -Body ([Text.Encoding]::UTF8.GetBytes($json))
   Test-CoreDecision $internalHeaders $body 200
   ```

6. **Representative denials, logout, and memory cleanup (terminal B).** Finish logout/cleanup even if an earlier assertion fails. No database grants are removed by this walkthrough.

   ```powershell
   Test-CoreDecision @{ 'X-Core-Session' = $userToken } $body 401 'invalid_service_credentials'
   Test-CoreDecision $internalHeaders @{ organization_id = $orgId; permission = 'core.roles.manage' } 422 'invalid_authorization_request'
   $null = Invoke-WebRequest "$base/auth/logout" -Method Post -WebSession $ownerSession -Headers $origin -UseBasicParsing
   Test-CoreDecision $internalHeaders $body 401 'invalid_user_session'
   $null = Invoke-WebRequest "$base/auth/logout" -Method Post -WebSession $operatorSession -Headers $origin -UseBasicParsing
   $internalHeaders.Clear()
   $serviceSecret = $null; $userToken = $null
   $ownerSession = $null; $operatorSession = $null
   Remove-Variable internalHeaders, serviceSecret, userToken, ownerSession, operatorSession -ErrorAction SilentlyContinue
   ```

   Keep the ignored secret files private for the later Booking setup. Clearing references is not a guarantee of erasing managed-memory copies; logout revokes the tokens. After stopping terminal A, clear its process-local digest setting with `[Environment]::SetEnvironmentVariable('CORE_BOOKING_SERVICE_CURRENT_DIGEST', $null)` if no longer needed.

## Verification and remaining work

```powershell
. ./scripts/use-tools.ps1
uv sync --locked
uv run --locked ruff check .
uv run --locked ruff format --check .
uv run --locked pytest -m 'not integration'
./scripts/test-integration.ps1
git diff --check
```

Migration verification runs only in the isolated test database and verifies preserved data, unchanged old role grants, new head, and repeat upgrade. Existing CI discovers these tests automatically. No dependency changes are required. Manual development migration/provisioning and deployed HTTPS/gateway behavior remain user/operator verification, not claims of agent execution. Booking client implementation, inventory, gateway deployment, recovery, invitations, domains, frontend, backups and restore testing remain separate work. Stop after CORE-007; no commit or push.

Executed locally with Python 3.12.14: locked sync, Ruff lint, Ruff formatting (74 files), 131 unit/safety tests, and 140 integration-suite tests (135 PostgreSQL tests plus five repeated safety checks) passed. Migration preservation, reported head `0006_booking_authorization`, and repeated upgrade passed. The initial duplicate test basename and SQL line-length issues were corrected before these passing checks. No development migration, local credential generation, or permission provisioning was executed; no Booking file was changed. Remote CORE-007 GitHub Actions remains unexecuted until the user pushes.
