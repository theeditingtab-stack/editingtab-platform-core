# CORE-005: Organization roles and enforced permissions

The Editing Tab now exposes a small organization API protected by existing revocable sessions. Core owns roles, grants, and audit records. Starting commit: `aedfa62` (user-verified CORE-004). No platform administration, onboarding UI, module entitlements, Booking, frontend, or deployment is implemented here.

## Policy and storage

The central catalog in `authorization/policy.py` contains exactly:

- `core.organization.read`: read an accessible organization.
- `core.members.read`: list active memberships and minimal user profiles.
- `core.roles.read`: list active roles and permission codes.
- `core.roles.manage`: create/update/archive roles and assign/remove roles.

The local bootstrap's `Organization owner` role explicitly contains these four codes. No wildcard includes future capabilities. New permissions must accompany their protected features, database catalog migration, request limits, and tests. Unknown codes, including platform privileges, are rejected in services and by a database CHECK constraint.

Effective permissions are the union of a membership's active roles within its organization. Membership alone grants no administration. Archived organizations, users, memberships, and roles, and inactive users, grant nothing. Current database state is checked for every request; no permission snapshot is stored in the session. Committed revocation takes effect on the next request without re-login. Listing one's own active organizations is allowed by membership; protected organization details still require the read permission.

Services enforce authorization. HTTP derives the actor UUID from the authenticated session, never a submitted actor ID. Every role mutation locks the organization row before checking current authority. Managers can grant only permissions they hold. Updates check both old and new permission sets; archive and assignment removal also check the target role's permissions. Limited managers cannot rename, weaken, archive, assign, or unassign a more privileged role through a weaker operation.

Migration `0004_organization_roles` follows unchanged `0003_password_sessions`. It adds `core_roles`, `core_role_permissions`, `core_membership_roles`, and `core_role_audit`, plus a composite unique key on existing memberships. Composite foreign keys enforce matching organization ownership for roles and memberships independently of service checks. Roles use UUIDs and timezone-aware timestamps. See PostgreSQL's [foreign-key constraints](https://www.postgresql.org/docs/17/ddl-constraints.html).

Role names are trimmed printable ASCII, 1?100 characters. Uniqueness uses ASCII lowercase within an organization; interior spaces are preserved. Names remain reserved after archival. Roles are soft-deleted; permission and assignment associations are explicitly removed for revocation. Repeated assignment addition is idempotent and does not fabricate another change audit.

## Last administrator and lifecycle

Changes that would remove the last active member with `core.roles.manage` return 409 and roll back. The prospective state is evaluated after flushing inside the same transaction. `SELECT FOR UPDATE` on the organization serializes conflicting changes under default READ COMMITTED isolation; PostgreSQL [row locks](https://www.postgresql.org/docs/17/explicit-locking.html) last until transaction completion. A test proves two real connections overlap on database locks: one administrator removal succeeds, the other is rejected.

Internal membership archival now removes role assignments with audit and last-admin checks. If assignments exist, an explicit authorized `actor_id` is required; omitting it cannot bypass checks. Restored memberships have no historical roles and need explicit reassignment. Unexpected historical assignments on an archived membership cause restoration to fail closed. Membership operations without assignments remain compatible with legacy organizations having no administrator yet. Bootstrap does not silently repair existing organizations.

Organization archival remains internal and preserves records while disabling organization access. No public organization-archive endpoint exists. Future user-deactivation/archive services must coordinate last-admin checks across affected organizations; no such mutation API exists here. Direct SQL edits bypass service-level invariants and are not a supported management path. This is not PostgreSQL row-level security or platform-superadmin access.

Role/assignment audit records contain organization, actor UUID, action, target role UUID, optional membership UUID, timestamp, and before/after permission-code arrays. They commit with the change and roll back on failure. No passwords, hashes, tokens, cookies, or member names/emails are included. There is no audit UI or generic logging framework.

## API contract

All routes require the existing session cookie. Every mutation also requires the existing exact Origin allowlist check. GET makes no changes. Organization responses are `Cache-Control: no-store`. Lists accept `limit` (1?100, default 50) and `offset` (0?100000), ordered by UUID.

| Method and path | Required authority / result |
| --- | --- |
| `GET /organizations` | Active memberships of the user; id/name/slug |
| `GET /organizations/{org}` | `core.organization.read`; id/name/slug |
| `GET /organizations/{org}/members` | `core.members.read`; membership id, user id, display name |
| `GET /organizations/{org}/roles` | `core.roles.read`; id, name, permission codes |
| `POST /organizations/{org}/roles` | `core.roles.manage`; JSON name/permissions; 201 role |
| `PUT /organizations/{org}/roles/{role}` | `core.roles.manage`; full replacement JSON name/permissions; 200 role |
| `DELETE /organizations/{org}/roles/{role}` | `core.roles.manage`; archive; 204 |
| `PUT /organizations/{org}/members/{member}/roles/{role}` | `core.roles.manage`; idempotent assignment; 204 |
| `DELETE /organizations/{org}/members/{member}/roles/{role}` | `core.roles.manage`; remove existing assignment; 204 |

401 means unauthenticated. Inaccessible organizations and foreign resource IDs return the same 404 `Resource not found.` Active members lacking permission receive 403. Last-admin and reserved-name conflicts return safe 409 responses. Invalid catalog/input returns 422; database errors return generic 503. Origin failures are 403 before route execution. Role bodies accept only `name` and `permissions`; assignment requests need no body.

## Checks

```powershell
. ./scripts/use-tools.ps1
uv sync --locked
uv run --locked ruff check .
uv run --locked ruff format --check .
uv run --locked pytest -m 'not integration'
./scripts/start-db.ps1 -TestDatabase
./scripts/test-integration.ps1
git diff --check
```

Ordinary integration tests use rollback-only private schemas. The concurrency test commits data in a newly created `core_concurrent_<random UUID>` schema within the explicitly guarded test database, then drops only that owned schema. It never resets a database or touches development. Existing CI runs all these tests with PostgreSQL. No dependencies or infrastructure were added.

## Manual development migration and bootstrap

Codex did not run these against development. Run from the project root after review. Preserve intentional non-default database settings in both terminals.

```powershell
. ./scripts/use-tools.ps1
$env:CORE_ENVIRONMENT = 'development'
$env:CORE_AUTH_ALLOWED_ORIGINS = '["http://127.0.0.1:18080"]'
uv run --locked alembic upgrade head
uv run --locked alembic current
uv run --locked python -m editingtab_core.authorization.bootstrap --email 'demo@example.test' --slug 'demo-hotel' --name 'Demo Hotel'
uv run --locked uvicorn editingtab_core.app:create_app --factory --host 127.0.0.1 --port 18080 --no-proxy-headers
```

Stop an already-running API yourself before restarting. Bootstrap requires an existing active user and explicit email, slug, and name. It creates no credentials or platform privilege. Any existing slug, even archived, causes an actionable conflict without changing administration. Rerunning after revocation cannot regrant permissions. Older organizations receive no automatic owner.

## Restricted-user preparation

Use fresh demo slugs/role names for this walkthrough. Reruns preserve existing grants; inspect existing state instead of resetting it. In another project-root terminal:

```powershell
. ./scripts/use-tools.ps1
$env:CORE_ENVIRONMENT = 'development'
uv run --locked python -m editingtab_core.auth.provision --email 'observer@example.test' --display-name 'Restricted Demo'
uv run --locked python -m editingtab_core.authorization.bootstrap --email 'observer@example.test' --slug 'demo-safari' --name 'Demo Safari'
```

Enter the observer password securely. If credentials already exist, use them; do not replace them. There is no public member-onboarding API. Manually prepare the observer's hotel membership without roles through the existing trusted identity service:

```powershell
@'
from sqlalchemy import select
from sqlalchemy.orm import Session
from editingtab_core.auth.provision import require_local
from editingtab_core.config import load_settings
from editingtab_core.database import build_engine
from editingtab_core.identity.models import Organization, User
from editingtab_core.identity.services import add_membership
settings = load_settings()
require_local(settings)
engine = build_engine(settings)
try:
    with Session(engine) as session:
        with session.begin():
            org = session.scalar(select(Organization.id).where(Organization.slug == "demo-hotel", Organization.deleted_at.is_(None)))
            user = session.scalar(select(User.id).where(User.normalized_email == "observer@example.test", User.is_active.is_(True), User.deleted_at.is_(None)))
        if org is None or user is None:
            raise SystemExit("Expected active demo organization/user missing")
        add_membership(session, organization_id=org, user_id=user)
    print("Membership prepared; this command assigns no roles.")
finally:
    engine.dispose()
'@ | uv run --locked python -
```

The observer owns the safari organization but has only membership in the hotel. Permissions never cross that boundary.


## Owner, restricted access, cross-organization denial, and revocation

Continue in the second terminal. Login prompts securely, sends UTF-8 JSON bytes, and retains cookies only in session variables. Do not print cookie jars or verbose HTTP headers.

```powershell
$base = 'http://127.0.0.1:18080'
$origin = @{ Origin = $base }
function New-DemoSession([string]$Email) {
    $secure = Read-Host "Password for $Email" -AsSecureString
    $credential = [System.Management.Automation.PSCredential]::new($Email, $secure)
    try {
        $json = @{ email = $Email; password = $credential.GetNetworkCredential().Password } | ConvertTo-Json -Compress
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
        $result = Invoke-WebRequest -UseBasicParsing -Uri "$base/auth/login" -Method Post -Headers $origin -ContentType 'application/json; charset=utf-8' -Body $bytes -SessionVariable session
        if ($result.StatusCode -ne 204) { throw 'Login did not succeed' }
        return $session
    } finally {
        Remove-Variable secure, credential, json, bytes, result -ErrorAction SilentlyContinue
    }
}
function Send-DemoJson([string]$Uri, [string]$Method, $Body, $Session) {
    $bytes = [System.Text.Encoding]::UTF8.GetBytes(($Body | ConvertTo-Json -Depth 5 -Compress))
    Invoke-RestMethod -Uri $Uri -Method $Method -WebSession $Session -Headers $origin -ContentType 'application/json; charset=utf-8' -Body $bytes
}
function Expect-Status([scriptblock]$Request, [int]$Expected) {
    try {
        $response = & $Request
        $actual = [int]$response.StatusCode
    } catch {
        if ($null -eq $_.Exception.Response) { throw }
        $actual = [int]$_.Exception.Response.StatusCode
    }
    if ($actual -ne $Expected) { throw "Expected HTTP $Expected; received $actual" }
    Write-Output "Verified HTTP $actual"
}
$ownerSession = New-DemoSession 'demo@example.test'
$observerSession = New-DemoSession 'observer@example.test'
$ownerOrganizations = Invoke-RestMethod "$base/organizations" -WebSession $ownerSession
$hotel = ($ownerOrganizations | Where-Object slug -eq 'demo-hotel').id
$observerOrganizations = Invoke-RestMethod "$base/organizations" -WebSession $observerSession
$safari = ($observerOrganizations | Where-Object slug -eq 'demo-safari').id
$observerUser = (Invoke-RestMethod "$base/auth/me" -WebSession $observerSession).id
$hotelMembers = Invoke-RestMethod "$base/organizations/$hotel/members" -WebSession $ownerSession
$observerMember = ($hotelMembers | Where-Object user_id -eq $observerUser).id
if (-not $hotel -or -not $safari -or -not $observerMember) { throw 'Expected demo setup missing' }

Expect-Status { Invoke-WebRequest -UseBasicParsing "$base/organizations/$hotel" -WebSession $ownerSession } 200
Expect-Status { Invoke-WebRequest -UseBasicParsing "$base/organizations/$hotel" -WebSession $observerSession } 403
Expect-Status { Invoke-WebRequest -UseBasicParsing "$base/organizations/$safari" -WebSession $ownerSession } 404

$reader = Send-DemoJson "$base/organizations/$hotel/roles" 'Post' @{ name = 'Demo reader'; permissions = @('core.organization.read') } $ownerSession
$assignment = "$base/organizations/$hotel/members/$observerMember/roles/$($reader.id)"
Expect-Status { Invoke-WebRequest -UseBasicParsing $assignment -Method Put -Headers $origin -WebSession $ownerSession } 204
Expect-Status { Invoke-WebRequest -UseBasicParsing "$base/organizations/$hotel" -WebSession $observerSession } 200
Expect-Status { Invoke-WebRequest -UseBasicParsing "$base/organizations/$hotel/members" -WebSession $observerSession } 403

# Same observer session: committed removal denies the very next request.
Expect-Status { Invoke-WebRequest -UseBasicParsing $assignment -Method Delete -Headers $origin -WebSession $ownerSession } 204
Expect-Status { Invoke-WebRequest -UseBasicParsing "$base/organizations/$hotel" -WebSession $observerSession } 403
# Archive only the reader role created by this walkthrough.
Expect-Status { Invoke-WebRequest -UseBasicParsing "$base/organizations/$hotel/roles/$($reader.id)" -Method Delete -Headers $origin -WebSession $ownerSession } 204

Expect-Status { Invoke-WebRequest -UseBasicParsing "$base/auth/logout" -Method Post -Headers $origin -WebSession $ownerSession } 204
Expect-Status { Invoke-WebRequest -UseBasicParsing "$base/auth/logout" -Method Post -Headers $origin -WebSession $observerSession } 204
Remove-Variable ownerSession, observerSession -ErrorAction SilentlyContinue
```

To update a role, use `Send-DemoJson` with `Put` and the full name/permissions body at `/organizations/{org}/roles/{role}`. Do not test removal of real owners manually; isolated tests cover all last-admin rejection paths and concurrent removal.

## Executed verification and limitations

Python 3.12.14; no dependency or lockfile changes. `uv sync --locked`, Ruff lint/format (56 files), 101 unit/safety tests, and 70 PostgreSQL/safety tests passed. The integration run includes five repeated safety tests and verifies migration upgrade through each committed revision to `0004_organization_roles`, preserved profiles/credentials/memberships, reported current head, and repeated upgrade. Earlier revision files were preserved. Git whitespace checks passed. All 20 PowerShell blocks across this handoff, the authentication handoff, and local-development instructions parsed successfully. The local bootstrap audit identifies the selected existing user as its bootstrap actor; it is a trusted development helper, not authenticated platform onboarding.

The development migration, bootstrap, and manual HTTP walkthrough were not executed. The user runs those after review. Remote GitHub Actions for CORE-005 has not run; existing CI automatically includes these tests. Test-only schema cleanup completed; development data and running services were untouched.

Remaining work includes separate platform administration, company-controlled onboarding, user lifecycle coordination, account recovery, module entitlements, domain routing and broader audit/retention policy, Booking, frontend, HTTPS/proxy deployment, operational monitoring, and backup/restore verification. This checkpoint is not public-deployment readiness. Stop after CORE-005; no commit or push was performed.
