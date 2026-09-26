# Core / Booking authorization contract (v1)

CORE-AUTH-006 defines Core's authoritative decision for protected Booking operations. It changes
only the Core repository. Booking remains a separate application with its own database and must
not read Core tables or infer authority from an organization UUID.

## Permission vocabulary

The endpoint accepts one exact active Booking permission from this closed vocabulary:

- `booking.inventory.read`
- `booking.inventory.manage`
- `booking.reservations.read`
- `booking.reservations.create`
- `booking.reservations.update`
- `booking.reservations.cancel`
- `booking.availability.read`
- `booking.safari.read`
- `booking.safari.manage`
- `booking.settings.read`
- `booking.settings.manage`

There are no wildcard, POS, Inbox, or Chatbot permissions. Malformed codes, unknown codes, and
non-Booking codes all fail as invalid authorization requests.

## Request and positive response

`POST /internal/v1/booking/authorize`, with `Content-Type: application/json`:

```text
Authorization: Bearer <Booking service secret>
X-Core-Session: <opaque Core user session token>
```

```json
{"organization_id":"<UUID>","permission":"booking.reservations.create"}
```

The service credential authenticates Booking, while the Core session proves the user identity.
The organization and exact permission select the tenant relationship and operation to evaluate;
neither is authority by itself. Browser cookies do not authenticate this internal endpoint, and
the service credential must never be sent to or accepted from the browser.

HTTP 200 contains exactly the identifiers Core verified:

```json
{
  "allowed": true,
  "user_id": "<UUID>",
  "membership_id": "<UUID>",
  "organization_id": "<UUID>",
  "permission": "booking.reservations.create"
}
```

It does not contain roles, the broader permission set, grant authority, platform grants,
entitlement lists, credentials, session data, or secrets. Every response carries
`Cache-Control: no-store`.

## Authoritative decision flow

Core evaluates each call from current database state and allows it only when all of these remain
true:

1. the Booking service credential and transport are valid;
2. the Core session exists, is unexpired, and is not revoked;
3. the session user is active and not archived;
4. the requested organization and the user's membership are active;
5. an active assigned organization role currently supplies the exact requested permission; and
6. that same organization's Booking entitlement is enabled.

The decision uses no role names, frontend lists, session permission claims, wildcard expansion,
or platform-admin bypass. Logout, selected-session revocation, password reset, user deactivation,
membership/organization/role archival, assignment or permission removal, and entitlement disable
affect the next request. The response is a point-in-time decision; Booking must still scope its own
database operation to the verified organization and must not cache or reuse the result.

## Error contract

Errors contain only `{"error":"<code>"}`. The deliberately grouped cases avoid disclosing
tenant existence or credential detail.

| HTTP | Code | Cases |
| --- | --- | --- |
| 401 | `invalid_service_credentials` | Missing/bad service credential, integration disabled, duplicate credential header, or unacceptable transport |
| 401 | `invalid_user_session` | Missing/malformed/expired/revoked session, archived user, or inactive user |
| 422 | `invalid_authorization_request` | Invalid JSON/body/UUID, extra field, malformed/non-Booking/unknown permission, wrong method, or body over 4096 bytes |
| 404 | `organization_not_accessible` | Missing/archived organization, missing/archived membership, or foreign organization |
| 403 | `permission_denied` | Active member lacks the exact effective permission |
| 403 | `module_disabled` | Exact permission is present but the organization's Booking entitlement is disabled or absent |
| 503 | `authorization_unavailable` | Core cannot safely complete the database decision |

Service authentication happens before body parsing or user/tenant database access. Session-header
syntax is checked before the request body reaches the route. Core does not echo supplied values or
log credential contents through this contract. Booking must fail closed for every non-200 result,
timeout, TLS/network failure, malformed response, redirect, or identifier mismatch.

## Service credential boundary

Core stores only SHA-256 digests in private deployment settings:

- `CORE_BOOKING_SERVICE_CURRENT_DIGEST` is required; without it the integration is disabled.
- `CORE_BOOKING_SERVICE_PREVIOUS_DIGEST` optionally supports a bounded credential-rotation
  overlap and cannot enable access without a current credential configuration.

Raw credentials are 43-128 URL-safe ASCII characters backed by at least 32 random bytes. Core
hashes the submitted secret and performs constant-time comparisons against both configured slots
without short-circuiting the comparisons. Neither the raw credential nor either digest appears in
responses. Generate local material with
`uv run --locked python scripts/init-booking-credential.py`; transfer the raw secret to Booking
only through private deployment secret management.

Production calls require direct private HTTPS. Plain HTTP is accepted only in explicit local mode
from a loopback peer. The public gateway must not route `/internal`; private gateway, application,
APM, and access logs must redact `Authorization`, `X-Core-Session`, cookies, and request bodies.

## Default Booking administrator provisioning

The existing platform-only route remains for compatibility:

```text
POST /platform/organizations/{organization_id}/booking-inventory-administrator
Origin: <configured browser origin>
Cookie: <active platform operator Core session>

{"membership_id":"<active same-organization membership UUID>"}
```

Despite the historical route name and persisted `booking_inventory` provenance marker, new
provisioning creates the dedicated `Booking administrator` organization role. It assigns all 11
Booking permissions above with `can_grant=false`, no Core permissions, and no platform authority.
The operation requires current platform authority, an active enabled organization, an active
recipient membership/user, and the recipient's current `core.roles.assign` permission.

Provisioning changes only the dedicated marked role and the requested membership assignment.
Arbitrary custom roles are never modified. A marked role with unrelated permissions, an archived
or tenant-renamed marked role, or a conflicting reserved name fails closed. Matching reruns are
idempotent. An explicit authorized rerun may restore missing reviewed Booking permissions and may
evolve the legacy dedicated `Booking inventory administrator` name to `Booking administrator`;
the permission/name transition is audited. Nothing is regranted at startup, entitlement enable,
or migration time.

Because all provisioned Booking permissions have `can_grant=false`, possessing the role does not
allow the recipient to delegate those permissions. This preserves CORE-AUTH-002's separation of
permission use from grant authority.

## `/auth/context` versus this decision

`GET /auth/context` is informational UX context. It exposes a current-state snapshot so a trusted
frontend can shape navigation, but its role names, permission list, grant-authority list, enabled
module list, and selected organization ID are never authorization evidence.

`POST /internal/v1/booking/authorize` is the authoritative service decision. It independently
revalidates the service, session, active user, active tenant relationship, one exact permission,
and Booking entitlement. A Booking permission can therefore still appear in `/auth/context` while
an internal request is denied because the entitlement is disabled; conversely, entitlement alone
never supplies a missing permission. Both paths derive membership and effective permission state
from the same current Core repository queries rather than session claims.

## Persistence and next integration step

No CORE-AUTH-006 migration is required. Migrations through `0010_account_onboarding` already
contain the final permission registry, role provenance, grant metadata, entitlement, and session
models. Existing installations change the dedicated role only when an operator explicitly invokes
provisioning, which keeps upgrades from silently changing tenant grants.

A later Booking-repository checkpoint must map every protected Booking operation to one exact code,
forward the opaque Core session proof server-to-server, call the fixed v1 URL with bounded timeouts
and no redirects, strictly validate the minimal response, fail closed, and scope all Booking data
access to the returned organization. That future work must not expose the service credential to the
frontend or trust frontend-provided authorization lists.
