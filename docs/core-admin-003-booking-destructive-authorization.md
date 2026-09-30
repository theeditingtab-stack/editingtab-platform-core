# CORE-ADMIN-003: Booking destructive authorization

Permanent reservation deletion is an exceptional platform operation, not a tenant role
capability. Tenant roles are administered within an organization and may be delegated by client
administrators; allowing permanent deletion through that mechanism would let a client grant an
irreversible operation. Core therefore provides a separate internal decision that requires
persistent Editing Tab platform authority.

This checkpoint authorizes the approval event only. Booking continues to own reservation data and
is responsible for performing and recording the later database deletion. Core never reads or
writes Booking's private tables.

## Supported operation

The closed platform-operation allowlist contains exactly:

- `reservation.purge`

Unknown operations fail closed. This contract does **not** create
`booking.reservations.purge`, does not add a tenant permission to `BOOKING_PERMISSIONS`, and does
not grant or require organization membership.

## Internal request and response

Booking calls:

```text
POST /internal/v1/booking/authorize-destructive
Authorization: Bearer <Booking service secret>
X-Core-Session: <opaque Core user session token>
Content-Type: application/json
```

```json
{
  "organization_id": "<target organization UUID>",
  "operation": "reservation.purge"
}
```

An allowed response is deliberately limited to the verified decision context:

```json
{
  "allowed": true,
  "user_id": "<platform administrator user UUID>",
  "organization_id": "<target organization UUID>",
  "operation": "reservation.purge"
}
```

It contains no membership, role, ordinary permission, platform-grant, entitlement, credential, or
session details. Every response has `Cache-Control: no-store`.

The internal endpoint uses the same Booking-only transport and service-authentication boundary as
`POST /internal/v1/booking/authorize`. Core validates the configured current or rotation-slot
Booking service credential before parsing the request body or querying user and organization
state. The service secret must remain server-side in Booking and must never be sent to a browser.

## Authorization sequence

Core allows the request only when all checks pass against current Core database state:

1. the existing Booking service credential and trusted transport are valid;
2. `X-Core-Session` identifies a live, unrevoked, unexpired Core session;
3. the session user is active and not archived;
4. the same user currently has a non-revoked persistent platform administrator grant;
5. the explicitly supplied target organization exists and is not archived;
6. that target organization has an enabled Booking entitlement; and
7. the requested operation exactly matches the supported allowlist.

The platform grant is loaded by Core; no boolean, header, role name, or claim from Booking can
assert platform authority. A client administrator is denied even if their tenant roles contain
every ordinary Booking permission. Conversely, a platform administrator is denied when the
target organization's Booking entitlement is absent or disabled. No membership is created or
changed by a decision.

Errors use the existing minimal internal shape, `{"error":"<code>"}`:

| HTTP | Code | Meaning |
| --- | --- | --- |
| 401 | `invalid_service_credentials` | Booking service authentication or transport failed |
| 401 | `invalid_user_session` | The Core session or active user check failed |
| 403 | `platform_authority_required` | The current user has no live platform administrator grant |
| 403 | `module_disabled` | Booking is absent or disabled for the target organization |
| 404 | `organization_not_accessible` | The target organization is missing or archived |
| 422 | `invalid_authorization_request` | The body, UUID, method, fields, or operation are unsupported |
| 503 | `authorization_unavailable` | Core could not safely complete the database decision |

Booking must treat every non-200 response, timeout, transport failure, redirect, malformed body,
or response-context mismatch as denial.

## Audit behavior

Each successful decision atomically writes one persistent `PlatformAudit` row with action
`booking.destructive.authorized`. The actor is the authenticated platform administrator, the
organization and target are the explicitly checked organization, and the only operation metadata
is:

```json
{"operation": "reservation.purge"}
```

Core audits authorization/approval because the later deletion occurs in Booking's database and is
outside Core's transaction boundary. Authentication headers, raw or hashed service credentials,
session tokens, cookies, and other authentication material are not stored in audit metadata.
Booking should separately audit the executed purge in its own persistence layer and retain the
verified Core actor, organization, and operation as execution context.

## Booking consumption requirements

Immediately before a purge, Booking should send the user's opaque Core session and its private
service credential to this endpoint over the configured private transport. It must strictly
validate the exact positive response, confirm all returned identifiers and the operation match the
request, and scope the deletion to the returned organization. The decision is point-in-time and
must not be cached, reused for a different reservation, organization, operation, or actor, or
treated as a general platform capability.
