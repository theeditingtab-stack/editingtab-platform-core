# CORE-AUTH-005 authenticated organization access context

## HTTP response

`GET /auth/context` requires the existing active Core session cookie. It returns a stable,
read-only snapshot assembled from current Core database state:

```json
{
  "user": {
    "user_id": "uuid",
    "email": "user@example.test",
    "display_name": "User"
  },
  "is_platform_admin": false,
  "organizations": [
    {
      "organization_id": "uuid",
      "name": "Organization",
      "slug": "organization",
      "membership_id": "uuid",
      "roles": [{"role_id": "uuid", "role_name": "Reader"}],
      "effective_permissions": ["core.organization.read"],
      "effective_grant_authority": [],
      "enabled_modules": ["booking"]
    }
  ]
}
```

Organizations are ordered by public slug and ID; roles by name and ID; permissions, grant
authority, and modules lexically. Only active memberships in active organizations are returned.
Only active assigned roles contribute. User inactivity/deletion, session expiry/revocation,
membership archival, organization archival, role archival, permission changes, grant-authority
changes, and entitlement changes are read on the next request. There are no permission claims in
the session and no wildcard expansion.

The identity fields are deliberately limited to user ID, email, and display name. The response
does not contain credentials, password hashes, session values/digests, security metadata, service
credentials, platform grant records, or data from another organization. `Cache-Control: no-store`
is present on success and error responses; this endpoint creates no shared or application cache.

## Organization selection and authorization

The frontend may present the returned organizations and retain a selected `organization_id` as
navigation/request context. Selection does not create authority and is not a trusted server-side
grant. Every protected operation must authenticate the current session and independently verify
the selected organization, active membership, required current permission, and, where relevant,
current entitlement. Backend authorization remains authoritative; the frontend should use the
context only to shape navigation and explain available actions.

Role names are descriptive. Frontends should use the flattened effective permission list for
display decisions rather than infer capability from a role name. Effective grant authority is a
separate list because holding a permission does not necessarily permit delegating it. Neither
list supplied back by a client is authorization evidence.

Enabled modules come from Core's existing entitlement records. Only currently enabled,
implemented modules are included; at this checkpoint that means `booking`. No POS, Unified Inbox,
or Chatbot capability is implied by catalog entries that cannot yet be enabled.

## Platform separation

`is_platform_admin` reports only whether the active user currently has an unrevoked platform
administrator grant. It does not expose grant rows or translate platform authority into tenant
roles, permissions, memberships, or organization visibility. A platform administrator without an
explicit active membership receives an empty organization list and must use separately authorized
platform APIs for platform work.

## Booking authorization handoff

The intended runtime flow remains:

1. Core authenticates the user with its revocable server-side session.
2. The frontend retrieves `/auth/context` and selects one returned organization ID.
3. For a protected Booking operation, Booking receives Core session proof and the selected
   organization ID.
4. Booking calls Core's versioned authorization endpoint with its service credential, the Core
   session proof, the selected organization ID, and the exact required permission.
5. Core validates the current session, active membership and organization, exact permission, and
   Booking entitlement for that operation.

Booking must not trust role names, effective-permission lists, grant-authority lists, module lists,
or an organization ID sent by the frontend. It must not read Core tables. CORE-AUTH-006 implements
this authoritative Core-side decision at `POST /internal/v1/booking/authorize`; Booking repository
integration remains a later checkpoint.

## Scope and persistence

This checkpoint adds a read-only response model and queries existing identity, authorization,
platform-grant, and entitlement records. It needs no migration, dependency, cache service, active
organization table, context token, frontend, domain routing, MFA, recovery mechanism, or Booking
change.
