# CORE-ADMIN-002 Booking management UI integration

## Scope and security boundary

The hosted Booking React/Vite application consumes the existing Core authentication and
administration APIs. Core remains the authority for authentication, organization isolation,
permission checks, delegated grant limits, recovery protections, and platform authority. The UI
may use returned permissions to hide or show controls, but that state is advisory and must never
be stored or submitted as trusted authorization evidence. Every Core request is authorized again
from current server-side state.

This checkpoint adds browser transport support only. It creates no frontend, domain model,
platform-authority grant endpoint, reservation purge operation, or database migration.

## Core base URL and browser requests

The Booking frontend must be configured with the absolute public Core base URL, such as
`http://127.0.0.1:8000` in local development or `https://core.example.com` in production. It must
send requests with Fetch `credentials: "include"`. The base URL must not contain credentials, and
session tokens must never be copied into JavaScript storage or authorization headers.

Core issues the opaque `editingtab_session` cookie as `HttpOnly`, host-only, and `Path=/`. The
browser manages this cookie; frontend code cannot read it. Authentication and administration
responses under `/auth`, `/organizations`, and `/platform` carry `Cache-Control: no-store`.

## Frontend origin configuration and CORS

`CORE_AUTH_ALLOWED_ORIGINS` is a JSON array of exact Booking frontend origins. An origin contains
only scheme, hostname, and optional port, with no path or trailing slash. For example:

```dotenv
CORE_AUTH_ALLOWED_ORIGINS=["http://127.0.0.1:5173"]
```

Core returns credentialed CORS headers only for an exact configured origin. Wildcards, wildcard
subdomains, user information, paths, and non-HTTPS production origins are rejected during
configuration validation. CORS permits the management methods `GET`, `HEAD`, `POST`, `PUT`,
`PATCH`, `DELETE`, and preflight `OPTIONS`, with JSON `Content-Type`. It does not permit or expose
an authorization header because browser authentication uses the opaque cookie.

CORS controls whether browser JavaScript can read a response; it is not authorization and does
not replace CSRF protection. All unsafe Core authentication, organization, and platform methods
still require exactly one `Origin` header whose value exactly matches the same configured list.
Missing, duplicate, `null`, and unconfigured origins fail with `403` before request parsing.

## Development HTTP setup

Set `CORE_ENVIRONMENT=development`, configure the exact Vite origin, and run Core at the base URL
used by the frontend. Explicit development and test modes issue an HTTP-compatible
`SameSite=Lax` cookie without `Secure`.

The frontend and API must use the same hostname in development so they remain same-site; ports
may differ. For example, use `127.0.0.1` for both rather than mixing `localhost` and `127.0.0.1`.
The different ports still require CORS. Browser calls must include credentials:

```javascript
fetch(`${coreBaseUrl}/auth/context`, { credentials: "include" })
```

Unsafe JSON calls also include `Content-Type: application/json`; the browser preflight is handled
by Core. CLI or automated unsafe requests must likewise supply an allowed `Origin`.

## Production HTTPS setup

Production must use HTTPS for both the Booking frontend origin and the Core base URL. Outside
explicit development/test mode, Core issues the session cookie with `Secure`, `HttpOnly`, and
`SameSite=None`, which is the browser-required combination for credentialed requests when the
frontend and API are cross-site. The cookie remains host-only and is sent only to Core.

Prefer frontend and Core hostnames under the same registrable site where deployment architecture
allows it. Browser or enterprise policies may block third-party cookies even when
`SameSite=None`; a same-site deployment avoids relying on third-party-cookie availability. TLS
termination must preserve the public HTTPS origin configured in Core.

## Management UI API surface

The frontend establishes its current state with:

- `GET /auth/context`

It then consumes these organization-scoped endpoints:

- `GET /organizations`
- `GET /organizations/{org}`
- `GET /organizations/{org}/members`
- `GET /organizations/{org}/members/{membership}`
- `GET /organizations/{org}/members/{membership}/access`
- `POST /organizations/{org}/members`
- `DELETE /organizations/{org}/members/{membership}`
- `POST /organizations/{org}/members/{membership}/restore`
- `POST /organizations/{org}/invitations`
- `GET /organizations/{org}/invitations`
- `DELETE /organizations/{org}/invitations/{invitation}`
- `GET /organizations/{org}/permissions`
- `GET /organizations/{org}/roles`
- `GET /organizations/{org}/roles/archived`
- `GET /organizations/{org}/roles/{role}`
- `POST /organizations/{org}/roles`
- `PATCH /organizations/{org}/roles/{role}`
- `DELETE /organizations/{org}/roles/{role}`
- `POST /organizations/{org}/roles/{role}/restore`
- `PUT /organizations/{org}/roles/{role}/permissions/{code}`
- `DELETE /organizations/{org}/roles/{role}/permissions/{code}`
- `PUT /organizations/{org}/members/{membership}/roles/{role}`
- `DELETE /organizations/{org}/members/{membership}/roles/{role}`

`effective_permissions` answers what the current identity may do. `effective_grant_authority`
answers which permissions that identity may delegate. The frontend must keep these concepts
separate. Core checks both independently, prevents grants beyond `can_grant`, keeps platform
authority separate, and returns no effective access for disabled or archived identities.

Responses can legitimately change between rendering and mutation. The frontend must handle
Core's current `401`, `403`, `404`, and `409` responses and refresh `/auth/context` plus relevant
resource data after access changes. A hidden button, cached context, organization identifier, or
client-side role calculation never overrides backend enforcement.
