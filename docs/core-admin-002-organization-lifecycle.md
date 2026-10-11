# CORE-ADMIN-002 organization onboarding and lifecycle

Global platform administrators can create an organization and its protected owner role before the
owner has a Core identity. `POST /platform/organizations` requires `owner_name`, `owner_email`, and
the selected module entitlements. The same transaction creates the organization, owner role and
permissions, entitlement rows, owner invitation, and audit records. A failure rolls back all rows;
a conflicting slug changes nothing.

The invitation is opaque, single-use, expiring, and stored only as a SHA-256 digest. Acceptance at
`POST /auth/invitations/accept` proves mailbox-token possession, creates the global identity and
Argon2id password credential when needed, assigns the owner membership, and consumes the token in
one locked transaction. Resend revokes the prior pending token before issuing a replacement. Revoke
never removes history. Raw tokens are returned only in explicit development/test mode. Production
still requires a confidential outbound email adapter; until one is configured the UI reports
`adapter_required` and hosting must not be called onboarding-ready.

## Platform operations

- `GET /platform/organizations` supports search and opt-in archived results.
- `GET /platform/organizations/{id}` includes owner activation and Booking entitlement status.
- `POST /platform/organizations/{id}/owner-invitation/resend` reissues a pending invite.
- `DELETE /platform/organizations/{id}/owner-invitation/{invitation}` revokes a pending invite.
- `POST /platform/organizations/{id}/archive` blocks tenant access and revokes pending invites.
- `POST /platform/organizations/{id}/restore` restores the organization only; revoked invitations
  stay revoked and must be explicitly reissued.
- `GET /platform/organizations/{id}/audit` returns secret-free platform audit history.

## Exact lifecycle support

| Entity | Tenant administrator | Global super-admin | Permanent deletion |
|---|---|---|---|
| Organization | No archive/restore endpoint | Archive and restore | Not supported; Booking and retention dependencies are cross-service |
| Membership | Explicit permission-gated archive/restore | No platform override added | Not supported |
| Custom role | Explicit permission-gated archive/restore | No platform override added | Not supported |
| Customer | Booking permission-gated archive/restore | Same scoped Booking API | Not supported |
| Reservation | Cancel only through normal permissions | Existing exact purge operation | Supported only by `POST .../purge` |

Reservation purge requires a current platform grant, a session reauthenticated within
`CORE_AUTH_REAUTHENTICATION_SECONDS`, exact `PURGE <reservation UUID>` confirmation, enabled Booking
entitlement, tenant-scoped lookup, and no payment or issued-invoice dependencies. It retains purge
audit evidence and channel tombstones. There is no generic hard-delete or raw-SQL browser endpoint.

## Manual browser check

1. Sign in as the bootstrapped platform administrator and open `/platform`.
2. Create an organization with a new owner email and Booking enabled. Confirm pending status.
3. In an explicit test environment only, obtain the development token from the response and submit
   it to `/auth/invitations/accept` with the matching email and a new 15+ character password.
4. Confirm the owner can sign in, sees only the new organization, and the token cannot be reused.
5. As platform admin, test resend/revoke on a second pending invite, archive/restore, entitlement
   changes, search, and audit history.
6. For a disposable reservation with no payments/invoices, enter its UUID, type the exact purge
   confirmation, and reenter the platform password. Verify a cross-tenant UUID returns not found and
   a reservation with financial records returns conflict.
