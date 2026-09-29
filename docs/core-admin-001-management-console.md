# CORE-ADMIN-001 administration management console API

## Architecture reused

This checkpoint exposes the existing Core identity, authentication, authorization, onboarding,
and platform services for an administration UI. It creates no second user, employee, membership,
role, permission, session, or platform-authority model. A Core `User` is global, a `Membership` is
that user's organization employee record, `Role` and `MembershipRole` are organization-scoped,
and `PermissionDefinition` remains the only organization-assignable permission registry.

HTTP handlers authenticate the existing opaque session cookie and pass the current user ID into
service methods. Authorization, organization scoping, delegated-grant checks, last-administrator
checks, locking, writes, and audit creation remain in the service layer. UI visibility is only a
convenience; it is never authorization evidence.

## Organization management API

All list routes accept `limit` (1–100, default 50) and `offset` (0–100000, default 0) where
shown. All unsafe methods require the configured exact `Origin`. Responses use explicit Pydantic
models, reject unknown request fields, and never include password hashes, credential records,
session tokens, invitation digests, or platform-grant rows.

| Method and path | Required authority | Purpose |
| --- | --- | --- |
| `GET /organizations` | Active session | List the caller's active organizations; paginated. |
| `GET /organizations/{org}` | `core.organization.read` | Read organization metadata. |
| `GET /organizations/{org}/members` | `core.members.read` | List active and archived employee memberships; paginated. |
| `GET /organizations/{org}/members/{membership}` | `core.members.read` | Inspect employee identity, state, and active role assignments. |
| `GET /organizations/{org}/members/{membership}/access` | `core.members.read` | Read current effective permissions and delegated grant authority. |
| `POST /organizations/{org}/members` | `core.members.manage` | Link an existing active Core user by ID, optionally with allowed roles. |
| `DELETE /organizations/{org}/members/{membership}` | `core.members.manage` | Archive access and remove role assignments. |
| `POST /organizations/{org}/members/{membership}/restore` | `core.members.manage` | Restore access without reviving historical assignments; optional fresh roles. |
| `POST /organizations/{org}/invitations` | `core.members.manage` | Invite by email with optional allowed initial roles. |
| `GET /organizations/{org}/invitations` | `core.members.manage` | List invitation lifecycle metadata; paginated and token-free. |
| `DELETE /organizations/{org}/invitations/{invitation}` | `core.members.manage` | Revoke a pending same-organization invitation. |
| `GET /organizations/{org}/permissions` | `core.roles.read` | List active organization-assignable registry entries. |
| `GET /organizations/{org}/roles` | `core.roles.read` | List active roles and their permission/grant entries; paginated. |
| `GET /organizations/{org}/roles/archived` | `core.roles.read` | List archived roles available for inspection or restoration; paginated. |
| `GET /organizations/{org}/roles/{role}` | `core.roles.read` | Inspect active or archived role state and system-managed status. |
| `POST /organizations/{org}/roles` | `core.roles.create` | Create a custom role within the actor's grant ceiling. |
| `PATCH /organizations/{org}/roles/{role}` | `core.roles.update` | Rename a custom role without replacing permissions. |
| `PUT /organizations/{org}/roles/{role}` | `core.roles.update` | Compatibility operation replacing custom-role metadata and permissions atomically. |
| `DELETE /organizations/{org}/roles/{role}` | `core.roles.archive` | Archive a custom role and remove its assignments. |
| `POST /organizations/{org}/roles/{role}/restore` | `core.roles.archive` | Restore a custom role without restoring assignments. |
| `PUT /organizations/{org}/roles/{role}/permissions/{code}` | `core.roles.update` | Grant/update one permission; body is `{"can_grant": boolean}`. |
| `DELETE /organizations/{org}/roles/{role}/permissions/{code}` | `core.roles.update` | Revoke one permission. |
| `PUT /organizations/{org}/members/{membership}/roles/{role}` | `core.roles.assign` | Assign an allowed active role idempotently. |
| `DELETE /organizations/{org}/members/{membership}/roles/{role}` | `core.roles.assign` | Revoke an allowed assignment. |

Invitation acceptance remains `POST /auth/invitations/accept` and reuses the existing global
identity and credential lifecycle. Production invitation creation does not serialize the raw
token; a delivery adapter must receive it transiently from the service boundary. Development and
test responses expose it once as `development_token` until that adapter exists. Invitation list
responses never expose either raw tokens or digests.

## Authorization and security boundaries

Every tenant service first establishes an active organization, active actor membership, and the
exact required permission. Target roles and memberships are selected with the same organization
ID; composite foreign keys provide an additional database boundary. A foreign or unavailable
target uses the non-disclosing `404` contract. Disabled users, archived users, archived
memberships, archived organizations, and archived roles contribute no effective access.

Using a permission and granting it remain separate. Role creation, permission changes, role
assignment, invitation role intent, archival, and restoration require every affected permission
code to be inside the actor's current `can_grant` union. Bulk role updates check both the old and
new state. A client administrator therefore cannot add a permission they cannot delegate, cannot
turn a held-but-nondelegable permission into grant authority, and cannot mint platform authority:
platform permissions are absent from the organization-assignable registry and rejected by both
the service and database constraints.

The bootstrap `Organization owner` role and roles carrying the existing Booking provisioning
marker are system-managed. Tenant role metadata, permission, archive, and restore operations
reject them. Assignments still require the existing role-assignment permission and complete
grant ceiling; Booking's designated administrator role continues to be provisioned only through
the separately platform-authorized operation. Recovery-sensitive mutations lock the organization
row, and no operation may remove the last active recovery-capable administrator.

Archiving a membership or custom role removes its assignments in the same transaction. Restoring
either resource never revives previous assignments, including dormant assignments left by older
data. Permission and assignment updates take effect on the next request because sessions contain
no cached authorization claims.

## Platform administration boundary

The platform console uses separate `PlatformAdminGrant` authority. Tenant roles never imply it,
and platform authority alone never grants tenant API access. The existing platform surface is:

| Method and path | Purpose |
| --- | --- |
| `GET /platform/organizations` | Paginated active organization list. |
| `GET /platform/organizations/{org}` | Organization detail plus current supported modules. |
| `POST /platform/organizations` | Atomically onboard an organization and owner. |
| `GET /platform/organizations/{org}/modules` | Read entitlements. |
| `PUT /platform/organizations/{org}/modules/{module}` | Change a supported entitlement. |
| `POST /platform/organizations/{org}/booking-inventory-administrator` | Provision the protected Booking administrator role. |

Initial platform bootstrap remains an operator-only CLI action. This checkpoint deliberately
does not add HTTP grant/revocation of platform-super-admin authority, organization hard deletion,
or reservation permanent purge.

## Frontend integration

The future admin frontend should begin with `GET /auth/context`, select an organization returned
there, and use effective permissions only to shape navigation and controls. It should fetch role
and employee detail after selection, use the permission registry for labels, and keep
`effective_grant_authority` separate when deciding which permission or role options to present.
The backend must still be allowed to return `403`, `404`, or `409` after any stale UI snapshot.

Use invitation creation for a new email identity; use direct member linking only when the UI was
given an existing Core user ID by a trusted workflow. Do not create passwords in an organization
admin form. After an archive or permission change, refresh member access and `/auth/context`.

No frontend architecture exists in this repository, so no frontend was added. The remaining
production UI dependency is an outbound invitation-delivery adapter; platform-admin lifecycle
and destructive Booking retention workflows are separate checkpoints.

## Persistence and compatibility

No migration is required. The API uses migrations `0004` through `0011` as implemented. Existing
bulk role update and member-link routes remain available, existing error meanings are preserved,
and the new focused routes provide safer UI operations without replacing the underlying domain
model.
