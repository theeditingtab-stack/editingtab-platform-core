# CORE-AUTH-001: Permission registry and vocabulary

CORE-AUTH-001 replaces the enumerated `core_role_permissions.code` CHECK constraint with a
Core-owned permission definition registry. It does not implement CORE-AUTH-002 granular
role-operation enforcement or `can_grant`, and it grants no new permission automatically.

## Registry and database integrity

`core_permission_definitions` stores the globally unique permission code, owning module,
human-readable description, organization-assignable flag, and lifecycle (`active` or
`deprecated`). Codes follow `<module>.<resource>.<action>` and use `read` rather than a parallel
`view` verb. There are no wildcard definitions.

`core_role_permissions` keeps its organization/role ownership foreign key and now references the
definition's code, assignability, and lifecycle through a composite foreign key. Fixed CHECKs on
the role-permission row require `organization_assignable = true` and `lifecycle = 'active'`.
Consequently, unknown, deprecated, and non-organization-assignable definitions are rejected by
PostgreSQL as well as by the service layer. A referenced definition cannot be made deprecated or
non-assignable until its role assignments have been deliberately migrated or removed.

Migration `0007_permission_registry` creates and seeds the registry before replacing the old
CHECK, preserving every existing role, assignment, and permission row. Downgrade first recreates
the six-code legacy CHECK, so it fails safely if a later code has been assigned rather than
deleting authorization data.

## Final organization permission vocabulary

| Module | Permission | Meaning |
| --- | --- | --- |
| Core | `core.organization.read` | Read organization details |
| Core | `core.members.read` | Read members/employees |
| Core | `core.members.manage` | Manage members/employees |
| Core | `core.roles.read` | Read roles and permission definitions |
| Core | `core.roles.create` | Create roles |
| Core | `core.roles.update` | Update roles |
| Core | `core.roles.archive` | Archive roles |
| Core | `core.roles.assign` | Assign and remove roles |
| Core | `core.roles.manage` | Compatibility authority for existing role operations |
| Booking | `booking.inventory.read` | Read inventory |
| Booking | `booking.inventory.manage` | Manage inventory |
| Booking | `booking.reservations.read` | Read reservations |
| Booking | `booking.reservations.create` | Create reservations |
| Booking | `booking.reservations.update` | Update reservations |
| Booking | `booking.reservations.cancel` | Cancel reservations |
| Booking | `booking.availability.read` | Read availability |
| Booking | `booking.safari.read` | Read safari definitions |
| Booking | `booking.safari.manage` | Manage safari definitions |
| Booking | `booking.settings.read` | Read Booking settings |
| Booking | `booking.settings.manage` | Manage Booking settings |

The existing `Organization owner` bootstrap role retains its original four Core permissions.
`core.roles.manage` remains the enforced compatibility capability for all current role operations,
so existing administrators lose no authority. The granular role codes are registered for
CORE-AUTH-002 but are not enforced or automatically granted here. The existing explicit Booking
inventory provisioner still grants only `booking.inventory.read` and
`booking.inventory.manage`.

## Catalog and authorization behavior

`GET /organizations/{organization_id}/permissions` requires an authenticated Core session, an
active membership in that organization, and `core.roles.read`. It returns only active,
organization-assignable definitions with `code`, `module`, `description`, and `lifecycle`, ordered
by module and code. It has no platform-authority representation and accepts no browser-supplied
permission decision.

Role create/update validation now queries the registry inside the service transaction. Existing
grant ceilings still require the acting administrator to hold every permission being granted.
Effective permissions remain a live union of active same-organization role assignments, with all
existing user, membership, organization, and role lifecycle filters. Deny-by-default behavior,
tenant isolation, last-administrator protection, and platform/tenant separation are unchanged.

The versioned Booking authorization endpoint recognizes all approved `booking.*` codes above and
still rejects Core, platform, wildcard, and unknown codes. It continues to return a decision for
one requested operation only; it never returns a broad permission set, authenticates users, or
reads Booking-owned data.

Future modules add permissions through a reviewed Core migration that inserts complete
definitions and accompanying service/contract tests. Adding a row does not grant it to any role,
enable a module entitlement, or authorize a feature. POS, Inbox, and Chatbot definitions are not
registered by this checkpoint.

Platform administrator grants remain in `core_platform_admin_grants`. They are not permission
definitions, cannot be assigned to organization roles, and never substitute for tenant membership
or an organization permission.
