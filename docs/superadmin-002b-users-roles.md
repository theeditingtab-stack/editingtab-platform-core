# SUPERADMIN-002B users, owners, roles, and permissions

## Capability matrix

| Area | Status | Reused implementation / checkpoint result |
| --- | --- | --- |
| Global administrator authority | Reused | `core_platform_admin_grants`; every platform service rechecks the active user and unrevoked grant through `_require_platform`. |
| User identities and authentication | Reused | `core_users`, `core_password_credentials`, and revocable `core_login_sessions`. Platform responses never select or serialize password hashes, token digests, or session material. |
| Organization membership lifecycle | Extended | `core_memberships`, membership role assignments, last-administrator evaluation, and existing member/role audits are reused. Platform archive/restore is transactional, audited, preserves the row, and does not restore historical roles. |
| Owner onboarding | Reused and exposed | Existing single-use `core_organization_invitations` with `organization_owner` kind, expiry/revocation/acceptance rules, and owner activation are unchanged. The new view distinguishes no recorded invitation from pending, accepted, expired, and revoked invitations and separately reports an active owner membership. |
| Roles and permissions | Reused and exposed read-only | `core_roles`, `core_role_permissions`, `core_permission_definitions`, `core_membership_roles`, entitlement-aware effective permission evaluation, system-role classification, and tenant grant-authority policies remain authoritative. |
| Platform audit | Reused and extended | `core_platform_audit` records platform membership archive/restore; existing `core_member_audit` and `core_role_audit` continue to record tenant-scoped membership and assignment effects. |
| Global user hard deletion or account suspension | Deferred | Hard deletion remains prohibited. Core has active/inactive and archive states, but this checkpoint does not invent a separate suspension lifecycle. |
| Global role create/edit/assign | Deferred | Existing mutations are intentionally tenant-authority operations. A global-admin bypass would weaken grant authority, self-escalation, and system-role policy, so platform role administration is inspection-only in this checkpoint. |
| Platform administrator grant lifecycle | Deferred | Bootstrap and controlled recovery remain operator-only. No HTTP operation can grant or revoke platform administration. |

## Platform API

- `GET /platform/users` — bounded (`1..100`) offset pagination, stable email/UUID ordering, and name/email search.
- `GET /platform/users/{user_id}` — safe identity status, activation state, cross-organization memberships, assigned roles, effective permissions for active access, and invitation states.
- `GET /platform/owner-onboarding` — organization owner relationship and initial-owner invitation status, including `unrecorded`.
- `POST /platform/organizations/{organization_id}/members/{membership_id}/archive` — soft revocation with role removal, last-owner/administrator protection, and audit records.
- `POST /platform/organizations/{organization_id}/members/{membership_id}/restore` — restores an eligible identity without reviving historical roles and writes audit records.
- `GET /platform/roles` — stable global or organization-filtered role inspection with scope, system/custom classification, permissions, and assignment count.
- `GET /platform/permissions` — permission registry inspection including lifecycle and organization-assignability.

All operations require a current authenticated platform administrator. Tenant administrators receive `403`; cross-organization identifiers are never accepted as authorization evidence. Unsafe operations also retain the existing Origin guard. No migration is required because the checkpoint reuses the current schema at `0015_platform_owner_lifecycle`.

## Deployment ordering

Deploy the Core API before enabling the Booking routes that consume these endpoints. No database migration or development-database upgrade is required. Existing organization, authentication, Booking authorization, invitation, and audit contracts remain unchanged.
