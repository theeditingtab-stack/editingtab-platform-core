# CORE-AUTH-003 employee lifecycle

## Identity model

Core keeps one global `User` for an account and one `Membership` for each organization in which
that user is an employee/member. A membership is therefore the employee record for an
organization; this checkpoint does not add a second employee table. The existing unique
`(organization_id, user_id)` constraint prevents duplicate relationships, and `deleted_at`
provides reversible membership archival while preserving the membership UUID and audit links.

Roles and role assignments remain organization-scoped. Composite foreign keys require a role,
membership, and assignment to use the same organization. A user may have independent
memberships and roles in multiple organizations.

## HTTP contract

All routes require an authenticated current user and an explicit organization ID. Foreign or
unavailable organization resources return the same non-disclosing `404` response.

| Method and path | Capability | Success behavior |
| --- | --- | --- |
| `GET /organizations/{organization_id}/members` | `core.members.read` | `200`; paginated active and archived memberships. |
| `GET /organizations/{organization_id}/members/{membership_id}` | `core.members.read` | `200`; one active or archived membership, or non-disclosing `404`. |
| `POST /organizations/{organization_id}/members` | `core.members.manage` | `200`; add an existing active Core user, return an existing active membership, or restore its archived membership. |
| `DELETE /organizations/{organization_id}/members/{membership_id}` | `core.members.manage` | `204`; archive an active membership or succeed idempotently if already archived. |
| `POST /organizations/{organization_id}/members/{membership_id}/restore` | `core.members.manage` | `200`; restore or idempotently return the active membership. |

Mutation requests are subject to the existing unsafe-method Origin protection. Add accepts a
global `user_id` plus optional unique `role_ids`; restore accepts optional unique `role_ids`.
There is no email invitation or credential creation path. Invalid request structure returns
`422`; missing capability returns `403`; foreign or unavailable identifiers return `404`; and
last-administrator protection returns `409`.

Member responses contain only `membership_id`, `user_id`, `display_name`, `email`, membership
`state`, and assigned active role summaries. Each role summary uses the existing role contract:
role ID, name, and permission entries containing `code` and `can_grant`. Password hashes,
sessions, service credentials, global active state, platform authority, and internal security
metadata are not exposed.

## Add, archive, and restore semantics

Adding an existing user is idempotent for an active organization/user pair. An archived pair is
restored in place with the same membership UUID. Restoring never revives old assignments; an
archive removes assignments transactionally, and the restore path also fails closed if raw or
historical assignments unexpectedly remain.

Initial roles are part of the same transaction as membership creation or restoration. A request
with roles additionally requires `core.roles.assign`; every role must be active and belong to the
same organization, and the actor must have grant authority for every permission carried by every
role. Any validation, persistence, or audit failure rolls back the membership and all assignments.
Calling add for an already-active member only adds requested missing assignments after the same
checks; it never duplicates either membership or assignment rows.

Archival preserves both `User` and `Membership`, removes active assignments, and takes effect in
authorization immediately. Assignment cleanup retains the CORE-AUTH-002 grant ceiling: when the
member has roles, the actor must also have role-assignment authority and be able to grant those
roles. The organization row lock serializes recovery-sensitive changes. The existing definition
of a recovery-capable administrator—holding all administrator operations and grant authority—is
unchanged, and archival cannot remove the last such administrator.

Tenant administrators manage only memberships and organization role assignments. They cannot
change `User.is_active`, email, password credentials, sessions, platform grants, or any other
global account/security state. Archiving one membership leaves the shared user and memberships
in other organizations active.

## Audit and migration

The existing transactional authorization audit ledger records `member.added`, `member.restored`,
and `member.archived`. For these events, `target_id` is the global user ID and `membership_id` is
the organization relationship. Initial assignment and archive cleanup use the existing
`assignment.added` and `assignment.removed` events, which include the role and permission/grant
state. Audits contain identifiers and authorization state only, never secrets.

No lifecycle table or schema column is needed. Migration `0009_employee_lifecycle` is a
narrow data migration: `core.members.manage` already exists in the `0007` permission registry,
but roles migrated as recovery-capable administrators at `0008` did not receive it. The migration
adds grant-enabled member management only to roles satisfying the existing administrator grant
definition. Its downgrade deliberately preserves later authorization edits because historical
backfilled rows cannot be distinguished safely from intentional assignments.

## Deferred work

Email invitations, pending invitation acceptance, email verification, password reset, account
recovery, MFA, session-management UI, global/platform user administration, employee frontend UI,
domain routing, and organization access-context APIs remain explicitly deferred.
