# CORE-AUTH-002: Delegated grant authority

CORE-AUTH-002 separates what an organization member may use from what the member may
delegate. Effective permissions are the union of permission codes on all current active roles;
effective grant authority is the union of rows whose `can_grant` value is `true`. Both sets are
calculated from current server-side organization, membership, user, role, assignment, and
permission state. Client-provided effective sets are never trusted.

## Permission and delegation semantics

Each `core_role_permissions` row has a non-null `can_grant` boolean. The row always grants use of
its permission. `can_grant=false` grants use only. `can_grant=true` grants use and permits the
member to place that permission, with either grant state, in a role when the member also has the
required role-operation capability. There is no wildcard, and holding a permission without grant
authority cannot bootstrap delegation.

Create requires `core.roles.create`, update requires `core.roles.update`, archive requires
`core.roles.archive`, and assignment or unassignment requires `core.roles.assign`. Read and list
continue to require `core.roles.read`. `core.roles.manage` remains registered only for migrated
compatibility data and is not consulted by role-operation enforcement.

Every requested permission must be active and organization-assignable and must be in the actor's
effective grant authority. Update validates the complete old and new role states; archive,
assignment, unassignment, and membership-archive cleanup validate the complete target role. This
prevents a narrow administrator from weakening, seizing, renaming, archiving, assigning, or
removing a stronger role. Organization locks serialize privilege-affecting mutations, and foreign
roles or memberships remain non-disclosing.

## Migration and bootstrap policy

Migration `0008_delegated_grant_authority` adds `can_grant` with a safe default of `false`. For
each historical role containing `core.roles.manage`, it adds the four granular role-operation
permissions and marks every permission on that explicit administrator role, including the new
operations, as delegable. It does not mark unrelated roles as delegators. This preserves the
standard historical owner role and its ceiling without globally upgrading all permissions.

Fresh owner roles receive organization/member/role read plus the four granular operations, all
with `can_grant=true`; they do not receive unrelated Booking permissions. A populated downgrade is
refused because revision 0007 cannot represent grant metadata without silently changing security
semantics. An empty schema can downgrade to 0007 and re-upgrade.

The platform Booking provisioner still creates only the dedicated inventory read/manage role and
sets both rows to `can_grant=false`. Platform provisioning can assign that role but does not give
the organization member grant authority. An inventory administrator can therefore use the
permissions but cannot manufacture another Booking role through tenant role APIs.

## API and audit contract

Role create and full-replacement update accept unique permission objects:

```json
{
  "name": "Booking Checker",
  "permissions": [
    {"code": "booking.reservations.read", "can_grant": false},
    {"code": "booking.availability.read", "can_grant": false}
  ]
}
```

Role list/create/update responses use the same permission-object shape. Duplicate codes, unknown
codes, deprecated definitions, non-assignable definitions, extra fields, and malformed entries are
rejected. Audit before/after values now contain permission objects, so a change to `can_grant` is
visible even when permission codes do not change. Role, assignment, and audit changes remain in one
transaction.

A Booking Supervisor can combine reservation read/update with selectively enabled delegation, but
only where its creator already has that grant authority. Job titles are labels only and have no
authorization meaning. A future role editor should show use and delegation separately, prevent
duplicate codes, submit the full role state on update, and treat server denials as authoritative.

The last-administrator invariant now requires at least one active member to hold and be able to
delegate role read/create/update/archive/assign. It is checked after prospective changes while the
organization row is locked, preserving concurrent last-administrator protection and ensuring an
administrator can reconstruct and assign recovery roles.
