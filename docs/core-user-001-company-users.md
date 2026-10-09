# CORE-USER-001 company users and platform bootstrap

## Company user boundary

Core remains the only owner of identities, credentials, sessions, memberships, roles, and platform
grants. Booking Administration calls Core over its public API and never reads Core tables. Every
company operation takes an organization ID from the route and re-authorizes the authenticated user
against that organization in the service layer. A foreign membership, role, or invitation remains a
non-disclosing `404`; an authenticated same-organization user without the required permission gets
`403`.

Memberships now have three states. `active` grants the roles currently assigned to the membership;
`inactive` preserves those assignments but removes the organization from access context and all
effective permission queries; `archived` is the existing reversible soft deletion and removes role
assignments. Restore intentionally does not revive historical roles. Deactivation and archival both
enforce the last-administrator invariant under the organization lock.

The company employee display name is stored on the membership. Editing it does not alter the global
identity or the name shown in another organization. Email and global account activity remain Core
identity/security properties and are not mutable by a tenant administrator. No company endpoint can
read or write credentials, password hashes, sessions, reset-token digests, or platform grants.

| Route | Required authority | Behavior |
| --- | --- | --- |
| `PATCH /organizations/{organization_id}/members/{membership_id}` | `core.members.manage` | Updates the company-specific display name. |
| `PUT /organizations/{organization_id}/members/{membership_id}/activation` | `core.members.manage` | Accepts `{ "active": true|false }`; preserves roles and protects the last administrator. |

Existing list, invitation, role assignment/revocation, archive, and restore routes retain their
documented authorization. Invitation acceptance and password reset use random one-time tokens whose
SHA-256 digests are stored. Passwords use Argon2id and never appear in response models. Explicit
development/test mode may return a one-time `development_token`; production never does. Production
still needs a confidential outbound email delivery adapter supplied by deployment infrastructure;
without one, an administrator can create the pending invitation but Core does not claim it was sent.

## Initial platform administrator

The designated address is fixed as `editingtab.dev@gmail.com`. Platform authority is a
`PlatformAdminGrant`, not an organization membership or role. The bootstrap command is never called
by application startup, migrations, or HTTP.

On a fresh database, first apply reviewed migrations, then run the interactive command in a protected
operator shell:

```powershell
. ./scripts/use-tools.ps1
uv run --locked alembic upgrade head
uv run --locked python -m editingtab_core.platform.bootstrap
```

The command requires exact confirmation and reads the initial password twice with hidden terminal
input. It accepts no password argument and logs no password. The transaction creates the designated
identity and credential when absent, creates the independent platform grant, writes the permanent
bootstrap marker, and appends a platform audit row. It creates no organization or membership.

Re-running bootstrap is idempotent only when the completed marker, active designated identity, and
active grant agree. It returns the existing grant without hashing, comparing, changing, or resetting
the supplied password. A disabled/archived account, revoked/missing grant, missing marker, or
conflicting historical grant fails closed. Startup never recreates or repairs any of these states.

For production, run the same command through the deployment platform's protected one-time operator
session after migrations. Enter a password sourced from the approved secret manager directly into
the hidden prompt; do not place it in command arguments, manifests, shell history, tickets, or logs.
Restrict shell and database credentials to recovery operators and retain the command audit trail.

## Controlled recovery

Lost administrator access is recovered only through this explicit operator command:

```powershell
. ./scripts/use-tools.ps1
uv run --locked python -m editingtab_core.platform.recover
```

It requires a different exact confirmation, hidden password entry and an already bootstrapped,
active, unarchived designated identity. It resets that credential, revokes every existing session,
restores or recreates only that identity's platform grant, and records both platform and security
audit entries. It will not silently reactivate or recreate a disabled/deleted identity.

Tenant owners and administrators have no route or permission code that creates, assigns, restores,
or revokes platform authority. The permission registry accepts organization-assignable definitions
only, so a role cannot encode platform-super-admin authority.
