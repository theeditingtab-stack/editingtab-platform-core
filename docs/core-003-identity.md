# CORE-003: Internal identity persistence

CORE-003 adds Core-owned organizations, users, and memberships. These remain internal Python services and repositories. This document records the CORE-003 checkpoint, which did not implement authentication. CORE-004 subsequently adds [password authentication](core-004-authentication.md); CORE-005 subsequently adds [organization roles and scoped authorization](core-005-authorization.md). Invitations, Booking, and frontend remain unimplemented.

The resumed workspace contained six partial identity files and the new migration, plus changes to Alembic's environment. They were reviewed and completed in place. No unrelated user changes were present.

## Models and migration

Revision `0002_core_identity` follows the unchanged committed `0001_foundation`. It adds:

| Table | Owned data and database guarantees |
| --- | --- |
| `core_organizations` | UUID id, name, normalized unique slug, created/updated/deleted timestamps; nonblank name and canonical slug checks |
| `core_users` | UUID id, display email, normalized unique email, display name, active flag, timestamps; normalization consistency and nonblank/basic email checks |
| `core_memberships` | UUID id, organization/user foreign keys, timestamps; unique organization/user pair, user lookup index, restrictive foreign keys |

Identifiers are generated with UUID4 by the ORM. Timestamps use PostgreSQL `timestamptz`; created/updated values default to database time. ORM updates advance `updated_at`; raw SQL writers would need to maintain it themselves. No database triggers or automatic startup migration were introduced.

The membership pair's unique index also supports organization-prefixed lookups. Relationships are preserved through soft deletion. There are no cascading hard deletes and no permanent-deletion service.

## Normalization and soft deletion

- Slugs: trim surrounding whitespace, lowercase, then require 1Ã¢â‚¬â€œ63 ASCII letters/digits separated by single hyphens. Names are trimmed, nonblank, at most 200 characters, and contain no control characters.
- Emails: trim surrounding whitespace, retain casing in `email`, and lowercase the entire address in `normalized_email`. Dots and plus-addressing are preserved. Uniqueness is case-insensitive by this platform policy, including the local part.
- This checkpoint accepts printable ASCII addresses with exactly one `@`, nonempty parts, no whitespace, and length at most 254. This is a basic persistence policy, not complete RFC validation or proof of mailbox ownership/deliverability. Internationalized addresses/SMTPUTF8 require a later explicit policy. PostgreSQL's C-collation lowercase check prevents a direct insert with an inconsistent lookup value.
- Organization slugs and normalized user emails remain reserved after archival. Membership pairs remain unique even while archived.
- Normal organization/user reads exclude archived records. An inactive user can still be found internally as an identity, but never counts as an active member.
- Active membership lookup/list results require an unarchived organization, an active unarchived user, and an unarchived membership.
- Archiving an organization marks that organization only, preserves memberships/users, and hides its memberships from active results. It does not deactivate a shared user or change their memberships in other organizations.
- Duplicate addition returns the existing membership UUID. Adding an archived membership restores the same record with its original UUID and creation timestamp. Unavailable parents prevent addition or restoration.
- Repeated archive calls are idempotent. Membership archival can explicitly remove a retained membership even when a parent is archived or inactive. Organization/user restoration and user activation/archive services are outside this checkpoint.

## Internal API and boundaries

`identity/services.py` provides:

| Function | Result |
| --- | --- |
| `create_organization(session, *, name, slug)` | Organization UUID |
| `create_user(session, *, email, display_name)` | User UUID |
| `add_membership(session, *, organization_id, user_id)` | Existing, restored, or newly created membership UUID |
| `get_membership(session, *, organization_id, membership_id)` | Immutable active membership snapshot, or safe not-found error |
| `list_active_memberships(session, *, organization_id)` | Active membership snapshots; empty for missing/archived organizations |
| `archive_organization(session, *, organization_id)` | No return value |
| `archive_membership(session, *, organization_id, membership_id)` | No return value |

Snapshots contain membership/organization/user IDs and created/updated timestamps, with no lazy ORM access outside a transaction.

Every membership lookup, insertion, restoration, or archive query includes explicit organization scope. A membership from another organization is not found or modified. Internal include-archived repository functions are named explicitly and used only by archive/restore services.

**Persistence scoping is not authorization.** Callers are currently trusted internal code. There is no authenticated principal, permission evaluation, entitlement check, platform-admin flag, or PostgreSQL row-level security policy. Membership does not grant administration. Authentication and authorization must be designed and tested before public management endpoints are introduced.

## Transactions and errors

Services require an idle SQLAlchemy Session and own `session.begin()`, commit, and rollback. Repositories flush to enforce real database constraints but never commit or roll back. Passing a session with a caller-owned transaction is rejected without committing or discarding its work; use a fresh session or explicitly complete the caller transaction first.

Membership mutation locks the organization before the user/membership where applicable. This serializes competing service operations against organization archival. Database unique constraints remain the final guard against duplicate slugs, email identities, and membership pairs.

Expected uniqueness errors become `IdentityConflict`; unavailable parents and missing scoped records have separate domain errors. Storage errors expose no SQL, submitted email, or driver detail in their messages, and suppress driver exception chaining in normal formatted output. Failed service transactions leave the session reusable. Do not log raw exception internals or use raw SQL to bypass the service contract.

## Verification design and results

The guarded test configuration still requires explicit `CORE_TEST_DB_*` values, the dedicated database/user, and a local host. Before DDL, fixtures verify the actual connected database and user. Every migration/domain test uses a random schema created inside an outer PostgreSQL transaction and a local search path. No existing public/test/development tables are reset.

Services use real commits/rollbacks through `Session(join_transaction_mode="create_savepoint")`. Tests observe savepoint release/rollback events and verify a flushed row disappears after an injected real uniqueness failure. The outer fixture transaction stays active, rolls back after each case, and verifies that the temporary schema is gone. Migration tests start at the baseline each run, check schema/constraints/timestamp types and the expected head, then repeat the upgrade. No `metadata.create_all` is used.

Local checks:

- `uv sync --locked`: passed, with unchanged dependency configuration and lockfile.
- Ruff lint and format check: passed. Initial import/formatting issues in the partial files were corrected without weakening checks.
- Unit/safety selection: 45 passed, including all existing health/configuration tests.
- Integration helper: 28 passed (23 PostgreSQL tests plus 5 repeated configuration safety tests).
- Baseline Ã¢â€ â€™ `0002_core_identity` Ã¢â€ â€™ repeated head: passed within the isolated test database.
- Git diff whitespace checks and documentation link/path checks passed. The baseline migration, dependency files, CI workflow, health routes, and database lifecycle remain unchanged.
- No development upgrade, downgrade, reset, or deletion was performed.

Coverage includes duplicate memberships, restore-in-place, multi-organization identity, both uniqueness policies after archival, active-result filters, cross-organization reads/writes, restrictive foreign keys, normalization constraints, rollback after partially flushed work, session reuse, and preservation of caller transactions.

CORE-002's local and GitHub Actions success was reported by the user. CORE-003 has not run on GitHub; the unchanged workflow automatically includes these tests after the user's manual push. This checkpoint has not been load-tested or validated under production deployment conditions.

## Changed files

- Completed the six files in `src/editingtab_core/identity`: package marker, models, errors, normalization, repository, and services.
- Completed `migrations/versions/0002_core_identity.py` and `migrations/env.py`.
- Added `tests/unit/test_identity_normalization.py` and `tests/integration/test_identity.py`; updated integration fixtures and `test_postgres.py`.
- Updated README, project brief, implementation plan, decision register, local development guide, dependency verification, and the historical CORE-002 report; added this document.

## PowerShell verification

From the project root, with the existing test PostgreSQL service running:

```powershell
. ./scripts/use-tools.ps1
uv sync --locked
uv run --locked ruff check .
uv run --locked ruff format --check .
uv run --locked pytest -m 'not integration'
./scripts/test-integration.ps1
```

If the test service is stopped, start it with `./scripts/start-db.ps1 -TestDatabase` first. If using a custom test host port, pass that same port with `./scripts/test-integration.ps1 -Port 25433`. The tests do not read the development `.env`. Their schema changes are rolled back, so they do not leave the public test schema at the new head.

After reviewing the migration, the user can explicitly upgrade the development database:

```powershell
. ./scripts/use-tools.ps1
uv run --locked alembic upgrade head
uv run --locked alembic current
```

Expected development head after that manual upgrade: `0002_core_identity (head)`. This command uses development configuration and was deliberately not run by Codex.

Suggested commit message: `feat(core): add organizations users and scoped memberships`.

No commit, push, repository setting change, or next-checkpoint implementation was performed.
CORE-005 lifecycle update: membership archival with role assignments now requires an explicit authorized actor, removes and audits those assignments, and protects the last administrator. Restoration does not restore historical roles. Organization archival remains internal and makes all organization access unavailable. Earlier test counts above are historical checkpoint evidence.
