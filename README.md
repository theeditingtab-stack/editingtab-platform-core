# The Editing Tab

The Editing Tab is a modular business platform for hotels, safari operators, and related businesses. Initial delivery covers Platform Core and Booking; future modules include POS, Unified Inbox, and Chatbot. Initial scope excludes payment gateway integration.

CORE-002 provides configuration, health endpoints, PostgreSQL connectivity, migrations, tests, Ruff, and CI. CORE-003 adds internal organization, user, and membership persistence with explicit organization scoping and soft deletion. CORE-004 adds Argon2id password authentication, revocable cookie sessions, Origin checks, and shared login throttling. CORE-005 adds organization roles, enforced permissions, scoped administration endpoints, and transactional role audit. CORE-006 adds separate platform authority, atomic existing-user onboarding, and server-side module entitlements. Booking, frontend, domains, recovery, and integrations remain future work. This is not a production-ready platform.

## Documents

- [AGENTS.md](AGENTS.md): instructions and security boundaries for future checkpoints.
- [Project brief](docs/project-brief.md): scope and requirements, including future work.
- [Implementation plan](docs/implementation-plan.md): checkpoint sequence and acceptance criteria.
- [Decisions and open questions](docs/decisions-and-open-questions.md): accepted foundation decisions and outstanding product/architecture choices.
- [Local development](docs/local-development.md): exact Windows PowerShell setup, database, migration, API, test, and shutdown commands.
- [Dependency verification](docs/dependency-verification.md): selected versions, compatibility evidence, and official references.
- [CORE-002 verification](docs/core-002-verification.md): historical foundation checks.
- [CORE-003 identity](docs/core-003-identity.md): implemented models, policies, transaction boundaries, tests, and manual verification.

- [CORE-004 authentication](docs/core-004-authentication.md): password/session design, CSRF and throttling policy, local provisioning, and PowerShell verification.

- [CORE-005 authorization](docs/core-005-authorization.md): permission policy, protected API, last-admin safeguards, bootstrap, tests, and manual verification.

- [CORE-006 platform administration](docs/core-006-platform.md): authority, onboarding, entitlements, tests, and the numbered manual walkthrough.

## Structure and ownership

`src/editingtab_core` contains application configuration, lifecycle, database session support, and health routes. `identity` contains Core-owned models, explicit repositories, and transaction-owning services. `auth` owns credentials, sessions, and login throttles. `migrations` retains the earlier revisions and adds `0005_platform_onboarding`; migrations are never applied at application startup. `tests/unit` contains mocked/configuration tests; `tests/integration` contains real PostgreSQL tests and database safety checks. `scripts` contains small local helpers.

Core owns shared identity, organization authorization, and platform administration. Booking will own inventory and reservations. The initial backend is a modular application, not separate services. Future module interfaces must preserve ownership and prevent access to private tables; no empty domain layers or speculative tables have been added.

## Workflow

Codex implementation -> user review -> local checks -> manual commit and push -> GitHub Actions verification.

Codex stops after each assigned checkpoint with evidence of checks actually run. The user reviews, tests, commits, and pushes manually. The user reports that CORE-002 and committed CORE-003 passed verification. CORE-004 is verified at `aedfa62`. CORE-005 is user-verified at `586b66b`, including GitHub Actions. CORE-006 awaits manual review, commit, push, and remote CI. Repository visibility is handled by the user and does not block implementation.

Company: The Editing Tab

GitHub owner: `theeditingtab-stack`

Git author: `The Editing Tab <the.editing.tab@gmail.com>`

Core and Booking have a two-week planning target, not a guaranteed completion date. OTA access, offline confirmation policy, deployment, and recovery decisions remain visible in the project documents.
