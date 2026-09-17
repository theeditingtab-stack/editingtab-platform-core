# The Editing Tab

The Editing Tab is a modular business platform for hotels, safari operators, and related businesses. Initial delivery covers Platform Core and Booking; future modules include POS, Unified Inbox, and Chatbot. Initial scope excludes payment gateway integration.

CORE-002 provides configuration, health endpoints, PostgreSQL connectivity, migrations, tests, Ruff, and CI. CORE-003 adds internal organization, user, and membership persistence with explicit organization scoping and soft deletion. Authentication, authorization, public management endpoints, Booking, frontend, and integrations remain future work. This is not a production-ready platform.

## Documents

- [AGENTS.md](AGENTS.md): instructions and security boundaries for future checkpoints.
- [Project brief](docs/project-brief.md): scope and requirements, including future work.
- [Implementation plan](docs/implementation-plan.md): checkpoint sequence and acceptance criteria.
- [Decisions and open questions](docs/decisions-and-open-questions.md): accepted foundation decisions and outstanding product/architecture choices.
- [Local development](docs/local-development.md): exact Windows PowerShell setup, database, migration, API, test, and shutdown commands.
- [Dependency verification](docs/dependency-verification.md): selected versions, compatibility evidence, and official references.
- [CORE-002 verification](docs/core-002-verification.md): historical foundation checks.
- [CORE-003 identity](docs/core-003-identity.md): implemented models, policies, transaction boundaries, tests, and manual verification.

## Structure and ownership

`src/editingtab_core` contains application configuration, lifecycle, database session support, and health routes. `identity` contains Core-owned models, explicit repositories, and transaction-owning services. `migrations` retains the empty baseline and adds `0002_core_identity`; migrations are never applied at application startup. `tests/unit` contains mocked/configuration tests; `tests/integration` contains real PostgreSQL tests and database safety checks. `scripts` contains small local helpers.

Core owns shared identity persistence and will provide platform administration. Booking will own inventory and reservations. The initial backend is a modular application, not separate services. Future module interfaces must preserve ownership and prevent access to private tables; no empty domain layers or speculative tables have been added.

## Workflow

Codex implementation → user review → local checks → manual commit and push → GitHub Actions verification.

Codex stops after each assigned checkpoint with evidence of checks actually run. The user reviews, tests, commits, and pushes manually. The user reports that CORE-002 passed GitHub Actions. CORE-003 is locally verified; its remote workflow has not run yet. Repository visibility is handled by the user and does not block implementation.

Company: The Editing Tab

GitHub owner: `theeditingtab-stack`

Git author: `The Editing Tab <the.editing.tab@gmail.com>`

Core and Booking have a two-week planning target, not a guaranteed completion date. OTA access, offline confirmation policy, deployment, and recovery decisions remain visible in the project documents.