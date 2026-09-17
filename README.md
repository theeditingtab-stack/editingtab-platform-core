# The Editing Tab

The Editing Tab is a modular business platform for hotels, safari operators, and related businesses. Initial delivery covers Platform Core and Booking; future modules include POS, Unified Inbox, and Chatbot. Initial scope excludes payment gateway integration.

CORE-002 implements the backend foundation: configuration, FastAPI health endpoints, synchronous PostgreSQL connectivity and sessions, Alembic baseline, tests, Ruff, and a CI workflow. There are no identity, organization, permission, Booking, frontend, or integration features yet. This is not a production-ready platform.

## Documents

- [AGENTS.md](AGENTS.md): instructions and security boundaries for future checkpoints.
- [Project brief](docs/project-brief.md): scope and requirements, including future work.
- [Implementation plan](docs/implementation-plan.md): checkpoint sequence and acceptance criteria.
- [Decisions and open questions](docs/decisions-and-open-questions.md): accepted foundation decisions and outstanding product/architecture choices.
- [Local development](docs/local-development.md): exact Windows PowerShell setup, database, migration, API, test, and shutdown commands.
- [Dependency verification](docs/dependency-verification.md): selected versions, compatibility evidence, and official references.
- [CORE-002 verification](docs/core-002-verification.md): executed checks, resources, and limitations.

## Structure and ownership

`src/editingtab_core` contains application configuration, lifecycle, database session support, and health routes. `migrations` contains the empty foundation baseline; it creates only Alembic revision bookkeeping. `tests/unit` contains mocked/configuration tests; `tests/integration` contains real PostgreSQL tests and database safety checks. `scripts` contains small local helpers.

Core will own shared identity and platform administration. Booking will own inventory and reservations. The initial backend is a modular application, not separate services. Future module interfaces must preserve ownership and prevent access to private tables; no empty domain layers or speculative tables have been added.

## Workflow

Codex implementation → user review → local checks → manual commit and push → GitHub Actions verification.

Codex stops after each assigned checkpoint with evidence of checks actually run. The user reviews, tests, commits, and pushes manually. The CI workflow is prepared but has not run on GitHub. Remote repository status remains unconfirmed; do not assume an old repository was deleted.

Company: The Editing Tab

GitHub owner: `theeditingtab-stack`

Git author: `The Editing Tab <the.editing.tab@gmail.com>`

Core and Booking have a two-week planning target, not a guaranteed completion date. OTA access, offline confirmation policy, deployment, and recovery decisions remain visible in the project documents.