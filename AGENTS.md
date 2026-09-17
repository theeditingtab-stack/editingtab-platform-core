# Project instructions

- Work only in the designated permanent workspace. Confirm location and inspect existing items before writing; preserve and report unexpected files.
- Build a fresh implementation. Do not copy previous Core or Booking implementations or use the editingtab-platform-core-part-01 directory. Do not generate ZIP files.
- Work on one assigned checkpoint at a time. Stop with a reviewable report describing changes, executed checks, limitations, and outstanding decisions.
- The user reviews, tests, commits, and pushes manually. Do not initialize Git, commit, push, or change GitHub unless separately and explicitly authorized.
- Use The Editing Tab company identity: GitHub owner `theeditingtab-stack`; Git author `The Editing Tab <the.editing.tab@gmail.com>`. Keep personal accounts, personal Windows usernames, and machine-specific absolute paths out of project documentation.
- Preserve organization isolation and permission boundaries. Scope access on the server; client administrators must never obtain platform privileges or access another organization.
- Enforce module entitlements on the server. Core owns shared identity and administration; Booking owns inventory and reservations. Never access another service's private tables directly.
- Prefer the smallest maintainable architecture. Explain the concrete need before adding services, queues, or abstractions. Use API, service, and repository boundaries where useful; services own transactions.
- Never print secrets or commit credentials. Never weaken tests or security to obtain passing checks. Claim checks passed only when executed successfully.
- No destructive database or infrastructure actions without explicit task authorization. Soft deletion preserves records; permanent deletion is a separate controlled operation. Booking cancellation must release inventory through its lifecycle.
- Verify dependency versions and compatibility at the implementation checkpoint; do not select versions from memory.
- Keep documentation aligned with implemented behavior. Distinguish proposals, plans, and verified behavior; never invent external APIs or integration access.
