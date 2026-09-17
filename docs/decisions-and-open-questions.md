# Decisions and open questions

## Confirmed requirements

- Company identity: The Editing Tab; GitHub owner `theeditingtab-stack`; Git author `The Editing Tab <the.editing.tab@gmail.com>`.
- Initial modules: Core and Booking. Future: POS, Unified Inbox, Chatbot. No initial payment gateway.
- Multi-organization users, explicit custom-role permissions, separate platform/client administration, company-controlled initial onboarding, and server-enforced entitlements.
- Verified custom domains, administrative audit records, appropriate soft deletion, and separately controlled permanent deletion.
- Booking lifecycle owns inventory release; transactional overselling protection and retry idempotency are required.
- Backend and frontend technologies, local development tools, and database ports follow the project brief. Backend versions are selected and recorded in [dependency verification](dependency-verification.md); frontend versions remain unselected.
- Offline conflicts require a policy; synchronization is not backup. Local/cloud backup and restore planning is required.
- Two weeks is a planning target; changes to scope require explicit agreement.
- The user reports successful CORE-002 GitHub Actions verification. Repository visibility is handled manually by the user and does not block implementation; no repository setting changes are authorized here.

## Design decisions and proposals

| Topic | Proposal | Decision gate |
| --- | --- | --- |
| Architecture and boundaries | Start with one deployable modular backend and one PostgreSQL database, with separate Core/Booking ownership and service interfaces. No cross-module private table access. Add services or queues only for demonstrated requirements. | Accepted by the CORE-002 task and implemented as a single foundation package; detailed module interfaces remain future work. |
| Foundation | Typed environment configuration; ignored local secrets and a placeholder-only example; separate liveness and database readiness endpoints; migration-managed schema; disposable PostgreSQL for CI. Health responses expose no secrets. | Accepted and implemented in CORE-002; local verification passed and the user reports that CORE-002 remote CI passed. |
| Tenant isolation | CORE-003 requires organization IDs in membership queries and mutations. Normal reads filter archival/active state. No row-level security is introduced for these trusted internal operations; it remains a possible additional defense before public access. | Implemented persistence scoping does not replace authentication, authorization, or trusted organization-context resolution. No public management endpoints exist. |
| Permissions | Deny by default; explicit permission catalog; organization-scoped role assignments; separate platform authority. Check membership, permission, and entitlement on protected operations. | Finalize before the proposed permissions checkpoint. |
| Transactions | Services control transactions; Booking uses PostgreSQL constraints/locking appropriate to the agreed inventory model. Store idempotency results with organization scope and request identity. | Finalize before BOOK-001/002, including cross-module transaction needs. |
| Deletion | CORE-003 archives organizations/memberships without deleting records. Slug/email uniqueness and membership pairs remain reserved. Active membership requires active parents; restore reuses the original membership. | Implemented for internal identity persistence. Retention, audit, user lifecycle operations, and controlled permanent deletion remain future work; Booking cancellation remains a separate lifecycle. |

CORE-003 also adopts UUID4 identifiers, timezone-aware timestamps, explicit database constraints, service-owned transactions, idempotent membership addition/restoration, and immutable membership result snapshots. Email lookup trims surrounding whitespace and lowercases ASCII addresses while preserving dots and plus-addressing; original casing is retained for display. Internationalized email and mailbox verification remain future policies. See [identity details](core-003-identity.md).

## Unresolved questions and blockers

| Topic | Open decision | When it blocks |
| --- | --- | --- |
| Dependency maintenance | Backend selection is complete. Revisit the AnyIO compatibility constraint when Starlette is updated; verify all upgrades against the locked checks. | Future dependency upgrades; no unresolved CORE-002 foundation decision. |
| Authentication | CORE-004 settles local Argon2id credentials and opaque revocable cookie sessions for the same-origin demo. Invitations, password recovery, verification, platform MFA, session-wide revocation on lifecycle changes, and initial platform operator bootstrap remain open. Which outbound message provider is available? | Recovery and operational security block public deployment; operator bootstrap blocks management endpoints. They do not block this assigned demo authentication checkpoint. |
| Tenant isolation | How will authenticated callers select and prove organization context, and should row-level security add defense in depth? | Before public management endpoints. Internal scoping, multi-organization identities, reserved uniqueness, and membership archive/restore are settled for CORE-003. |
| Role permissions | Permission catalog, role administration limits, delegated grants, default roles, and platform operator powers? | Before the proposed permissions checkpoint; no self-escalation is negotiable. |
| Module boundaries | Which shared identifiers and interfaces are public? How do entitlement changes affect active reservations and in-flight operations? | Before entitlement and Booking service integration. |
| Domains | Verification method, re-verification/ownership transfer, DNS/TLS provisioning, fallback domain, and trusted proxy configuration? | Before the proposed domain/audit checkpoint and live domain flows; does not block database connectivity. |
| Booking model | Pooled room types or individual units? Occupancy, date boundaries, organization timezone, rates/currency, hold duration, cancellation policy, and guest information requirements? | Before BOOK-001 schema and lifecycle design. |
| OTA access | For each provider: direct or partner access, channel manager support, approval lead time, availability/reservation capabilities, synchronization lag and limits, cost, and test access? | Before provider integration commitments or code; research should start early. No access or capability is assumed. |
| Offline conflicts | Reserved offline inventory allocation or provisional bookings? Who resolves conflicts, and what can staff promise while disconnected? What data and credentials may be stored locally? | Before offline confirmations or sync implementation. Decide initial delivery expectations early. |
| Deployment | Hosting region/provider, environments, TLS, domain routing, secrets, monitoring, operator responsibility, and budget? | Before OPS-001 deployment implementation; revisit earlier if it changes authentication/domain design. |
| Recovery | Required recovery point (acceptable data loss) and recovery time, retention, encrypted local/cloud storage, backup frequency, restore-test frequency, ownership, and budget? | Before production readiness and backup implementation. No unconditional zero-loss or zero-downtime promise. |
| Audit and retention | Which events, actor metadata, retention periods, access permissions, and permanent-deletion approval process are required? | Before the proposed domain/audit checkpoint and deletion behavior; permanent deletion stays unavailable until controlled requirements are agreed. |
| GitHub and CI | CORE-002 CI passed according to the user. CORE-003 is committed and verified according to the user. CORE-004 remote verification awaits manual push; visibility is handled separately. | Does not block local implementation. Do not modify GitHub settings. |
| Delivery acceptance | Exact initial user flows, OTA/offline delivery expectations, operational acceptance criteria, and available reviewers? | Resolve early to assess the two-week target; do not silently omit requirements. |

CORE-003 identity persistence is committed and verified. CORE-004 implements password authentication; authorization and platform bootstrap remain required before public management endpoints. See [CORE-004 policy and limitations](core-004-authentication.md). Provider access, domains, entitlements, recovery, and future modules remain unresolved as listed. Stop after CORE-004; this is not production readiness.
