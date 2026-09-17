# Project brief

## Purpose and scope

The Editing Tab supports businesses such as hotels and safari operators through independently entitled modules. Clients may purchase different combinations. Initial delivery includes Platform Core and Booking. POS, Unified Inbox, and Chatbot are future modules. Payment gateway integration is outside initial scope.

The company operates platform administration and initially controls client onboarding. Clients administer their own organizations through their own domains. Platform and organization administration must have distinct authorization boundaries.

## Platform Core

- Organizations, memberships, and users who can belong to multiple organizations.
- Custom roles with explicit permissions, similar to Moodle; organization administrators cannot grant platform privileges or access other organizations.
- Shared identity, organization access checks, and server-enforced module entitlements.
- Verified custom domain mappings with secure organization resolution.
- Audit records for important administrative changes.
- Soft deletion where appropriate, preserving database records. Permanent deletion is a separate controlled operation.

## Booking

- Accommodation inventory and availability, with explicit organization isolation.
- Manual telephone and walk-in bookings, plus direct website bookings.
- Reservation lifecycle including cancellations and expiring holds.
- Transactional protection against overselling and idempotency for retryable operations.
- Cancellation releases inventory through the booking lifecycle, never generic soft deletion.

## External booking channels

Airbnb, Agoda, Booking.com, Booking.lk, and other channels require provider-specific investigation. Verify API access, partner approval, channel-manager options, supported capabilities, synchronization limits, costs, and test access. Installing a library does not establish channel access. No integration availability is confirmed.

Channel scope and access are unresolved delivery dependencies; they must remain visible in the plan rather than being silently excluded to fit the target.

## Offline operation

Future POS and manual bookings need local operation and synchronization after connectivity returns. Offline and online inventory can conflict. An explicit allocation or provisional booking policy must be agreed before implementing offline confirmations. Synchronization is not a backup. Offline confirmation behavior and its delivery checkpoint remain unresolved.

## Backup and recovery

Plan local and cloud backups, restore testing, and recovery procedures. The business wants minimal data loss and downtime; unconditional zero data loss or downtime is not promised. Recovery point and recovery time targets, retention, infrastructure, costs, and operational ownership require explicit decisions.

## Technical direction

Backend: Python 3.12, FastAPI, Pydantic Settings, PostgreSQL 17, synchronous SQLAlchemy 2.x, Psycopg 3, Alembic, uv, pytest, and Ruff. Local development uses Windows PowerShell, VS Code, and Docker Compose for PostgreSQL. The database host port is configurable with default 15432; the container port remains 5432.

Frontend, at a later checkpoint: Next.js, React, and TypeScript. Backend versions were selected and locally verified in CORE-002; see [dependency verification](dependency-verification.md). Frontend dependency selection remains future work.

Core owns shared identity and administration; Booking owns inventory and reservations. Modules must not directly access another service's private tables. Prefer the smallest maintainable architecture, using API, service, and repository boundaries where useful. Services own transaction boundaries. Additional microservices, queues, and abstractions need a concrete justification.

## Delivery constraint

Core and Booking have a two-week planning target. Estimates depend on scope decisions, security and concurrency verification, frontend flows, infrastructure, and external approvals. Report schedule risks and agree any scope change explicitly; do not silently remove requirements.


## Current checkpoint state

CORE-002 provides the backend foundation; the user reports that its local checks and GitHub Actions passed. CORE-003 adds internal organization, user, and membership persistence, with scoped queries, reserved uniqueness, and soft deletion. See [CORE-003 identity](core-003-identity.md) for policies and verification. Persistence scoping does not provide authentication or authorization. Other requirements above remain future work; no public management endpoints exist.
