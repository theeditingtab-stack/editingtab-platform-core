# CORE-SETUP-001 first-time web Super Admin setup

## Authority and lifecycle

Core remains the only owner of the initial identity, password credential, platform grant,
bootstrap closure, and audit record. The Booking React application renders the form and calls
Core; it holds no platform-authority logic. `GET /platform/setup/status` returns only
`{"setup_required": true|false}`. It never reports an email, token configuration, account count,
grant state, or recovery details, and platform responses are marked `Cache-Control: no-store`.

`POST /platform/setup` accepts `email`, `password`, `password_confirmation`, and `setup_token`.
It requires the existing exact-Origin protection, a bounded request body, a configured setup-token
digest, and a PostgreSQL-backed per-source rate limit. Token comparison is constant-time against a
lowercase SHA-256 digest. Validation and error responses never echo request input.

After token authentication, Core locks the singleton `core_platform_bootstrap` row. The same
transaction creates the selected Core identity and Argon2id credential, creates the independent
platform grant, records `administrator_user_id` and `completed_at`, and appends the existing
platform audit record. It creates no organization, membership, role, or browser session. Concurrent
requests serialize on that row: one may return `201`; every later request returns `409` without
changing credentials or grants.

Completed or inconsistent historical state fails closed. Setup eligibility is never inferred from
an empty user table or a missing active grant. Migration `0016_first_time_web_setup` only adds the
nullable administrator reference and backfills an existing completed installation when it has its
single historical platform grant. Existing users, password hashes, grants, sessions, and audits are
not rewritten.

## Create and configure the setup token

From the Core repository root, generate a 256-bit URL-safe token and its digest into ignored,
exclusive files:

```console
python scripts/init-setup-token.py
```

The command prints file names only. Import `.secrets/initial-setup.token` into the approved password
manager as the private token. Configure only the contents of `.secrets/initial-setup.sha256` as
`CORE_SETUP_TOKEN_DIGEST`; the browser operator enters the raw token. Do not place either value in
Git, command arguments, tickets, screenshots, build arguments, browser storage, or logs. Restrict
the local file ACLs and delete both files after the password-manager import and deployment setup.

Optional rate-limit settings are `CORE_SETUP_WINDOW_SECONDS` (60..3600, default 300) and
`CORE_SETUP_SOURCE_LIMIT` (1..20, default 5). The source address uses the same reviewed ingress
trust boundary as login throttling.

After successful setup, remove `CORE_SETUP_TOKEN_DIGEST` from the service environment and restart
Core. Database closure already prevents reuse; removing the digest independently disables the web
operation. This also prevents a later ordinary data reset from making setup usable. Destruction of
both the database and deployment configuration is a new installation and cannot be distinguished
using lost state.

## Recovery and CLI compatibility

The interactive `editingtab_core.platform.bootstrap` command remains available and retains its
legacy fixed company identity for protected-shell workflows. It records the same administrator
reference when it performs a fresh bootstrap. The separate interactive
`editingtab_core.platform.recover` command now targets the administrator recorded in bootstrap
state, resets only that credential, revokes its sessions, restores its grant, and writes the same
platform and security audit records. Neither command runs at API startup or during migrations.
