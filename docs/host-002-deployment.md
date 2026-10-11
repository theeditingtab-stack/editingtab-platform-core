# HOST-002 Core container boundary

Core now has a production image, but remains part of the unified deployment owned by
the Booking repository at `deploy/compose.production.yaml`. The image uses Python 3.12,
the checked-in `uv.lock`, a non-root runtime user, and a liveness check. Its startup
command never runs Alembic. The separate `core-migrate` Compose service runs
`scripts/run-migrations.py` and must complete before `core-api` starts.

Production startup reads the database password and Booking service digest from mounted
secret files, validates configuration without displaying values, and then replaces the
entrypoint process with Uvicorn. Uvicorn trusts forwarded headers because the API has no
published port and is reachable only from containers on the private application network.
The public Caddy proxy removes the direct network path from an Internet client.
Plain HTTP for the internal Booking contract is accepted only from the explicitly
configured private CIDR; forwarded headers cannot expand that trust boundary.

Core production configuration must set `CORE_ENVIRONMENT=production`, the explicit
database target, exactly `https://demo.theeditingtab.com` as the allowed browser origin,
and the SHA-256 digest of the Booking service credential. Production cookie behavior is
therefore Secure, HttpOnly, SameSite=None, host-only, and scoped to `/`.

Use the unified deployment guide in the Booking repository for secrets, migrations,
bootstrap, backup, verification, and rollback. No migration is applied by API startup.
