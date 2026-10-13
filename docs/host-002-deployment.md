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

For the Render staging topology introduced by Core DEPLOY-001 commit `eb34b63` and Booking
DEPLOY-001 commit `79d619d`, DEPLOY-002B keeps `--forwarded-allow-ips=*` intentionally. Core is a
private service with no public hostname inside a network-isolated Render environment, while the
only public web service is Caddy. Caddy trusts Render's overwritten `CF-Connecting-IP` only from a
private ingress peer and replaces the upstream `X-Forwarded-For` value with one canonical client
address. Restricting Uvicorn to a guessed CIDR would not improve the boundary because Render does
not provide a stable per-service ingress CIDR in the Blueprint, and could silently collapse all
login attempts into a proxy-source bucket.

This wildcard is conditional on private-service reachability and Caddy's header sanitization. It
must be removed or narrowed before Core receives any public or otherwise untrusted direct network
path. Other services in the same isolated environment remain inside this network trust boundary;
hosted verification must confirm private-only reachability, the observed Caddy-to-Core peer, the
canonical client address, and rejection of browser-supplied forwarding values. Static inspection
does not establish those hosted facts.

Core production configuration must set `CORE_ENVIRONMENT=production`, the explicit
database target, exactly `https://demo.theeditingtab.com` as the allowed browser origin,
and the SHA-256 digest of the Booking service credential. Production cookie behavior is
therefore Secure, HttpOnly, SameSite=None, host-only, and scoped to `/`.

Use the unified deployment guide in the Booking repository for secrets, migrations,
bootstrap, backup, verification, and rollback. No migration is applied by API startup.
