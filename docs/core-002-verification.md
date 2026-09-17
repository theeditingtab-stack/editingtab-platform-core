# CORE-002 verification

Historical checkpoint record: verified locally on 2026-09-17. The user subsequently reported successful manual verification and CORE-002 GitHub Actions. The execution/state statements below describe the original CORE-002 run; see [CORE-003 identity](core-003-identity.md) for the current checkpoint. Scope is the backend foundation only; future Core and Booking features remain unimplemented.

## Files and local artifacts

- Added `pyproject.toml`, `uv.lock`, `.python-version`, `.gitignore`, and `.env.example`.
- Added `compose.yaml`, `alembic.ini`, `migrations/env.py`, `migrations/script.py.mako`, and `migrations/versions/0001_foundation.py`.
- Added `src/editingtab_core/{__init__,config,database,app}.py`.
- Added `tests/conftest.py`, `tests/unit/test_config.py`, `tests/unit/test_health.py`, and `tests/integration/{conftest,test_postgres,test_safety}.py`.
- Added `scripts/init-dev.py`, `scripts/use-tools.ps1`, `scripts/start-db.ps1`, and `scripts/test-integration.ps1`.
- Added `.github/workflows/backend.yml` and the local development, dependency verification, and checkpoint verification documents.
- Updated README, project brief, implementation plan, and decision register; preserved existing requirements and AGENTS.md.
- Generated ignored local `.env`, `.venv`, tool installation/cache files under `.tools`, and test/lint caches. No secret values appear in project documentation.

## Executed checks

| Check | Result |
| --- | --- |
| Fresh lock generation and `uv sync --locked` | Passed; Python 3.12.14 used |
| Ruff lint and format check | Passed |
| `pytest -m 'not integration'` | 25 passed; 3 real integration tests deselected |
| Explicit integration test helper | 8 passed: 3 real PostgreSQL tests and 5 configuration safety cases |
| Test database migration | Upgrade to head, current revision `0001_foundation`, and repeat upgrade passed; only `alembic_version` exists |
| Development migration | Upgrade and current revision passed; no downgrade/reset performed |
| Compose port overrides | Validated development 25432 and test 25433 resolve to internal 5432 without changing running services or printing secrets |
| Documentation and secret review | Relative links resolve; no machine-specific absolute paths in documentation; generated development password absent from intended project files |
| Initialization rerun | Existing `.env` preserved byte-for-byte; no password displayed |
| Integration without explicit configuration | Failed as expected with 3 setup errors; no fallback |
| Integration with unavailable test endpoint | Failed as expected with connectivity, migration, and readiness failures |
| Live API with PostgreSQL available | Liveness 200 and readiness 200 |
| Same API while development database stopped | Liveness 200; readiness 503 in approximately 3.04 seconds |
| Same API after PostgreSQL restored | Readiness 200 without restarting API |
| API shutdown | Application shutdown completed after Ctrl+C |
| Test storage inspection | tmpfs at `/var/lib/postgresql/data`; no volume mounts |

Initial issues were corrected: a write command exceeded Windows command-length limits, Ruff initially scanned local downloaded tooling before explicit exclusions were added, and upstream test-client dependency warnings required compatible HTTPX2/AnyIO selection. An integration-marker detection issue was fixed so safety tests run with the unit checks. Warnings remain errors. A documentation audit initially mistook an HTTPS URL for a Windows path; the corrected audit passed. Two official Starlette documentation URLs returned HTTP 502; official repository source and package metadata were used instead.

## Project Docker resources

| Resource | State at checkpoint |
| --- | --- |
| `editingtab-core-dev-db-1` | Running, healthy; `127.0.0.1:15432 → 5432` |
| `editingtab-core-dev-db-test-1` | Running, healthy; `127.0.0.1:15433 → 5432`; disposable tmpfs |
| `editingtab-core-dev_core_postgres_data` | Persistent development volume; retained |
| `editingtab-core-dev_default` | Project bridge network; retained |

Both database services use `postgres:17`; the observed server is PostgreSQL 17.11. Only this task's development database was temporarily stopped, then restored. No existing resources were deleted, and no unrelated services or shared Docker settings were changed. The API verification process is stopped.

## Not executed / limitations

- GitHub Actions has not run. Its workflow is prepared for push and pull request events; execution requires the user's manual repository setup/review/push. Remote repository status remains unconfirmed.
- CI's Linux runner has not been exercised remotely; local verification used Windows.
- Production deployment, authentication, tenant access rules, domain mapping, Booking, OTA/offline capabilities, backup/restore readiness, and load testing are outside this checkpoint.
- Connection settings bound individual waits; arbitrary network/DNS failure timing is not an unconditional deadline.
- The local database uses the official image's development bootstrap user; production least-privilege roles, TLS, and operational configuration remain future work.
- The PostgreSQL major tag is mutable across patch releases; the Python lockfile does not pin Docker images.

Use [local development](local-development.md) for exact PowerShell reproduction commands. No Git initialization, commit, push, or GitHub modification was performed.