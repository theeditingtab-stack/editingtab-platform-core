# Dependency verification

Selected during CORE-002 on 2026-09-17 from official documentation and PyPI JSON package metadata. Selected package releases were stable, not yanked, and compatible with Python 3.12 according to metadata. A fresh uv resolution, locked sync, and local execution provide compatibility evidence; no prior lockfile was reused.

| Component | Selected / observed version |
| --- | --- |
| Python | 3.12 requirement; 3.12.14 actually installed and used |
| uv | 0.12.15 |
| FastAPI | 0.141.1 |
| Pydantic Settings | 2.15.0 |
| SQLAlchemy | 2.0.54 |
| Psycopg with binary extra | 3.3.5 |
| Alembic | 1.20.0 |
| Uvicorn | 0.53.0 |
| pytest | 9.1.1 |
| Ruff | 0.16.8 |
| HTTPX2 (test client dependency) | 2.13.0 |
| Hatchling (build backend) | 1.32.0 |
| AnyIO compatibility constraint | 4.14.2 |
| PostgreSQL | Official `postgres:17`; local server observed 17.11 |

Direct dependencies are exact in `pyproject.toml`; `uv.lock` retains the resolved transitive dependencies and hashes. Use `uv sync --locked` and `uv run --locked`. Python is constrained to the 3.12 series. The PostgreSQL major tag allows patch updates; this is not an immutable container-image pin.

## Compatibility findings

Starlette 1.6.0, resolved by FastAPI, deprecated its older HTTPX test-client path. HTTPX2 was selected after checking its official repository and package metadata.

With AnyIO 4.15.1, Starlette's test client used a deprecated `BlockingPortal` alias and failed our warnings-as-errors check. AnyIO 4.14.2 was verified stable and compatible, then explicitly constrained. Warnings remain errors; no warning suppression or reduced assertions were introduced. Revisit this constraint with a Starlette update.

## Official sources

- [uv installation](https://docs.astral.sh/uv/getting-started/installation/) and [GitHub Actions integration](https://docs.astral.sh/uv/guides/integration/github/): local tooling and CI setup.
- [FastAPI lifespan](https://fastapi.tiangolo.com/advanced/events/): application resource lifecycle.
- [Pydantic Settings](https://docs.pydantic.dev/latest/concepts/pydantic_settings/): environment configuration.
- [SQLAlchemy engine configuration](https://docs.sqlalchemy.org/en/20/core/engines.html): URL objects and lazy connections.
- [Psycopg installation](https://www.psycopg.org/psycopg3/docs/basic/install.html): binary package and platform support.
- [Alembic tutorial](https://alembic.sqlalchemy.org/en/latest/tutorial.html): revision infrastructure.
- [PostgreSQL connection settings](https://www.postgresql.org/docs/17/libpq-connect.html) and [official Docker image](https://hub.docker.com/_/postgres): connection bounds and local database setup.
- [HTTPX2](https://github.com/pydantic/httpx2), [Starlette test client source](https://github.com/Kludex/starlette/blob/main/starlette/testclient.py), and [AnyIO release history](https://anyio.readthedocs.io/en/stable/versionhistory.html): compatibility investigation.
- [GitHub PostgreSQL service containers](https://docs.github.com/en/actions/tutorials/use-containerized-services/create-postgresql-service-containers): isolated CI database.
- [PyPI metadata API](https://docs.pypi.org/api/json/): release versions, Python requirements, and yanked status. Queries used each package's `https://pypi.org/pypi/<package>/json` endpoint, plus the exact AnyIO 4.14.2 endpoint.

CI pins the official checkout and setup-uv actions by full commit SHA from current uv guidance. It uses read-only repository permissions, no persisted checkout credentials, and disposable database credentials. A real GitHub Actions run remains pending the user's manual push.