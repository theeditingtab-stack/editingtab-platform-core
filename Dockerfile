FROM ghcr.io/astral-sh/uv:0.12.15@sha256:62f8c047d0a0e9ece6b53fc63df902585a67a47a7f318ddec4a37db586edc8e3 AS uv

FROM python:3.12-slim-bookworm@sha256:392307d22300de8b5986851a12d9176dfc0fc073e65bf6523ebd7dcbeb23564e AS builder

COPY --from=uv /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/opt/core/.venv
WORKDIR /opt/core

COPY pyproject.toml uv.lock README.md ./
COPY src/ ./src/
RUN uv sync --locked --no-dev --no-editable

FROM python:3.12-slim-bookworm@sha256:392307d22300de8b5986851a12d9176dfc0fc073e65bf6523ebd7dcbeb23564e AS runtime

ENV PATH=/opt/core/.venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
WORKDIR /opt/core

RUN groupadd --system core \
    && useradd --system --gid core --home-dir /nonexistent --no-create-home core \
    && mkdir -p /opt/core/.core-branding \
    && chown core:core /opt/core/.core-branding

COPY --from=builder --chown=core:core /opt/core/.venv ./.venv
COPY --chown=core:core alembic.ini ./
COPY --chown=core:core migrations/ ./migrations/
COPY --chown=core:core scripts/run-migrations.py scripts/validate-production-config.py scripts/load-production-secrets.sh ./scripts/

USER core
EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health/live', timeout=2).read()"]

ENTRYPOINT ["/bin/sh", "scripts/load-production-secrets.sh"]
CMD ["uvicorn", "editingtab_core.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8080", "--no-access-log", "--proxy-headers", "--forwarded-allow-ips=*"]
