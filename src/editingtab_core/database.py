"""Synchronous connections; callers own transaction boundaries."""

from collections.abc import Iterator

from fastapi import Request
from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session

from editingtab_core.config import Settings


def build_engine(settings: Settings) -> Engine:
    timeout = settings.db_connect_timeout
    return create_engine(
        settings.database_url(),
        pool_pre_ping=True,
        pool_size=5,
        max_overflow=0,
        pool_timeout=timeout,
        hide_parameters=True,
        echo=False,
        connect_args={
            "connect_timeout": timeout,
            "options": f"-c statement_timeout={timeout * 1000}",
            "keepalives": 1,
            "keepalives_idle": timeout,
            "keepalives_interval": 1,
            "keepalives_count": 2,
            "tcp_user_timeout": timeout * 1000,
        },
    )


def get_session(request: Request) -> Iterator[Session]:
    # This synchronous dependency is run in FastAPI's worker thread pool.
    # Close rolls back any uncommitted transaction; no implicit commit.
    with request.app.state.session_factory() as session:
        yield session
