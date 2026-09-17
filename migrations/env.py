"""Use application configuration or an explicitly supplied test connection."""

from alembic import context
from alembic.util import CommandError
from sqlalchemy.exc import SQLAlchemyError

import editingtab_core.auth.models  # noqa: F401
import editingtab_core.authorization.models  # noqa: F401
import editingtab_core.platform.models  # noqa: F401
from editingtab_core.config import load_settings
from editingtab_core.database import build_engine
from editingtab_core.identity.models import Base

target_metadata = Base.metadata


def _run_online(connection) -> None:
    try:
        context.configure(connection=connection, target_metadata=target_metadata, compare_type=True)
        with context.begin_transaction():
            context.run_migrations()
    except SQLAlchemyError:
        raise CommandError(
            "Database migration failed; check connectivity and configuration"
        ) from None


def run_migrations() -> None:
    if context.is_offline_mode():
        context.configure(
            dialect_name="postgresql", target_metadata=target_metadata, literal_binds=True
        )
        with context.begin_transaction():
            context.run_migrations()
        return

    # Tests inject a guarded connection with a transactional private schema.
    # Never read a developer .env or dispose a caller-owned connection here.
    connection = context.config.attributes.get("connection")
    if connection is not None:
        _run_online(connection)
        return

    settings = context.config.attributes.get("settings")
    if settings is None:
        settings = load_settings()
    engine = build_engine(settings)
    try:
        with engine.connect() as connection:
            _run_online(connection)
    except SQLAlchemyError:
        raise CommandError(
            "Database migration failed; check connectivity and configuration"
        ) from None
    finally:
        engine.dispose()


run_migrations()
