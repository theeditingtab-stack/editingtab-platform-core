"""Use the same validated configuration without putting credentials in INI."""

from alembic import context
from alembic.util import CommandError
from sqlalchemy.exc import SQLAlchemyError

from editingtab_core.config import load_settings
from editingtab_core.database import build_engine

# No domain models yet. Add owned model metadata when domain work is authorized.
target_metadata = None


def run_migrations() -> None:
    settings = context.config.attributes.get("settings")
    if settings is None:
        settings = load_settings()
    if context.is_offline_mode():
        context.configure(
            dialect_name="postgresql", target_metadata=target_metadata, literal_binds=True
        )
        with context.begin_transaction():
            context.run_migrations()
        return

    engine = build_engine(settings)
    try:
        with engine.connect() as connection:
            context.configure(connection=connection, target_metadata=target_metadata)
            with context.begin_transaction():
                context.run_migrations()
    except SQLAlchemyError:
        raise CommandError(
            "Database migration failed; check connectivity and configuration"
        ) from None
    finally:
        engine.dispose()


run_migrations()
