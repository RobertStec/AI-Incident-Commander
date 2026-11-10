"""Alembic environment for asynchronous PostgreSQL migrations."""

import asyncio
from logging.config import fileConfig

from alembic import context
from sqlalchemy.engine import Connection

from ai_incident_commander.infrastructure.database_config import (
    DatabaseConfig,
)
from ai_incident_commander.infrastructure.database_engine import (
    create_database_engine,
)

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# SQLAlchemy metadata will be configured when we define the schema.
target_metadata = None


def run_migrations_offline() -> None:
    """Generate PostgreSQL migration SQL without connecting to the database."""
    context.configure(
        dialect_name="postgresql",
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection) -> None:
    """Run synchronous Alembic operations through a SQLAlchemy connection."""
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
    )

    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    """Run online migrations using the application's database configuration."""
    database_config = DatabaseConfig.from_environment()
    engine = create_database_engine(database_config)

    try:
        async with engine.connect() as connection:
            await connection.run_sync(do_run_migrations)
    finally:
        await engine.dispose()


def run_migrations_online() -> None:
    """Start the asynchronous online migration runner."""
    asyncio.run(run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
