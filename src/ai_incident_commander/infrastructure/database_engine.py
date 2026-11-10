"""Factory for the asynchronous PostgreSQL database engine."""

from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from ai_incident_commander.infrastructure.database_config import (
    DatabaseConfig,
)


def create_database_engine(config: DatabaseConfig) -> AsyncEngine:
    """Create a PostgreSQL AsyncEngine without opening a connection."""
    return create_async_engine(
        config.url,
        echo=False,
        hide_parameters=True,
        pool_pre_ping=True,
    )
