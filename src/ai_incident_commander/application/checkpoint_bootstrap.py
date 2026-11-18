"""Lifecycle boundary for the LangGraph PostgreSQL checkpoint store.

Schema setup/migrations are intentionally NOT performed at application startup.
The returned saver owns a Psycopg connection only for this context's lifetime.
"""

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver
from langgraph.checkpoint.serde.jsonplus import JsonPlusSerializer

from ai_incident_commander.infrastructure.checkpoint_connection import (
    create_checkpoint_conninfo,
)
from ai_incident_commander.infrastructure.database_config import DatabaseConfig


@asynccontextmanager
async def postgres_checkpoint_lifespan(
    *, config: DatabaseConfig | None = None
) -> AsyncGenerator[AsyncPostgresSaver]:
    """Open one checkpoint connection for the owner application's lifespan.

    The caller owns the context and must not retain its saver after exit.
    Credentials are never logged here. Run database schema setup separately.
    """
    database_config = config if config is not None else DatabaseConfig.from_environment()
    conninfo = create_checkpoint_conninfo(database_config)
    serializer = JsonPlusSerializer(
        pickle_fallback=False,
        allowed_json_modules=None,
        allowed_msgpack_modules=None,
    )
    async with AsyncPostgresSaver.from_conn_string(conninfo, serde=serializer) as saver:
        yield saver
