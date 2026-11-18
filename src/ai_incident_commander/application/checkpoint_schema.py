"""Explicit administrative setup for LangGraph PostgreSQL checkpoint tables.

This operation may execute DDL and LangGraph-managed schema migrations. It must
never be called as part of normal application startup or request handling.
"""

from ai_incident_commander.application.checkpoint_bootstrap import (
    postgres_checkpoint_lifespan,
)
from ai_incident_commander.infrastructure.database_config import DatabaseConfig


class CheckpointSchemaChangeNotConfirmedError(ValueError):
    """Checkpoint schema changes were not explicitly requested."""


async def initialize_postgres_checkpoint_schema(
    *, config: DatabaseConfig, apply_schema_changes: bool = False
) -> None:
    """Apply LangGraph's checkpoint schema migrations only when explicitly enabled.

    The caller must supply a reviewed database configuration and opt into DDL.
    This function does not manage Alembic and is not an authorization boundary;
    enforce operational permissions and database privileges outside this API.
    """
    if not apply_schema_changes:
        raise CheckpointSchemaChangeNotConfirmedError(
            "Checkpoint schema setup requires explicit apply_schema_changes=True."
        )

    async with postgres_checkpoint_lifespan(config=config) as saver:
        await saver.setup()
