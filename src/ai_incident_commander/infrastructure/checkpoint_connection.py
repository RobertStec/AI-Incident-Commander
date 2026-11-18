"""Build the Psycopg connection URI used by the LangGraph checkpointer.

The adapter does not connect to PostgreSQL or create/migrate checkpoint tables.
"""

from ai_incident_commander.infrastructure.database_config import (
    DatabaseConfig,
    DatabaseConfigurationError,
)

_CHECKPOINT_SEARCH_PATH_OPTION = "-csearch_path=langgraph_checkpoint"


def create_checkpoint_conninfo(config: DatabaseConfig) -> str:
    """Build a libpq URI scoped to the dedicated LangGraph checkpoint schema.

    Preserve credential escaping and unrelated connection parameters. Reject
    pre-existing libpq options rather than overriding another search_path or
    silently dropping caller settings. The result contains secrets: never log it.
    """
    if config.url.drivername != "postgresql+psycopg":
        raise DatabaseConfigurationError(
            "Checkpoint connection requires the postgresql+psycopg driver."
        )
    if "options" in config.url.query:
        raise DatabaseConfigurationError(
            "Checkpoint connection does not accept preconfigured libpq options."
        )

    checkpoint_url = config.url.set(drivername="postgresql").update_query_dict(
        {"options": _CHECKPOINT_SEARCH_PATH_OPTION}
    )
    return checkpoint_url.render_as_string(hide_password=False)
