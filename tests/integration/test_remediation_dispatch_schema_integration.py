"""Opt-in PostgreSQL schema contract for durable remediation dispatch reservations."""

import asyncio
import os

import pytest
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from ai_incident_commander.infrastructure.database_config import DatabaseConfig
from ai_incident_commander.infrastructure.database_engine import create_database_engine
from ai_incident_commander.infrastructure.remediation_dispatch_tables import (
    remediation_dispatches_table,
)
from ai_incident_commander.infrastructure.remediation_execution_tables import (
    remediation_executions_table,
)

pytestmark = pytest.mark.skipif(
    os.environ.get("RUN_DB_SCHEMA_TESTS") != "1",
    reason="Set RUN_DB_SCHEMA_TESTS=1 to enable database schema tests",
)


def test_dispatch_schema_matches_durable_reservation_contract() -> None:
    async def run_scenario() -> None:
        assert remediation_dispatches_table.metadata is remediation_executions_table.metadata
        engine = create_database_engine(DatabaseConfig.from_environment())
        try:
            async with engine.connect() as connection:

                def inspect_schema(sync_connection: sa.Connection) -> dict[str, object]:
                    inspector = sa.inspect(sync_connection)
                    assert inspector.has_table("remediation_dispatches")
                    return {
                        "columns": inspector.get_columns("remediation_dispatches"),
                        "primary_key": inspector.get_pk_constraint("remediation_dispatches"),
                        "foreign_keys": inspector.get_foreign_keys("remediation_dispatches"),
                        "unique_constraints": inspector.get_unique_constraints(
                            "remediation_dispatches"
                        ),
                    }

                schema = await connection.run_sync(inspect_schema)
        finally:
            await engine.dispose()

        columns = {column["name"]: column for column in schema["columns"]}
        assert set(columns) == {"dispatch_id", "execution_id", "reserved_at"}
        for name in ("dispatch_id", "execution_id"):
            assert isinstance(columns[name]["type"], postgresql.UUID)
            assert columns[name]["nullable"] is False
        assert isinstance(columns["reserved_at"]["type"], sa.DateTime)
        assert columns["reserved_at"]["type"].timezone is True
        assert columns["reserved_at"]["nullable"] is False
        assert columns["reserved_at"]["default"] is None

        assert schema["primary_key"]["name"] == "pk_remediation_dispatches"
        assert schema["primary_key"]["constrained_columns"] == ["dispatch_id"]
        assert any(
            constraint["name"] == "uq_remediation_dispatches_execution_id"
            and constraint["column_names"] == ["execution_id"]
            for constraint in schema["unique_constraints"]
        )
        assert any(
            fk["name"] == "fk_remediation_dispatches_execution_id"
            and fk["constrained_columns"] == ["execution_id"]
            and fk["referred_table"] == "remediation_executions"
            and fk["referred_columns"] == ["execution_id"]
            and fk["options"].get("ondelete") == "RESTRICT"
            for fk in schema["foreign_keys"]
        )

    asyncio.run(run_scenario())
