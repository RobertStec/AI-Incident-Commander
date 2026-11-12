"""Read-only checks for the PostgreSQL approval and execution claim schema."""

import asyncio
import os

import pytest
import sqlalchemy as sa
from sqlalchemy.engine import Connection

from ai_incident_commander.infrastructure.approval_tables import (
    approval_decisions_table,
    approval_requests_table,
)
from ai_incident_commander.infrastructure.database_config import DatabaseConfig
from ai_incident_commander.infrastructure.database_engine import create_database_engine
from ai_incident_commander.infrastructure.execution_claim_tables import execution_claims_table


def _assert_schema_matches_metadata(connection: Connection, table: sa.Table) -> None:
    """Compare a live PostgreSQL table against SQLAlchemy Core metadata."""
    inspector = sa.inspect(connection)
    assert table.name in inspector.get_table_names()

    actual_columns = {column["name"]: column for column in inspector.get_columns(table.name)}
    assert set(actual_columns) == set(table.columns.keys())

    for expected in table.columns:
        actual = actual_columns[expected.name]
        assert actual["nullable"] == expected.nullable
        assert actual["type"].compile(dialect=connection.dialect) == expected.type.compile(
            dialect=connection.dialect
        )
        assert actual.get("default") is None

    actual_pk = inspector.get_pk_constraint(table.name)
    assert actual_pk["name"] == table.primary_key.name
    assert actual_pk["constrained_columns"] == list(table.primary_key.columns.keys())

    expected_uniques = {
        (constraint.name, tuple(constraint.columns.keys()))
        for constraint in table.constraints
        if isinstance(constraint, sa.UniqueConstraint)
    }
    actual_uniques = {
        (constraint["name"], tuple(constraint["column_names"]))
        for constraint in inspector.get_unique_constraints(table.name)
    }
    assert actual_uniques == expected_uniques

    expected_fks = {
        (
            constraint.name,
            tuple(constraint.columns.keys()),
            constraint.referred_table.name,
            tuple(element.column.name for element in constraint.elements),
            constraint.ondelete,
        )
        for constraint in table.constraints
        if isinstance(constraint, sa.ForeignKeyConstraint)
    }
    actual_fks = {
        (
            constraint["name"],
            tuple(constraint["constrained_columns"]),
            constraint["referred_table"],
            tuple(constraint["referred_columns"]),
            constraint.get("options", {}).get("ondelete"),
        )
        for constraint in inspector.get_foreign_keys(table.name)
    }
    assert actual_fks == expected_fks

    expected_checks = {
        constraint.name
        for constraint in table.constraints
        if isinstance(constraint, sa.CheckConstraint)
    }
    actual_checks = {
        constraint["name"] for constraint in inspector.get_check_constraints(table.name)
    }
    assert actual_checks == expected_checks


@pytest.mark.parametrize(
    "table",
    (approval_requests_table, approval_decisions_table, execution_claims_table),
    ids=("requests", "decisions", "execution-claims"),
)
def test_live_approval_schema_matches_metadata(table: sa.Table) -> None:
    """Inspect PostgreSQL only when integration tests are explicitly enabled."""
    if os.environ.get("RUN_DB_SCHEMA_TESTS") != "1":
        pytest.skip("Set RUN_DB_SCHEMA_TESTS=1 to enable database schema checks")

    async def check_schema() -> None:
        engine = create_database_engine(DatabaseConfig.from_environment())
        try:
            async with engine.connect() as connection:
                await connection.run_sync(_assert_schema_matches_metadata, table)
        finally:
            await engine.dispose()

    asyncio.run(check_schema())
