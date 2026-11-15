"""Opt-in PostgreSQL checks for legacy and MCP-bound action policy versions.

These tests must run only after the Alembic upgrade e62b4f0c91ad.
Test records are rolled back, leaving no persistent approval or claim rows.
"""

import asyncio
import os
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncConnection

from ai_incident_commander.infrastructure.approval_tables import approval_requests_table
from ai_incident_commander.infrastructure.database_config import DatabaseConfig
from ai_incident_commander.infrastructure.database_engine import create_database_engine
from ai_incident_commander.infrastructure.execution_claim_tables import execution_claims_table

pytestmark = pytest.mark.skipif(
    os.environ.get("RUN_DB_SCHEMA_TESTS") != "1",
    reason="Set RUN_DB_SCHEMA_TESTS=1 to enable database schema checks",
)

_FINGERPRINT = "afp:v2:" + "a" * 64
_VALID_V1 = "apv:v1:" + "b" * 64
_VALID_V2 = "apv:v2:" + "b" * 64


async def _insert_request(
    connection: AsyncConnection,
    *,
    policy_version: str,
    request_id: UUID,
    plan_id: UUID,
    step_id: UUID,
) -> None:
    now = datetime.now(UTC)
    await connection.execute(
        sa.insert(approval_requests_table).values(
            request_id=request_id,
            plan_id=plan_id,
            step_id=step_id,
            action_fingerprint=_FINGERPRINT,
            policy_version=policy_version,
            requested_at=now,
            expires_at=now + timedelta(minutes=10),
        )
    )


async def _insert_claim(
    connection: AsyncConnection,
    *,
    policy_version: str,
    request_id: UUID,
    plan_id: UUID,
    step_id: UUID,
) -> None:
    await connection.execute(
        sa.insert(execution_claims_table).values(
            claim_id=uuid4(),
            request_id=request_id,
            plan_id=plan_id,
            step_id=step_id,
            action_fingerprint=_FINGERPRINT,
            policy_version=policy_version,
            claimed_at=datetime.now(UTC),
        )
    )


@pytest.mark.parametrize("policy_version", (_VALID_V1, _VALID_V2), ids=("v1", "v2"))
def test_postgres_accepts_both_policy_versions_for_request_and_claim(
    policy_version: str,
) -> None:
    async def scenario() -> None:
        engine = create_database_engine(DatabaseConfig.from_environment())
        try:
            async with engine.connect() as connection:
                transaction = await connection.begin()
                try:
                    request_id, plan_id, step_id = uuid4(), uuid4(), uuid4()
                    await _insert_request(
                        connection,
                        policy_version=policy_version,
                        request_id=request_id,
                        plan_id=plan_id,
                        step_id=step_id,
                    )
                    await _insert_claim(
                        connection,
                        policy_version=policy_version,
                        request_id=request_id,
                        plan_id=plan_id,
                        step_id=step_id,
                    )
                finally:
                    await transaction.rollback()
        finally:
            await engine.dispose()

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "invalid_version",
    ("apv:v3:" + "b" * 64, "apv:v2:" + "g" * 64),
    ids=("unknown-version", "invalid-digest"),
)
@pytest.mark.parametrize("table_kind", ("request", "claim"))
def test_postgres_rejects_invalid_policy_version(
    table_kind: str,
    invalid_version: str,
) -> None:
    async def scenario() -> None:
        engine = create_database_engine(DatabaseConfig.from_environment())
        try:
            async with engine.connect() as connection:
                transaction = await connection.begin()
                try:
                    request_id, plan_id, step_id = uuid4(), uuid4(), uuid4()
                    if table_kind == "claim":
                        # A valid parent request ensures that the claim CHECK,
                        # rather than the foreign key, is the rejected condition.
                        await _insert_request(
                            connection,
                            policy_version=_VALID_V1,
                            request_id=request_id,
                            plan_id=plan_id,
                            step_id=step_id,
                        )

                    with pytest.raises(IntegrityError) as error:
                        async with connection.begin_nested():
                            if table_kind == "request":
                                await _insert_request(
                                    connection,
                                    policy_version=invalid_version,
                                    request_id=request_id,
                                    plan_id=plan_id,
                                    step_id=step_id,
                                )
                            else:
                                await _insert_claim(
                                    connection,
                                    policy_version=invalid_version,
                                    request_id=request_id,
                                    plan_id=plan_id,
                                    step_id=step_id,
                                )

                    original = error.value.orig
                    assert getattr(original, "sqlstate", None) == "23514"
                    expected_constraint = (
                        "ck_approval_request_policy_version"
                        if table_kind == "request"
                        else "ck_execution_claims_policy_version"
                    )
                    assert original.diag.constraint_name == expected_constraint
                finally:
                    await transaction.rollback()
        finally:
            await engine.dispose()

    asyncio.run(scenario())
