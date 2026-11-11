"""Opt-in integration tests for the PostgreSQL approval repository."""

import asyncio
import os
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from ai_incident_commander.application.approval_repository import (
    ApprovalRequestAlreadyExistsError,
)
from ai_incident_commander.domain.remediation_approval import RemediationApprovalRequest
from ai_incident_commander.infrastructure.approval_tables import approval_requests_table
from ai_incident_commander.infrastructure.database_config import DatabaseConfig
from ai_incident_commander.infrastructure.database_engine import create_database_engine
from ai_incident_commander.infrastructure.postgres_approval_repository import (
    PostgresApprovalRepository,
)


def _require_database_tests() -> None:
    if os.environ.get("RUN_DB_APPROVAL_TESTS") != "1":
        pytest.skip("Set RUN_DB_APPROVAL_TESTS=1 to enable approval database tests")


def _make_request() -> RemediationApprovalRequest:
    requested_at = datetime(2030, 1, 1, tzinfo=UTC)
    return RemediationApprovalRequest(
        request_id=uuid4(),
        plan_id=uuid4(),
        step_id=uuid4(),
        action_fingerprint="afp:v2:" + "a" * 64,
        policy_version="apv:v1:" + "b" * 64,
        requested_at=requested_at,
        expires_at=requested_at + timedelta(minutes=30),
    )


async def _delete_test_request(engine: AsyncEngine, request_id: UUID) -> None:
    async with engine.begin() as connection:
        await connection.execute(
            sa.delete(approval_requests_table).where(
                approval_requests_table.c.request_id == request_id
            )
        )


def test_create_request_persists_all_fields() -> None:
    """Read committed data through a separate database connection."""
    _require_database_tests()

    async def run_scenario() -> None:
        request = _make_request()
        engine = create_database_engine(DatabaseConfig.from_environment())
        try:
            repository = PostgresApprovalRepository(engine=engine)
            await repository.create_request(request)

            async with engine.connect() as connection:
                result = await connection.execute(
                    sa.select(approval_requests_table).where(
                        approval_requests_table.c.request_id == request.request_id
                    )
                )
                row = result.mappings().one()

            assert row["request_id"] == request.request_id
            assert row["plan_id"] == request.plan_id
            assert row["step_id"] == request.step_id
            assert row["action_fingerprint"] == request.action_fingerprint
            assert row["policy_version"] == request.policy_version
            assert row["requested_at"] == request.requested_at
            assert row["expires_at"] == request.expires_at
        finally:
            try:
                await _delete_test_request(engine, request.request_id)
            finally:
                await engine.dispose()

    asyncio.run(run_scenario())


def test_create_request_rejects_duplicate_request_id() -> None:
    """Translate the database primary-key violation into a domain-port error."""
    _require_database_tests()

    async def run_scenario() -> None:
        request = _make_request()
        engine = create_database_engine(DatabaseConfig.from_environment())
        try:
            repository = PostgresApprovalRepository(engine=engine)
            await repository.create_request(request)

            with pytest.raises(ApprovalRequestAlreadyExistsError):
                await repository.create_request(request)

            async with engine.connect() as connection:
                count = await connection.scalar(
                    sa.select(sa.func.count())
                    .select_from(approval_requests_table)
                    .where(approval_requests_table.c.request_id == request.request_id)
                )
            assert count == 1
        finally:
            try:
                await _delete_test_request(engine, request.request_id)
            finally:
                await engine.dispose()

    asyncio.run(run_scenario())


def test_get_request_returns_complete_domain_model() -> None:
    """Reconstruct all fields from a committed request as a domain object."""
    _require_database_tests()

    async def run_scenario() -> None:
        request = _make_request()
        engine = create_database_engine(DatabaseConfig.from_environment())
        try:
            repository = PostgresApprovalRepository(engine=engine)
            await repository.create_request(request)

            restored = await repository.get_request(request.request_id)

            assert isinstance(restored, RemediationApprovalRequest)
            assert restored is not request
            assert restored == request
            assert restored.requested_at.tzinfo is UTC
            assert restored.expires_at.tzinfo is UTC
        finally:
            try:
                await _delete_test_request(engine, request.request_id)
            finally:
                await engine.dispose()

    asyncio.run(run_scenario())


def test_get_request_returns_none_for_missing_id() -> None:
    """A missing request is not confused with a database failure."""
    _require_database_tests()

    async def run_scenario() -> None:
        engine = create_database_engine(DatabaseConfig.from_environment())
        try:
            repository = PostgresApprovalRepository(engine=engine)
            assert await repository.get_request(uuid4()) is None
        finally:
            await engine.dispose()

    asyncio.run(run_scenario())


def test_get_request_normalizes_non_utc_session_timestamps() -> None:
    """Always restore UTC timestamps even when the DB session uses another zone."""
    _require_database_tests()

    async def run_scenario() -> None:
        request = _make_request()
        config = DatabaseConfig.from_environment()
        engine = create_async_engine(
            config.url,
            connect_args={"options": "-c TimeZone=Asia/Tokyo"},
            hide_parameters=True,
        )
        try:
            repository = PostgresApprovalRepository(engine=engine)
            await repository.create_request(request)

            async with engine.connect() as connection:
                raw_timestamp = await connection.scalar(
                    sa.select(approval_requests_table.c.requested_at).where(
                        approval_requests_table.c.request_id == request.request_id
                    )
                )

            assert raw_timestamp is not None
            assert raw_timestamp.utcoffset() == timedelta(hours=9)

            restored = await repository.get_request(request.request_id)
            assert restored is not None
            assert restored.requested_at == request.requested_at
            assert restored.expires_at == request.expires_at
            assert restored.requested_at.tzinfo is UTC
            assert restored.expires_at.tzinfo is UTC
        finally:
            try:
                await _delete_test_request(engine, request.request_id)
            finally:
                await engine.dispose()

    asyncio.run(run_scenario())


def test_get_request_does_not_modify_persisted_record() -> None:
    """A read leaves the stored request unchanged."""
    _require_database_tests()

    async def run_scenario() -> None:
        request = _make_request()
        engine = create_database_engine(DatabaseConfig.from_environment())
        statement = sa.select(approval_requests_table).where(
            approval_requests_table.c.request_id == request.request_id
        )
        try:
            repository = PostgresApprovalRepository(engine=engine)
            await repository.create_request(request)

            async with engine.connect() as connection:
                before = dict((await connection.execute(statement)).mappings().one())

            restored = await repository.get_request(request.request_id)
            assert restored is not None

            async with engine.connect() as connection:
                after = dict((await connection.execute(statement)).mappings().one())

            assert after == before
        finally:
            try:
                await _delete_test_request(engine, request.request_id)
            finally:
                await engine.dispose()

    asyncio.run(run_scenario())
