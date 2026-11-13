"""Opt-in PostgreSQL tests for durable remediation execution state changes."""

import asyncio
import os
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from typing import cast
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncEngine

from ai_incident_commander.application.remediation_execution_repository import (
    RemediationExecutionAlreadyStartedError,
    RemediationExecutionClaimNotFoundError,
    RemediationExecutionNotFoundError,
    RemediationExecutionOutcomeNotAllowedError,
)
from ai_incident_commander.domain.execution_claim import ExecutionClaim
from ai_incident_commander.domain.remediation_approval import (
    RemediationApprovalDecision,
    RemediationApprovalOutcome,
    RemediationApprovalRequest,
)
from ai_incident_commander.domain.remediation_execution import (
    RemediationExecution,
    RemediationExecutionStatus,
)
from ai_incident_commander.infrastructure.approval_tables import (
    approval_decisions_table,
    approval_requests_table,
)
from ai_incident_commander.infrastructure.database_config import DatabaseConfig
from ai_incident_commander.infrastructure.database_engine import create_database_engine
from ai_incident_commander.infrastructure.execution_claim_tables import (
    execution_claims_table,
)
from ai_incident_commander.infrastructure.postgres_approval_repository import (
    PostgresApprovalRepository,
)
from ai_incident_commander.infrastructure.postgres_execution_claim_repository import (
    PostgresExecutionClaimRepository,
)
from ai_incident_commander.infrastructure.postgres_remediation_execution_repository import (
    PostgresRemediationExecutionRepository,
)
from ai_incident_commander.infrastructure.remediation_execution_tables import (
    remediation_executions_table,
)

pytestmark = pytest.mark.skipif(
    os.environ.get("RUN_DB_APPROVAL_TESTS") != "1",
    reason="Set RUN_DB_APPROVAL_TESTS=1 to enable database integration tests",
)

_FINGERPRINT = "afp:v2:" + "a" * 64
_POLICY_VERSION = "apv:v1:" + "b" * 64


async def _database_now(engine: AsyncEngine) -> datetime:
    async with engine.connect() as connection:
        timestamp = await connection.scalar(sa.select(sa.func.clock_timestamp()))
    assert isinstance(timestamp, datetime)
    return timestamp.astimezone(UTC)


@asynccontextmanager
async def _seed_claims(
    count: int = 1,
) -> AsyncIterator[tuple[AsyncEngine, tuple[ExecutionClaim, ...]]]:
    """Build real approved claims and clean up only test-owned records."""
    engine = create_database_engine(DatabaseConfig.from_environment())
    requests: list[UUID] = []
    claims: list[ExecutionClaim] = []
    try:
        approvals = PostgresApprovalRepository(engine=engine)
        claim_repository = PostgresExecutionClaimRepository(engine=engine)
        for _ in range(count):
            now = await _database_now(engine)
            request = RemediationApprovalRequest(
                plan_id=uuid4(),
                step_id=uuid4(),
                action_fingerprint=_FINGERPRINT,
                policy_version=_POLICY_VERSION,
                requested_at=now - timedelta(minutes=5),
                expires_at=now + timedelta(minutes=25),
            )
            requests.append(request.request_id)
            await approvals.create_request(request)
            await approvals.record_decision_once(
                RemediationApprovalDecision(
                    request_id=request.request_id,
                    operator_id="remediation-execution-integration-operator",
                    outcome=RemediationApprovalOutcome.APPROVED,
                    decided_at=await _database_now(engine),
                    reason="Approved for execution lifecycle integration test.",
                )
            )
            claims.append(
                await claim_repository.claim_once(
                    request_id=request.request_id,
                    plan_id=request.plan_id,
                    step_id=request.step_id,
                    action_fingerprint=request.action_fingerprint,
                    policy_version=request.policy_version,
                )
            )
        yield engine, tuple(claims)
    finally:
        try:
            if requests:
                async with engine.begin() as connection:
                    # FK RESTRICT: execution -> claim -> decision -> request.
                    await connection.execute(
                        sa.delete(remediation_executions_table).where(
                            remediation_executions_table.c.claim_id.in_(
                                sa.select(execution_claims_table.c.claim_id).where(
                                    execution_claims_table.c.request_id.in_(requests)
                                )
                            )
                        )
                    )
                    await connection.execute(
                        sa.delete(execution_claims_table).where(
                            execution_claims_table.c.request_id.in_(requests)
                        )
                    )
                    await connection.execute(
                        sa.delete(approval_decisions_table).where(
                            approval_decisions_table.c.request_id.in_(requests)
                        )
                    )
                    await connection.execute(
                        sa.delete(approval_requests_table).where(
                            approval_requests_table.c.request_id.in_(requests)
                        )
                    )
        finally:
            await engine.dispose()


def test_start_once_rejects_unknown_claim_without_creating_attempt() -> None:
    async def run_scenario() -> None:
        engine = create_database_engine(DatabaseConfig.from_environment())
        missing_claim_id = uuid4()
        try:
            repository = PostgresRemediationExecutionRepository(engine=engine)
            with pytest.raises(RemediationExecutionClaimNotFoundError):
                await repository.start_once(claim_id=missing_claim_id)
            async with engine.connect() as connection:
                count = await connection.scalar(
                    sa.select(sa.func.count())
                    .select_from(remediation_executions_table)
                    .where(remediation_executions_table.c.claim_id == missing_claim_id)
                )
            assert count == 0
        finally:
            await engine.dispose()

    asyncio.run(run_scenario())


def test_start_once_commits_single_executing_attempt_using_postgres_clock() -> None:
    async def run_scenario() -> None:
        async with _seed_claims() as (engine, claims):
            claim = claims[0]
            repository = PostgresRemediationExecutionRepository(engine=engine)
            before = await _database_now(engine)
            execution = await repository.start_once(claim_id=claim.claim_id)
            after = await _database_now(engine)

            assert isinstance(execution, RemediationExecution)
            assert execution.execution_id != claim.claim_id
            assert execution.claim_id == claim.claim_id
            assert execution.status is RemediationExecutionStatus.EXECUTING
            assert execution.status_changed_at is None
            assert execution.started_at.tzinfo is UTC
            assert before <= execution.started_at <= after

            statement = sa.select(remediation_executions_table).where(
                remediation_executions_table.c.claim_id == claim.claim_id
            )
            async with engine.connect() as connection:
                persisted = (await connection.execute(statement)).mappings().one()
            assert persisted["execution_id"] == execution.execution_id
            assert persisted["claim_id"] == claim.claim_id
            assert persisted["status"] == "executing"
            assert persisted["started_at"] == execution.started_at
            assert persisted["status_changed_at"] is None

    asyncio.run(run_scenario())


def test_start_once_denies_identical_retry_and_preserves_first_attempt() -> None:
    async def run_scenario() -> None:
        async with _seed_claims() as (engine, claims):
            claim = claims[0]
            repository = PostgresRemediationExecutionRepository(engine=engine)
            first = await repository.start_once(claim_id=claim.claim_id)

            with pytest.raises(RemediationExecutionAlreadyStartedError):
                await repository.start_once(claim_id=claim.claim_id)

            statement = sa.select(remediation_executions_table).where(
                remediation_executions_table.c.claim_id == claim.claim_id
            )
            async with engine.connect() as connection:
                attempts = (await connection.execute(statement)).mappings().all()
            assert len(attempts) == 1
            assert attempts[0]["execution_id"] == first.execution_id
            assert attempts[0]["started_at"] == first.started_at

    asyncio.run(run_scenario())


def test_start_once_allows_distinct_claims_without_cross_talk() -> None:
    async def run_scenario() -> None:
        async with _seed_claims(count=2) as (engine, claims):
            repository = PostgresRemediationExecutionRepository(engine=engine)
            first = await repository.start_once(claim_id=claims[0].claim_id)
            second = await repository.start_once(claim_id=claims[1].claim_id)

            assert first.execution_id != second.execution_id
            assert first.claim_id != second.claim_id
            assert first.status is RemediationExecutionStatus.EXECUTING
            assert second.status is RemediationExecutionStatus.EXECUTING
            async with engine.connect() as connection:
                count = await connection.scalar(
                    sa.select(sa.func.count())
                    .select_from(remediation_executions_table)
                    .where(
                        remediation_executions_table.c.claim_id.in_(
                            (claims[0].claim_id, claims[1].claim_id)
                        )
                    )
                )
            assert count == 2

    asyncio.run(run_scenario())


@pytest.mark.parametrize(
    "outcome",
    [
        RemediationExecutionStatus.SUCCEEDED,
        RemediationExecutionStatus.FAILED,
        RemediationExecutionStatus.UNKNOWN,
    ],
)
def test_record_outcome_once_commits_terminal_status_using_postgres_clock(
    outcome: RemediationExecutionStatus,
) -> None:
    async def run_scenario() -> None:
        async with _seed_claims() as (engine, claims):
            repository = PostgresRemediationExecutionRepository(engine=engine)
            started = await repository.start_once(claim_id=claims[0].claim_id)
            before = await _database_now(engine)
            finalized = await repository.record_outcome_once(
                execution_id=started.execution_id,
                outcome=outcome,
            )
            after = await _database_now(engine)

            assert isinstance(finalized, RemediationExecution)
            assert finalized.execution_id == started.execution_id
            assert finalized.claim_id == started.claim_id
            assert finalized.status is outcome
            assert finalized.started_at == started.started_at
            assert finalized.status_changed_at is not None
            assert finalized.status_changed_at.tzinfo is UTC
            assert before <= finalized.status_changed_at <= after

            async with engine.connect() as connection:
                persisted = (
                    (
                        await connection.execute(
                            sa.select(remediation_executions_table).where(
                                remediation_executions_table.c.execution_id == started.execution_id
                            )
                        )
                    )
                    .mappings()
                    .one()
                )
            assert persisted["status"] == outcome.value
            assert persisted["status_changed_at"] == finalized.status_changed_at
            assert persisted["started_at"] == started.started_at

    asyncio.run(run_scenario())


def test_record_outcome_once_rejects_missing_execution_id() -> None:
    async def run_scenario() -> None:
        engine = create_database_engine(DatabaseConfig.from_environment())
        try:
            repository = PostgresRemediationExecutionRepository(engine=engine)
            with pytest.raises(RemediationExecutionNotFoundError):
                await repository.record_outcome_once(
                    execution_id=uuid4(),
                    outcome=RemediationExecutionStatus.SUCCEEDED,
                )
        finally:
            await engine.dispose()

    asyncio.run(run_scenario())


@pytest.mark.parametrize("second_outcome", ["same", "different"])
def test_record_outcome_once_rejects_repeated_or_conflicting_result(
    second_outcome: str,
) -> None:
    async def run_scenario() -> None:
        async with _seed_claims() as (engine, claims):
            repository = PostgresRemediationExecutionRepository(engine=engine)
            started = await repository.start_once(claim_id=claims[0].claim_id)
            first = await repository.record_outcome_once(
                execution_id=started.execution_id,
                outcome=RemediationExecutionStatus.SUCCEEDED,
            )
            retry_outcome = (
                RemediationExecutionStatus.SUCCEEDED
                if second_outcome == "same"
                else RemediationExecutionStatus.FAILED
            )
            with pytest.raises(RemediationExecutionOutcomeNotAllowedError):
                await repository.record_outcome_once(
                    execution_id=started.execution_id,
                    outcome=retry_outcome,
                )

            async with engine.connect() as connection:
                persisted = (
                    (
                        await connection.execute(
                            sa.select(remediation_executions_table).where(
                                remediation_executions_table.c.execution_id == started.execution_id
                            )
                        )
                    )
                    .mappings()
                    .one()
                )
            assert persisted["status"] == "succeeded"
            assert persisted["status_changed_at"] == first.status_changed_at
            assert persisted["started_at"] == first.started_at

    asyncio.run(run_scenario())


@pytest.mark.parametrize(
    "invalid_outcome",
    [
        RemediationExecutionStatus.EXECUTING,
        cast(RemediationExecutionStatus, "succeeded"),
    ],
)
def test_record_outcome_once_rejects_invalid_or_untyped_outcome(
    invalid_outcome: RemediationExecutionStatus,
) -> None:
    async def run_scenario() -> None:
        async with _seed_claims() as (engine, claims):
            repository = PostgresRemediationExecutionRepository(engine=engine)
            started = await repository.start_once(claim_id=claims[0].claim_id)
            with pytest.raises(RemediationExecutionOutcomeNotAllowedError):
                await repository.record_outcome_once(
                    execution_id=started.execution_id,
                    outcome=invalid_outcome,
                )

            async with engine.connect() as connection:
                persisted = (
                    (
                        await connection.execute(
                            sa.select(remediation_executions_table).where(
                                remediation_executions_table.c.execution_id == started.execution_id
                            )
                        )
                    )
                    .mappings()
                    .one()
                )
            assert persisted["status"] == "executing"
            assert persisted["status_changed_at"] is None

    asyncio.run(run_scenario())


def test_record_outcome_once_leaves_other_executions_unchanged() -> None:
    async def run_scenario() -> None:
        async with _seed_claims(count=2) as (engine, claims):
            repository = PostgresRemediationExecutionRepository(engine=engine)
            first = await repository.start_once(claim_id=claims[0].claim_id)
            second = await repository.start_once(claim_id=claims[1].claim_id)
            await repository.record_outcome_once(
                execution_id=first.execution_id,
                outcome=RemediationExecutionStatus.UNKNOWN,
            )

            async with engine.connect() as connection:
                rows = (
                    (
                        await connection.execute(
                            sa.select(remediation_executions_table).where(
                                remediation_executions_table.c.execution_id.in_(
                                    (first.execution_id, second.execution_id)
                                )
                            )
                        )
                    )
                    .mappings()
                    .all()
                )
            assert len(rows) == 2
            by_id = {row["execution_id"]: row for row in rows}
            assert by_id[first.execution_id]["status"] == "unknown"
            assert by_id[second.execution_id]["status"] == "executing"
            assert by_id[second.execution_id]["status_changed_at"] is None

    asyncio.run(run_scenario())


@pytest.mark.parametrize(
    "outcomes",
    [
        (
            RemediationExecutionStatus.SUCCEEDED,
            RemediationExecutionStatus.UNKNOWN,
        ),
        (
            RemediationExecutionStatus.SUCCEEDED,
            RemediationExecutionStatus.SUCCEEDED,
        ),
    ],
    ids=("conflicting-outcomes", "identical-outcomes"),
)
def test_record_outcome_once_allows_only_one_concurrent_winner(
    outcomes: tuple[RemediationExecutionStatus, RemediationExecutionStatus],
) -> None:
    """Force both workers to attempt UPDATE while another transaction holds the row.

    Event hooks report SQL dispatch, not success. The row lock prevents either
    worker from completing until BOTH have reached the guarded UPDATE.
    """

    async def run_scenario() -> None:
        async with _seed_claims() as (setup_engine, claims):
            setup_repository = PostgresRemediationExecutionRepository(engine=setup_engine)
            started = await setup_repository.start_once(claim_id=claims[0].claim_id)

            config = DatabaseConfig.from_environment()
            worker_engines = (
                create_database_engine(config),
                create_database_engine(config),
            )
            update_dispatched = (asyncio.Event(), asyncio.Event())
            worker_tasks: list[asyncio.Task[RemediationExecution]] = []

            def make_update_listener(signal: asyncio.Event) -> Callable[..., None]:
                def on_before_execute(
                    _connection: object,
                    _cursor: object,
                    statement: str,
                    _parameters: object,
                    _context: object,
                    _executemany: bool,
                ) -> None:
                    if statement.lstrip().lower().startswith("update remediation_executions "):
                        signal.set()

                return on_before_execute

            listeners = tuple(make_update_listener(signal) for signal in update_dispatched)
            for engine, listener in zip(worker_engines, listeners, strict=True):
                sa.event.listen(engine.sync_engine, "before_cursor_execute", listener)

            try:
                # Lock the persisted EXECUTING row BEFORE scheduling the workers.
                async with setup_engine.begin() as blocker:
                    locked = await blocker.scalar(
                        sa.select(remediation_executions_table.c.execution_id)
                        .where(remediation_executions_table.c.execution_id == started.execution_id)
                        .with_for_update()
                    )
                    assert locked == started.execution_id

                    for engine, outcome in zip(worker_engines, outcomes, strict=True):
                        repository = PostgresRemediationExecutionRepository(engine=engine)
                        worker_tasks.append(
                            asyncio.create_task(
                                repository.record_outcome_once(
                                    execution_id=started.execution_id,
                                    outcome=outcome,
                                )
                            )
                        )

                    # Each independent worker has reached the UPDATE statement.
                    # No worker can commit while the blocker owns the row lock.
                    await asyncio.wait_for(
                        asyncio.gather(*(signal.wait() for signal in update_dispatched)),
                        timeout=10,
                    )
                    assert all(not task.done() for task in worker_tasks)

                # Commit the blocking transaction, allowing the workers to race.
                results = await asyncio.wait_for(
                    asyncio.gather(*worker_tasks, return_exceptions=True),
                    timeout=10,
                )
                winners = [result for result in results if isinstance(result, RemediationExecution)]
                refusals = [
                    result
                    for result in results
                    if isinstance(result, RemediationExecutionOutcomeNotAllowedError)
                ]
                assert len(winners) == 1, results
                assert len(refusals) == 1, results

                winner = winners[0]
                winner_index = next(
                    index for index, result in enumerate(results) if result is winner
                )
                assert winner.status is outcomes[winner_index]
                assert winner.execution_id == started.execution_id
                assert winner.claim_id == started.claim_id
                assert winner.started_at == started.started_at
                assert winner.status_changed_at is not None

                # The losing worker cannot modify the committed winner's outcome.
                async with setup_engine.connect() as connection:
                    persisted = (
                        (
                            await connection.execute(
                                sa.select(remediation_executions_table).where(
                                    remediation_executions_table.c.execution_id
                                    == started.execution_id
                                )
                            )
                        )
                        .mappings()
                        .one()
                    )
                assert persisted["status"] == winner.status.value
                assert persisted["status_changed_at"] == winner.status_changed_at
                assert persisted["started_at"] == started.started_at
                assert persisted["claim_id"] == started.claim_id
            finally:
                # Never leave a blocked task or open connection behind on failure.
                for task in worker_tasks:
                    if not task.done():
                        task.cancel()
                if worker_tasks:
                    await asyncio.gather(*worker_tasks, return_exceptions=True)
                for engine, listener in zip(worker_engines, listeners, strict=True):
                    sa.event.remove(engine.sync_engine, "before_cursor_execute", listener)
                    await engine.dispose()

    asyncio.run(run_scenario())


def test_get_by_claim_id_returns_none_for_unknown_claim() -> None:
    async def run_scenario() -> None:
        engine = create_database_engine(DatabaseConfig.from_environment())
        try:
            repository = PostgresRemediationExecutionRepository(engine=engine)
            assert await repository.get_by_claim_id(claim_id=uuid4()) is None
        finally:
            await engine.dispose()

    asyncio.run(run_scenario())


def test_get_by_claim_id_returns_none_when_claim_has_no_execution() -> None:
    async def run_scenario() -> None:
        async with _seed_claims() as (engine, claims):
            claim_id = claims[0].claim_id
            repository = PostgresRemediationExecutionRepository(engine=engine)
            assert await repository.get_by_claim_id(claim_id=claim_id) is None

            async with engine.connect() as connection:
                count = await connection.scalar(
                    sa.select(sa.func.count())
                    .select_from(remediation_executions_table)
                    .where(remediation_executions_table.c.claim_id == claim_id)
                )
            assert count == 0

    asyncio.run(run_scenario())


def test_get_by_claim_id_reads_committed_executing_without_mutation_or_retry() -> None:
    async def run_scenario() -> None:
        async with _seed_claims() as (engine, claims):
            claim_id = claims[0].claim_id
            writer = PostgresRemediationExecutionRepository(engine=engine)
            started = await writer.start_once(claim_id=claim_id)

            # Use a separate engine to prove this is a committed database read.
            reader_engine = create_database_engine(DatabaseConfig.from_environment())
            try:
                reader = PostgresRemediationExecutionRepository(engine=reader_engine)
                first_read = await reader.get_by_claim_id(claim_id=claim_id)
                second_read = await reader.get_by_claim_id(claim_id=claim_id)
                assert first_read == started
                assert second_read == started
                assert first_read is not None
                assert first_read.status is RemediationExecutionStatus.EXECUTING
                assert first_read.status_changed_at is None
                assert first_read.started_at.tzinfo is UTC

                async with reader_engine.connect() as connection:
                    persisted = (
                        (
                            await connection.execute(
                                sa.select(remediation_executions_table).where(
                                    remediation_executions_table.c.claim_id == claim_id
                                )
                            )
                        )
                        .mappings()
                        .one()
                    )
                assert persisted["execution_id"] == started.execution_id
                assert persisted["status"] == "executing"
                assert persisted["status_changed_at"] is None
            finally:
                await reader_engine.dispose()

            # Reading is not a fresh authorization to execute again.
            with pytest.raises(RemediationExecutionAlreadyStartedError):
                await writer.start_once(claim_id=claim_id)

    asyncio.run(run_scenario())


@pytest.mark.parametrize(
    "outcome",
    [
        RemediationExecutionStatus.SUCCEEDED,
        RemediationExecutionStatus.FAILED,
        RemediationExecutionStatus.UNKNOWN,
    ],
)
def test_get_by_claim_id_reconstructs_terminal_status_without_mutation(
    outcome: RemediationExecutionStatus,
) -> None:
    async def run_scenario() -> None:
        async with _seed_claims() as (engine, claims):
            claim_id = claims[0].claim_id
            writer = PostgresRemediationExecutionRepository(engine=engine)
            started = await writer.start_once(claim_id=claim_id)
            finalized = await writer.record_outcome_once(
                execution_id=started.execution_id,
                outcome=outcome,
            )

            reader_engine = create_database_engine(DatabaseConfig.from_environment())
            try:
                reader = PostgresRemediationExecutionRepository(engine=reader_engine)
                loaded = await reader.get_by_claim_id(claim_id=claim_id)
                repeated = await reader.get_by_claim_id(claim_id=claim_id)
                assert loaded == finalized
                assert repeated == finalized
                assert loaded is not None
                assert loaded.status is outcome
                assert loaded.started_at.tzinfo is UTC
                assert loaded.status_changed_at is not None
                assert loaded.status_changed_at.tzinfo is UTC

                async with reader_engine.connect() as connection:
                    persisted = (
                        (
                            await connection.execute(
                                sa.select(remediation_executions_table).where(
                                    remediation_executions_table.c.claim_id == claim_id
                                )
                            )
                        )
                        .mappings()
                        .one()
                    )
                assert persisted["status"] == outcome.value
                assert persisted["started_at"] == finalized.started_at
                assert persisted["status_changed_at"] == finalized.status_changed_at
            finally:
                await reader_engine.dispose()

    asyncio.run(run_scenario())


def test_get_by_claim_id_is_scoped_to_the_requested_claim() -> None:
    async def run_scenario() -> None:
        async with _seed_claims(count=2) as (engine, claims):
            repository = PostgresRemediationExecutionRepository(engine=engine)
            first_claim = claims[0].claim_id
            second_claim = claims[1].claim_id
            first = await repository.start_once(claim_id=first_claim)

            assert await repository.get_by_claim_id(claim_id=first_claim) == first
            assert await repository.get_by_claim_id(claim_id=second_claim) is None

            second = await repository.start_once(claim_id=second_claim)
            finalized = await repository.record_outcome_once(
                execution_id=first.execution_id,
                outcome=RemediationExecutionStatus.UNKNOWN,
            )

            assert await repository.get_by_claim_id(claim_id=first_claim) == finalized
            assert await repository.get_by_claim_id(claim_id=second_claim) == second

    asyncio.run(run_scenario())


def test_start_once_allows_only_one_concurrent_winner() -> None:
    """Two workers racing for one claim must not both start execution.

    A third transaction holds the claim row lock while both independent
    workers dispatch SELECT ... FOR UPDATE. Neither may finish before release.
    """

    async def run_scenario() -> None:
        async with _seed_claims() as (setup_engine, claims):
            claim_id = claims[0].claim_id
            config = DatabaseConfig.from_environment()
            worker_engines = (
                create_database_engine(config),
                create_database_engine(config),
            )
            lock_dispatched = (asyncio.Event(), asyncio.Event())
            worker_tasks: list[asyncio.Task[RemediationExecution]] = []

            def make_lock_listener(signal: asyncio.Event) -> Callable[..., None]:
                def on_before_execute(
                    _connection: object,
                    _cursor: object,
                    statement: str,
                    _parameters: object,
                    _context: object,
                    _executemany: bool,
                ) -> None:
                    sql = " ".join(statement.lower().split())
                    if (
                        sql.startswith("select ")
                        and "from remediation_execution_claims" in sql
                        and "for update" in sql
                    ):
                        signal.set()

                return on_before_execute

            listeners = tuple(make_lock_listener(signal) for signal in lock_dispatched)
            for engine, listener in zip(worker_engines, listeners, strict=True):
                sa.event.listen(engine.sync_engine, "before_cursor_execute", listener)

            try:
                # Block both workers on the same durable claim before scheduling.
                async with setup_engine.begin() as blocker:
                    locked = await blocker.scalar(
                        sa.select(execution_claims_table.c.claim_id)
                        .where(execution_claims_table.c.claim_id == claim_id)
                        .with_for_update()
                    )
                    assert locked == claim_id

                    for engine in worker_engines:
                        repository = PostgresRemediationExecutionRepository(engine=engine)
                        worker_tasks.append(
                            asyncio.create_task(repository.start_once(claim_id=claim_id))
                        )

                    # SQL dispatch is not completion. The blocker still owns
                    # the row lock, so both workers must remain pending.
                    await asyncio.wait_for(
                        asyncio.gather(*(signal.wait() for signal in lock_dispatched)),
                        timeout=10,
                    )
                    assert all(not task.done() for task in worker_tasks)

                # Release the row lock; one transaction must win the INSERT.
                results = await asyncio.wait_for(
                    asyncio.gather(*worker_tasks, return_exceptions=True),
                    timeout=10,
                )
                winners = [result for result in results if isinstance(result, RemediationExecution)]
                refusals = [
                    result
                    for result in results
                    if isinstance(result, RemediationExecutionAlreadyStartedError)
                ]
                assert len(winners) == 1, results
                assert len(refusals) == 1, results

                winner = winners[0]
                assert winner.claim_id == claim_id
                assert winner.status is RemediationExecutionStatus.EXECUTING
                assert winner.status_changed_at is None
                assert winner.started_at.tzinfo is UTC

                # Verify committed state via a separate connection.
                async with setup_engine.connect() as connection:
                    rows = (
                        (
                            await connection.execute(
                                sa.select(remediation_executions_table).where(
                                    remediation_executions_table.c.claim_id == claim_id
                                )
                            )
                        )
                        .mappings()
                        .all()
                    )
                assert len(rows) == 1
                assert rows[0]["execution_id"] == winner.execution_id
                assert rows[0]["claim_id"] == claim_id
                assert rows[0]["status"] == "executing"
                assert rows[0]["started_at"] == winner.started_at
                assert rows[0]["status_changed_at"] is None

                reader = PostgresRemediationExecutionRepository(engine=setup_engine)
                assert await reader.get_by_claim_id(claim_id=claim_id) == winner
            finally:
                # Even if the test fails, never leave blocked workers behind.
                for task in worker_tasks:
                    if not task.done():
                        task.cancel()
                if worker_tasks:
                    await asyncio.gather(*worker_tasks, return_exceptions=True)
                for engine, listener in zip(worker_engines, listeners, strict=True):
                    sa.event.remove(engine.sync_engine, "before_cursor_execute", listener)
                    await engine.dispose()

    asyncio.run(run_scenario())
