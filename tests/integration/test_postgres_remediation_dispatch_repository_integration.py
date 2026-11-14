"""Opt-in PostgreSQL integration tests for durable MCP dispatch reservations."""

import asyncio
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncEngine

from ai_incident_commander.application.approval_execution_guard import VerifiedExecutionScope
from ai_incident_commander.application.remediation_dispatch_repository import (
    RemediationDispatchAlreadyReservedError,
    RemediationDispatchApprovalDeniedError,
    RemediationDispatchExecutionNotExecutingError,
    RemediationDispatchExecutionNotFoundError,
    RemediationDispatchScopeMismatchError,
)
from ai_incident_commander.domain.remediation_approval import (
    RemediationApprovalDecision,
    RemediationApprovalOutcome,
    RemediationApprovalRequest,
)
from ai_incident_commander.domain.remediation_dispatch import RemediationDispatch
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
from ai_incident_commander.infrastructure.execution_claim_tables import execution_claims_table
from ai_incident_commander.infrastructure.postgres_approval_repository import (
    PostgresApprovalRepository,
)
from ai_incident_commander.infrastructure.postgres_execution_claim_repository import (
    PostgresExecutionClaimRepository,
)
from ai_incident_commander.infrastructure.postgres_remediation_dispatch_repository import (
    PostgresRemediationDispatchRepository,
)
from ai_incident_commander.infrastructure.postgres_remediation_execution_repository import (
    PostgresRemediationExecutionRepository,
)
from ai_incident_commander.infrastructure.remediation_dispatch_tables import (
    remediation_dispatches_table,
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
        value = await connection.scalar(sa.select(sa.func.clock_timestamp()))
    assert isinstance(value, datetime)
    return value.astimezone(UTC)


@asynccontextmanager
async def _seed_executions(
    count: int = 1,
) -> AsyncIterator[tuple[AsyncEngine, tuple[RemediationExecution, ...]]]:
    """Create real approved executions; remove only this scenario's records."""
    engine = create_database_engine(DatabaseConfig.from_environment())
    request_ids: list[UUID] = []
    executions: list[RemediationExecution] = []
    try:
        approvals = PostgresApprovalRepository(engine=engine)
        claims = PostgresExecutionClaimRepository(engine=engine)
        lifecycle = PostgresRemediationExecutionRepository(engine=engine)
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
            request_ids.append(request.request_id)
            await approvals.create_request(request)
            await approvals.record_decision_once(
                RemediationApprovalDecision(
                    request_id=request.request_id,
                    operator_id="dispatch-integration-operator",
                    outcome=RemediationApprovalOutcome.APPROVED,
                    decided_at=await _database_now(engine),
                    reason="Approved for durable dispatch integration test.",
                )
            )
            claim = await claims.claim_once(
                request_id=request.request_id,
                plan_id=request.plan_id,
                step_id=request.step_id,
                action_fingerprint=request.action_fingerprint,
                policy_version=request.policy_version,
            )
            executions.append(await lifecycle.start_once(claim_id=claim.claim_id))

        yield engine, tuple(executions)
    finally:
        try:
            if request_ids:
                async with engine.begin() as connection:
                    claim_ids = sa.select(execution_claims_table.c.claim_id).where(
                        execution_claims_table.c.request_id.in_(request_ids)
                    )
                    execution_ids = sa.select(remediation_executions_table.c.execution_id).where(
                        remediation_executions_table.c.claim_id.in_(claim_ids)
                    )
                    # FK RESTRICT: dispatch -> execution -> claim -> decision -> request.
                    await connection.execute(
                        sa.delete(remediation_dispatches_table).where(
                            remediation_dispatches_table.c.execution_id.in_(execution_ids)
                        )
                    )
                    await connection.execute(
                        sa.delete(remediation_executions_table).where(
                            remediation_executions_table.c.claim_id.in_(claim_ids)
                        )
                    )
                    await connection.execute(
                        sa.delete(execution_claims_table).where(
                            execution_claims_table.c.request_id.in_(request_ids)
                        )
                    )
                    await connection.execute(
                        sa.delete(approval_decisions_table).where(
                            approval_decisions_table.c.request_id.in_(request_ids)
                        )
                    )
                    await connection.execute(
                        sa.delete(approval_requests_table).where(
                            approval_requests_table.c.request_id.in_(request_ids)
                        )
                    )
        finally:
            await engine.dispose()


async def _dispatch_count(engine: AsyncEngine, execution_id: UUID) -> int:
    async with engine.connect() as connection:
        count = await connection.scalar(
            sa.select(sa.func.count())
            .select_from(remediation_dispatches_table)
            .where(remediation_dispatches_table.c.execution_id == execution_id)
        )
    assert isinstance(count, int)
    return count


def test_reserve_once_commits_one_dispatch_using_postgres_clock() -> None:
    async def run_scenario() -> None:
        async with _seed_executions() as (engine, executions):
            repository = PostgresRemediationDispatchRepository(engine=engine)
            before = await _database_now(engine)
            dispatch = await repository.reserve_once(execution_id=executions[0].execution_id)
            after = await _database_now(engine)

            assert isinstance(dispatch, RemediationDispatch)
            assert dispatch.execution_id == executions[0].execution_id
            assert dispatch.reserved_at.tzinfo is UTC
            assert before <= dispatch.reserved_at <= after
            assert await _dispatch_count(engine, executions[0].execution_id) == 1

            # Separate connection observes the committed reservation.
            async with engine.connect() as connection:
                persisted = (
                    (
                        await connection.execute(
                            sa.select(remediation_dispatches_table).where(
                                remediation_dispatches_table.c.execution_id
                                == executions[0].execution_id
                            )
                        )
                    )
                    .mappings()
                    .one()
                )
            assert persisted["dispatch_id"] == dispatch.dispatch_id
            assert persisted["reserved_at"] == dispatch.reserved_at

    asyncio.run(run_scenario())


def test_reserve_once_denies_missing_execution() -> None:
    async def run_scenario() -> None:
        async with _seed_executions() as (engine, _):
            repository = PostgresRemediationDispatchRepository(engine=engine)
            missing = uuid4()
            with pytest.raises(RemediationDispatchExecutionNotFoundError):
                await repository.reserve_once(execution_id=missing)
            assert await _dispatch_count(engine, missing) == 0

    asyncio.run(run_scenario())


def test_reserve_once_denies_identical_retry_without_modifying_first() -> None:
    async def run_scenario() -> None:
        async with _seed_executions() as (engine, executions):
            execution = executions[0]
            repository = PostgresRemediationDispatchRepository(engine=engine)
            first = await repository.reserve_once(execution_id=execution.execution_id)
            with pytest.raises(RemediationDispatchAlreadyReservedError):
                await repository.reserve_once(execution_id=execution.execution_id)

            assert await _dispatch_count(engine, execution.execution_id) == 1
            stored = await repository.get_by_execution_id(execution_id=execution.execution_id)
            assert stored == first

    asyncio.run(run_scenario())


def test_reserve_once_keeps_distinct_executions_independent() -> None:
    async def run_scenario() -> None:
        async with _seed_executions(count=2) as (engine, executions):
            repository = PostgresRemediationDispatchRepository(engine=engine)
            first = await repository.reserve_once(execution_id=executions[0].execution_id)
            second = await repository.reserve_once(execution_id=executions[1].execution_id)

            assert first.dispatch_id != second.dispatch_id
            assert first.execution_id != second.execution_id
            assert await _dispatch_count(engine, first.execution_id) == 1
            assert await _dispatch_count(engine, second.execution_id) == 1

    asyncio.run(run_scenario())


@pytest.mark.parametrize(
    "outcome",
    (
        RemediationExecutionStatus.SUCCEEDED,
        RemediationExecutionStatus.FAILED,
        RemediationExecutionStatus.UNKNOWN,
    ),
)
def test_reserve_once_refuses_terminal_or_unknown_execution(
    outcome: RemediationExecutionStatus,
) -> None:
    async def run_scenario() -> None:
        async with _seed_executions() as (engine, executions):
            execution_id = executions[0].execution_id
            lifecycle = PostgresRemediationExecutionRepository(engine=engine)
            await lifecycle.record_outcome_once(execution_id=execution_id, outcome=outcome)
            repository = PostgresRemediationDispatchRepository(engine=engine)
            with pytest.raises(RemediationDispatchExecutionNotExecutingError):
                await repository.reserve_once(execution_id=execution_id)
            assert await _dispatch_count(engine, execution_id) == 0

    asyncio.run(run_scenario())


def test_get_by_execution_id_returns_none_for_unknown_execution() -> None:
    async def run_scenario() -> None:
        async with _seed_executions() as (engine, _):
            repository = PostgresRemediationDispatchRepository(engine=engine)
            assert await repository.get_by_execution_id(execution_id=uuid4()) is None

    asyncio.run(run_scenario())


def test_get_by_execution_id_returns_none_before_reservation() -> None:
    async def run_scenario() -> None:
        async with _seed_executions() as (engine, executions):
            repository = PostgresRemediationDispatchRepository(engine=engine)
            execution_id = executions[0].execution_id
            assert await repository.get_by_execution_id(execution_id=execution_id) is None
            assert await _dispatch_count(engine, execution_id) == 0

    asyncio.run(run_scenario())


def test_get_by_execution_id_reads_committed_reservation_without_regranting() -> None:
    async def run_scenario() -> None:
        async with _seed_executions() as (engine, executions):
            repository = PostgresRemediationDispatchRepository(engine=engine)
            execution_id = executions[0].execution_id
            initial = await repository.reserve_once(execution_id=execution_id)

            assert await repository.get_by_execution_id(execution_id=execution_id) == initial
            assert await repository.get_by_execution_id(execution_id=execution_id) == initial
            with pytest.raises(RemediationDispatchAlreadyReservedError):
                await repository.reserve_once(execution_id=execution_id)
            assert await _dispatch_count(engine, execution_id) == 1

    asyncio.run(run_scenario())


def test_committed_reservation_remains_readable_after_terminal_outcome() -> None:
    async def run_scenario() -> None:
        async with _seed_executions() as (engine, executions):
            execution_id = executions[0].execution_id
            repository = PostgresRemediationDispatchRepository(engine=engine)
            reserved = await repository.reserve_once(execution_id=execution_id)
            lifecycle = PostgresRemediationExecutionRepository(engine=engine)
            await lifecycle.record_outcome_once(
                execution_id=execution_id,
                outcome=RemediationExecutionStatus.UNKNOWN,
            )

            assert await repository.get_by_execution_id(execution_id=execution_id) == reserved
            with pytest.raises(RemediationDispatchExecutionNotExecutingError):
                await repository.reserve_once(execution_id=execution_id)
            assert await _dispatch_count(engine, execution_id) == 1

    asyncio.run(run_scenario())


async def _compete_while_execution_row_is_locked(
    *,
    setup_engine: AsyncEngine,
    execution_id: UUID,
    second_operation: str,
    verified_scope: VerifiedExecutionScope | None = None,
) -> tuple[object, object]:
    """Make two independent workers reach the same locked PostgreSQL row.

    Statement listeners signal that each worker has issued its locking SQL.
    The blocker holds the execution row until both attempts are outstanding.
    No timing-based sleep determines when the lock is released.
    """
    config = DatabaseConfig.from_environment()
    worker_engines = (create_database_engine(config), create_database_engine(config))
    statements_issued = (asyncio.Event(), asyncio.Event())
    workers: list[asyncio.Task[object]] = []

    def make_listener(signal: asyncio.Event, *, outcome_update: bool = False):
        def before_cursor_execute(
            _connection: object,
            _cursor: object,
            statement: str,
            _parameters: object,
            _context: object,
            _executemany: bool,
        ) -> None:
            sql = " ".join(statement.upper().split())
            if outcome_update:
                if sql.startswith("UPDATE REMEDIATION_EXECUTIONS "):
                    signal.set()
            elif "FROM REMEDIATION_EXECUTIONS" in sql and "FOR UPDATE" in sql:
                signal.set()

        return before_cursor_execute

    listeners = (
        make_listener(statements_issued[0]),
        make_listener(statements_issued[1], outcome_update=second_operation == "outcome"),
    )
    registered = []

    try:
        for engine, listener in zip(worker_engines, listeners, strict=True):
            sa.event.listen(engine.sync_engine, "before_cursor_execute", listener)
            registered.append((engine, listener))

        first_repository = PostgresRemediationDispatchRepository(engine=worker_engines[0])
        second_repository = PostgresRemediationDispatchRepository(engine=worker_engines[1])
        async with setup_engine.begin() as blocker:
            locked_id = await blocker.scalar(
                sa.select(remediation_executions_table.c.execution_id)
                .where(remediation_executions_table.c.execution_id == execution_id)
                .with_for_update()
            )
            assert locked_id == execution_id

            if verified_scope is None:
                first_attempt = first_repository.reserve_once(execution_id=execution_id)
            else:
                first_attempt = first_repository.reserve_verified_once(
                    execution_id=execution_id, verified_scope=verified_scope
                )

            if second_operation == "outcome":
                second_attempt = PostgresRemediationExecutionRepository(
                    engine=worker_engines[1]
                ).record_outcome_once(
                    execution_id=execution_id,
                    outcome=RemediationExecutionStatus.UNKNOWN,
                )
            elif verified_scope is None:
                second_attempt = second_repository.reserve_once(execution_id=execution_id)
            else:
                second_attempt = second_repository.reserve_verified_once(
                    execution_id=execution_id, verified_scope=verified_scope
                )

            workers = [
                asyncio.create_task(first_attempt),
                asyncio.create_task(second_attempt),
            ]
            await asyncio.wait_for(
                asyncio.gather(*(signal.wait() for signal in statements_issued)),
                timeout=10,
            )
            assert all(not worker.done() for worker in workers)

        # Releasing the database lock permits the workers to compete for it.
        results = await asyncio.wait_for(
            asyncio.gather(*workers, return_exceptions=True), timeout=10
        )
        return results[0], results[1]
    finally:
        for worker in workers:
            if not worker.done():
                worker.cancel()
        if workers:
            await asyncio.gather(*workers, return_exceptions=True)
        for engine, listener in registered:
            sa.event.remove(engine.sync_engine, "before_cursor_execute", listener)
        for engine in worker_engines:
            await engine.dispose()


def test_concurrent_reserve_once_commits_exactly_one_dispatch() -> None:
    """Two independent workers cannot reserve the same EXECUTING attempt twice."""

    async def run_scenario() -> None:
        async with _seed_executions() as (engine, executions):
            execution_id = executions[0].execution_id
            results = await _compete_while_execution_row_is_locked(
                setup_engine=engine,
                execution_id=execution_id,
                second_operation="reserve",
            )
            winners = [result for result in results if isinstance(result, RemediationDispatch)]
            refusals = [
                result
                for result in results
                if isinstance(result, RemediationDispatchAlreadyReservedError)
            ]
            assert len(winners) == 1, results
            assert len(refusals) == 1, results

            stored = await PostgresRemediationDispatchRepository(engine=engine).get_by_execution_id(
                execution_id=execution_id
            )
            assert stored == winners[0]
            assert stored is not None
            assert stored.execution_id == execution_id
            assert stored.reserved_at.tzinfo is UTC
            assert await _dispatch_count(engine, execution_id) == 1

    asyncio.run(run_scenario())


def test_concurrent_reservation_and_outcome_respect_execution_row_lock() -> None:
    """An outcome winner denies reservation; a reservation winner persists once."""

    async def run_scenario() -> None:
        async with _seed_executions() as (engine, executions):
            execution_id = executions[0].execution_id
            reservation_result, outcome_result = await _compete_while_execution_row_is_locked(
                setup_engine=engine,
                execution_id=execution_id,
                second_operation="outcome",
            )
            assert isinstance(outcome_result, RemediationExecution), (
                reservation_result,
                outcome_result,
            )
            assert outcome_result.status is RemediationExecutionStatus.UNKNOWN
            assert outcome_result.execution_id == execution_id
            persisted_execution = await PostgresRemediationExecutionRepository(
                engine=engine
            ).get_by_claim_id(claim_id=executions[0].claim_id)
            assert persisted_execution == outcome_result

            repository = PostgresRemediationDispatchRepository(engine=engine)
            stored = await repository.get_by_execution_id(execution_id=execution_id)
            if isinstance(reservation_result, RemediationDispatch):
                # Reservation acquired the lock before the conditional outcome UPDATE.
                assert stored == reservation_result
                assert await _dispatch_count(engine, execution_id) == 1
            else:
                # Outcome acquired the lock first, so reserve_once saw UNKNOWN.
                assert isinstance(
                    reservation_result, RemediationDispatchExecutionNotExecutingError
                ), (reservation_result, outcome_result)
                assert stored is None
                assert await _dispatch_count(engine, execution_id) == 0

            # Once the outcome is terminal, neither ordering permits another dispatch.
            with pytest.raises(RemediationDispatchExecutionNotExecutingError):
                await repository.reserve_once(execution_id=execution_id)

    asyncio.run(run_scenario())


async def _scope_for_execution(
    engine: AsyncEngine, execution: RemediationExecution
) -> VerifiedExecutionScope:
    """Test-only scope fixture derived from a real persisted claim, not a Guard token."""
    async with engine.connect() as connection:
        claim = (
            (
                await connection.execute(
                    sa.select(execution_claims_table).where(
                        execution_claims_table.c.claim_id == execution.claim_id
                    )
                )
            )
            .mappings()
            .one()
        )
    return VerifiedExecutionScope(
        request_id=claim["request_id"],
        plan_id=claim["plan_id"],
        step_id=claim["step_id"],
        action_fingerprint=claim["action_fingerprint"],
        policy_version=claim["policy_version"],
    )


def test_verified_reservation_commits_one_dispatch_for_matching_scope() -> None:
    async def scenario() -> None:
        async with _seed_executions() as (engine, executions):
            execution = executions[0]
            verified_scope = await _scope_for_execution(engine, execution)
            repository = PostgresRemediationDispatchRepository(engine=engine)
            before = await _database_now(engine)
            reserved = await repository.reserve_verified_once(
                execution_id=execution.execution_id, verified_scope=verified_scope
            )
            after = await _database_now(engine)
            assert reserved.execution_id == execution.execution_id
            assert before <= reserved.reserved_at <= after
            assert (
                await repository.get_by_execution_id(execution_id=execution.execution_id)
                == reserved
            )
            assert await _dispatch_count(engine, execution.execution_id) == 1

    asyncio.run(scenario())


def test_verified_reservation_rejects_scope_from_another_execution() -> None:
    async def scenario() -> None:
        async with _seed_executions(count=2) as (engine, executions):
            scope_a = await _scope_for_execution(engine, executions[0])
            repository = PostgresRemediationDispatchRepository(engine=engine)
            with pytest.raises(RemediationDispatchScopeMismatchError):
                await repository.reserve_verified_once(
                    execution_id=executions[1].execution_id, verified_scope=scope_a
                )
            assert await _dispatch_count(engine, executions[0].execution_id) == 0
            assert await _dispatch_count(engine, executions[1].execution_id) == 0
            # A rejected cross-binding attempt must not consume B's reservation.
            scope_b = await _scope_for_execution(engine, executions[1])
            winner = await repository.reserve_verified_once(
                execution_id=executions[1].execution_id, verified_scope=scope_b
            )
            assert winner.execution_id == executions[1].execution_id

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "field_name,wrong_value",
    [
        ("request_id", uuid4()),
        ("plan_id", uuid4()),
        ("step_id", uuid4()),
        ("action_fingerprint", "afp:v2:" + "c" * 64),
        ("policy_version", "apv:v1:" + "d" * 64),
    ],
)
def test_verified_reservation_rejects_each_scope_mismatch(
    field_name: str, wrong_value: object
) -> None:
    async def scenario() -> None:
        async with _seed_executions() as (engine, executions):
            execution = executions[0]
            original = await _scope_for_execution(engine, execution)
            tampered = replace(original, **{field_name: wrong_value})
            repository = PostgresRemediationDispatchRepository(engine=engine)
            with pytest.raises(RemediationDispatchScopeMismatchError):
                await repository.reserve_verified_once(
                    execution_id=execution.execution_id, verified_scope=tampered
                )
            assert await _dispatch_count(engine, execution.execution_id) == 0

    asyncio.run(scenario())


def test_verified_reservation_rejects_rejected_approval() -> None:
    async def scenario() -> None:
        async with _seed_executions() as (engine, executions):
            execution = executions[0]
            scope = await _scope_for_execution(engine, execution)
            async with engine.begin() as connection:
                await connection.execute(
                    sa.update(approval_decisions_table)
                    .where(approval_decisions_table.c.request_id == scope.request_id)
                    .values(outcome=RemediationApprovalOutcome.REJECTED.value)
                )
            repository = PostgresRemediationDispatchRepository(engine=engine)
            with pytest.raises(RemediationDispatchApprovalDeniedError):
                await repository.reserve_verified_once(
                    execution_id=execution.execution_id, verified_scope=scope
                )
            assert await _dispatch_count(engine, execution.execution_id) == 0

    asyncio.run(scenario())


@pytest.mark.parametrize("timestamp_column", ("decided_at", "recorded_at"))
def test_verified_reservation_rejects_invalid_approval_window(timestamp_column: str) -> None:
    async def scenario() -> None:
        async with _seed_executions() as (engine, executions):
            execution = executions[0]
            scope = await _scope_for_execution(engine, execution)
            async with engine.begin() as connection:
                expires_at = await connection.scalar(
                    sa.select(approval_requests_table.c.expires_at).where(
                        approval_requests_table.c.request_id == scope.request_id
                    )
                )
                assert isinstance(expires_at, datetime)
                await connection.execute(
                    sa.update(approval_decisions_table)
                    .where(approval_decisions_table.c.request_id == scope.request_id)
                    .values({timestamp_column: expires_at})
                )
            repository = PostgresRemediationDispatchRepository(engine=engine)
            with pytest.raises(RemediationDispatchApprovalDeniedError):
                await repository.reserve_verified_once(
                    execution_id=execution.execution_id, verified_scope=scope
                )
            assert await _dispatch_count(engine, execution.execution_id) == 0

    asyncio.run(scenario())


def test_verified_reservation_rejects_missing_decision() -> None:
    async def scenario() -> None:
        async with _seed_executions() as (engine, executions):
            execution = executions[0]
            scope = await _scope_for_execution(engine, execution)
            async with engine.begin() as connection:
                await connection.execute(
                    sa.delete(approval_decisions_table).where(
                        approval_decisions_table.c.request_id == scope.request_id
                    )
                )
            repository = PostgresRemediationDispatchRepository(engine=engine)
            with pytest.raises(RemediationDispatchApprovalDeniedError):
                await repository.reserve_verified_once(
                    execution_id=execution.execution_id, verified_scope=scope
                )
            assert await _dispatch_count(engine, execution.execution_id) == 0

    asyncio.run(scenario())


def test_verified_reservation_rejects_inconsistent_persisted_claim() -> None:
    async def scenario() -> None:
        async with _seed_executions() as (engine, executions):
            execution = executions[0]
            scope = await _scope_for_execution(engine, execution)
            async with engine.begin() as connection:
                await connection.execute(
                    sa.update(execution_claims_table)
                    .where(execution_claims_table.c.claim_id == execution.claim_id)
                    .values(action_fingerprint="afp:v2:" + "e" * 64)
                )
            repository = PostgresRemediationDispatchRepository(engine=engine)
            with pytest.raises(RemediationDispatchApprovalDeniedError):
                await repository.reserve_verified_once(
                    execution_id=execution.execution_id, verified_scope=scope
                )
            assert await _dispatch_count(engine, execution.execution_id) == 0

    asyncio.run(scenario())


def test_verified_reservation_rejects_duplicate_after_success() -> None:
    async def scenario() -> None:
        async with _seed_executions() as (engine, executions):
            execution = executions[0]
            scope = await _scope_for_execution(engine, execution)
            repository = PostgresRemediationDispatchRepository(engine=engine)
            initial = await repository.reserve_verified_once(
                execution_id=execution.execution_id, verified_scope=scope
            )
            with pytest.raises(RemediationDispatchAlreadyReservedError):
                await repository.reserve_verified_once(
                    execution_id=execution.execution_id, verified_scope=scope
                )
            assert (
                await repository.get_by_execution_id(execution_id=execution.execution_id) == initial
            )
            assert await _dispatch_count(engine, execution.execution_id) == 1

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "outcome",
    (
        RemediationExecutionStatus.SUCCEEDED,
        RemediationExecutionStatus.FAILED,
        RemediationExecutionStatus.UNKNOWN,
    ),
)
def test_verified_reservation_rejects_non_executing_status(
    outcome: RemediationExecutionStatus,
) -> None:
    async def scenario() -> None:
        async with _seed_executions() as (engine, executions):
            execution = executions[0]
            scope = await _scope_for_execution(engine, execution)
            await PostgresRemediationExecutionRepository(engine=engine).record_outcome_once(
                execution_id=execution.execution_id, outcome=outcome
            )
            repository = PostgresRemediationDispatchRepository(engine=engine)
            with pytest.raises(RemediationDispatchExecutionNotExecutingError):
                await repository.reserve_verified_once(
                    execution_id=execution.execution_id, verified_scope=scope
                )
            assert await _dispatch_count(engine, execution.execution_id) == 0

    asyncio.run(scenario())


def test_verified_reservation_rejects_missing_execution() -> None:
    async def scenario() -> None:
        async with _seed_executions() as (engine, executions):
            scope = await _scope_for_execution(engine, executions[0])
            missing_id = uuid4()
            repository = PostgresRemediationDispatchRepository(engine=engine)
            with pytest.raises(RemediationDispatchExecutionNotFoundError):
                await repository.reserve_verified_once(
                    execution_id=missing_id, verified_scope=scope
                )
            assert await _dispatch_count(engine, missing_id) == 0

    asyncio.run(scenario())


def test_concurrent_verified_reserve_once_commits_exactly_one_dispatch() -> None:
    """Two workers with the same approved scope must not reserve twice."""

    async def run_scenario() -> None:
        async with _seed_executions() as (engine, executions):
            execution = executions[0]
            execution_id = execution.execution_id
            verified_scope = await _scope_for_execution(engine, execution)

            results = await _compete_while_execution_row_is_locked(
                setup_engine=engine,
                execution_id=execution_id,
                second_operation="reserve",
                verified_scope=verified_scope,
            )
            winners = [result for result in results if isinstance(result, RemediationDispatch)]
            refusals = [
                result
                for result in results
                if isinstance(result, RemediationDispatchAlreadyReservedError)
            ]
            assert len(winners) == 1, results
            assert len(refusals) == 1, results

            repository = PostgresRemediationDispatchRepository(engine=engine)
            stored = await repository.get_by_execution_id(execution_id=execution_id)
            assert stored == winners[0]
            assert stored is not None
            assert stored.execution_id == execution_id
            assert stored.reserved_at.tzinfo is UTC
            assert await _dispatch_count(engine, execution_id) == 1

            with pytest.raises(RemediationDispatchAlreadyReservedError):
                await repository.reserve_verified_once(
                    execution_id=execution_id, verified_scope=verified_scope
                )

    asyncio.run(run_scenario())


def test_concurrent_verified_reservation_and_outcome_respect_execution_row_lock() -> None:
    """A terminal outcome prevents a late verified reservation."""

    async def run_scenario() -> None:
        async with _seed_executions() as (engine, executions):
            execution = executions[0]
            execution_id = execution.execution_id
            verified_scope = await _scope_for_execution(engine, execution)

            reservation_result, outcome_result = await _compete_while_execution_row_is_locked(
                setup_engine=engine,
                execution_id=execution_id,
                second_operation="outcome",
                verified_scope=verified_scope,
            )
            assert isinstance(outcome_result, RemediationExecution), (
                reservation_result,
                outcome_result,
            )
            assert outcome_result.execution_id == execution_id
            assert outcome_result.status is RemediationExecutionStatus.UNKNOWN

            lifecycle = PostgresRemediationExecutionRepository(engine=engine)
            assert await lifecycle.get_by_claim_id(claim_id=execution.claim_id) == outcome_result

            repository = PostgresRemediationDispatchRepository(engine=engine)
            stored = await repository.get_by_execution_id(execution_id=execution_id)
            if isinstance(reservation_result, RemediationDispatch):
                # Verified reservation committed first; the outcome followed.
                assert stored == reservation_result
                assert await _dispatch_count(engine, execution_id) == 1
            else:
                # Outcome committed first; a stale EXECUTING view was not accepted.
                assert isinstance(
                    reservation_result, RemediationDispatchExecutionNotExecutingError
                ), (reservation_result, outcome_result)
                assert stored is None
                assert await _dispatch_count(engine, execution_id) == 0

            with pytest.raises(RemediationDispatchExecutionNotExecutingError):
                await repository.reserve_verified_once(
                    execution_id=execution_id, verified_scope=verified_scope
                )

    asyncio.run(run_scenario())
