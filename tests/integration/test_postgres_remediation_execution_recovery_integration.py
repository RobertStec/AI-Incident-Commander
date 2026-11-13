"""Opt-in PostgreSQL tests for atomic, fail-closed execution-claim recovery."""

import asyncio
import os
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncEngine

from ai_incident_commander.application.approval_execution_guard import VerifiedExecutionScope
from ai_incident_commander.application.remediation_execution_repository import (
    RemediationExecutionAlreadyStartedError,
    RemediationExecutionClaimNotFoundError,
    RemediationExecutionRecoveryApprovalDeniedError,
    RemediationExecutionRecoveryScopeMismatchError,
    RemediationExecutionRecoveryWindowNotSatisfiedError,
)
from ai_incident_commander.domain.execution_claim import ExecutionClaim
from ai_incident_commander.domain.execution_claim_recovery_policy import (
    ExecutionClaimRecoveryWindowPolicy,
)
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
from ai_incident_commander.infrastructure.execution_claim_tables import execution_claims_table
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


def _scope(claim: ExecutionClaim) -> VerifiedExecutionScope:
    return VerifiedExecutionScope(
        request_id=claim.request_id,
        plan_id=claim.plan_id,
        step_id=claim.step_id,
        action_fingerprint=claim.action_fingerprint,
        policy_version=claim.policy_version,
    )


def _policy() -> ExecutionClaimRecoveryWindowPolicy:
    return ExecutionClaimRecoveryWindowPolicy(max_claim_age=timedelta(minutes=10))


async def _database_now(engine: AsyncEngine) -> datetime:
    async with engine.connect() as connection:
        value = await connection.scalar(sa.select(sa.func.clock_timestamp()))
    assert isinstance(value, datetime)
    return value.astimezone(UTC)


@asynccontextmanager
async def _approved_claim() -> AsyncIterator[tuple[AsyncEngine, ExecutionClaim]]:
    """Commit a real approved claim and remove only this test's records."""
    engine = create_database_engine(DatabaseConfig.from_environment())
    now = await _database_now(engine)
    request = RemediationApprovalRequest(
        plan_id=uuid4(),
        step_id=uuid4(),
        action_fingerprint=_FINGERPRINT,
        policy_version=_POLICY_VERSION,
        requested_at=now - timedelta(minutes=5),
        expires_at=now + timedelta(minutes=25),
    )
    try:
        approvals = PostgresApprovalRepository(engine=engine)
        claims = PostgresExecutionClaimRepository(engine=engine)
        await approvals.create_request(request)
        await approvals.record_decision_once(
            RemediationApprovalDecision(
                request_id=request.request_id,
                operator_id="recovery-integration-operator",
                outcome=RemediationApprovalOutcome.APPROVED,
                decided_at=await _database_now(engine),
                reason="Approved for execution recovery integration test.",
            )
        )
        claim = await claims.claim_once(
            request_id=request.request_id,
            plan_id=request.plan_id,
            step_id=request.step_id,
            action_fingerprint=request.action_fingerprint,
            policy_version=request.policy_version,
        )
        yield engine, claim
    finally:
        try:
            async with engine.begin() as connection:
                # FK RESTRICT: execution -> claim -> approval decision -> request.
                await connection.execute(
                    sa.delete(remediation_executions_table).where(
                        remediation_executions_table.c.claim_id.in_(
                            sa.select(execution_claims_table.c.claim_id).where(
                                execution_claims_table.c.request_id == request.request_id
                            )
                        )
                    )
                )
                await connection.execute(
                    sa.delete(execution_claims_table).where(
                        execution_claims_table.c.request_id == request.request_id
                    )
                )
                await connection.execute(
                    sa.delete(approval_decisions_table).where(
                        approval_decisions_table.c.request_id == request.request_id
                    )
                )
                await connection.execute(
                    sa.delete(approval_requests_table).where(
                        approval_requests_table.c.request_id == request.request_id
                    )
                )
        finally:
            await engine.dispose()


async def _execution_count(engine: AsyncEngine, claim_id: UUID) -> int:
    async with engine.connect() as connection:
        result = await connection.scalar(
            sa.select(sa.func.count())
            .select_from(remediation_executions_table)
            .where(remediation_executions_table.c.claim_id == claim_id)
        )
    assert isinstance(result, int)
    return result


def test_recovery_commits_exactly_one_executing_attempt_with_database_clock() -> None:
    async def run_scenario() -> None:
        async with _approved_claim() as (engine, claim):
            repository = PostgresRemediationExecutionRepository(engine=engine)
            before = await _database_now(engine)
            execution = await repository.start_recovered_once(
                claim_id=claim.claim_id,
                verified_scope=_scope(claim),
                recovery_policy=_policy(),
            )
            after = await _database_now(engine)
            assert execution.claim_id == claim.claim_id
            assert execution.status is RemediationExecutionStatus.EXECUTING
            assert execution.status_changed_at is None
            assert execution.started_at.tzinfo is UTC
            assert before <= execution.started_at <= after
            assert await _execution_count(engine, claim.claim_id) == 1
            assert await repository.get_by_claim_id(claim_id=claim.claim_id) == execution

            with pytest.raises(RemediationExecutionAlreadyStartedError):
                await repository.start_recovered_once(
                    claim_id=claim.claim_id,
                    verified_scope=_scope(claim),
                    recovery_policy=_policy(),
                )
            assert await _execution_count(engine, claim.claim_id) == 1

    asyncio.run(run_scenario())


def test_recovery_refuses_missing_claim() -> None:
    async def run_scenario() -> None:
        async with _approved_claim() as (engine, claim):
            repository = PostgresRemediationExecutionRepository(engine=engine)
            missing_id = uuid4()
            with pytest.raises(RemediationExecutionClaimNotFoundError):
                await repository.start_recovered_once(
                    claim_id=missing_id,
                    verified_scope=_scope(claim),
                    recovery_policy=_policy(),
                )
            assert await _execution_count(engine, missing_id) == 0

    asyncio.run(run_scenario())


def test_recovery_refuses_scope_changed_since_claim() -> None:
    async def run_scenario() -> None:
        async with _approved_claim() as (engine, claim):
            repository = PostgresRemediationExecutionRepository(engine=engine)
            changed_scope = replace(_scope(claim), plan_id=uuid4())
            with pytest.raises(RemediationExecutionRecoveryScopeMismatchError):
                await repository.start_recovered_once(
                    claim_id=claim.claim_id,
                    verified_scope=changed_scope,
                    recovery_policy=_policy(),
                )
            assert await _execution_count(engine, claim.claim_id) == 0

    asyncio.run(run_scenario())


@pytest.mark.parametrize("approval_problem", ("rejected", "missing"))
def test_recovery_refuses_invalid_persisted_approval(approval_problem: str) -> None:
    async def run_scenario() -> None:
        async with _approved_claim() as (engine, claim):
            async with engine.begin() as connection:
                if approval_problem == "missing":
                    await connection.execute(
                        sa.delete(approval_decisions_table).where(
                            approval_decisions_table.c.request_id == claim.request_id
                        )
                    )
                else:
                    await connection.execute(
                        sa.update(approval_decisions_table)
                        .where(approval_decisions_table.c.request_id == claim.request_id)
                        .values(outcome=RemediationApprovalOutcome.REJECTED.value)
                    )
            repository = PostgresRemediationExecutionRepository(engine=engine)
            with pytest.raises(RemediationExecutionRecoveryApprovalDeniedError):
                await repository.start_recovered_once(
                    claim_id=claim.claim_id,
                    verified_scope=_scope(claim),
                    recovery_policy=_policy(),
                )
            assert await _execution_count(engine, claim.claim_id) == 0

    asyncio.run(run_scenario())


def test_recovery_refuses_inconsistent_persisted_approval_scope() -> None:
    async def run_scenario() -> None:
        async with _approved_claim() as (engine, claim):
            async with engine.begin() as connection:
                await connection.execute(
                    sa.update(approval_requests_table)
                    .where(approval_requests_table.c.request_id == claim.request_id)
                    .values(action_fingerprint="afp:v2:" + "c" * 64)
                )
            repository = PostgresRemediationExecutionRepository(engine=engine)
            with pytest.raises(RemediationExecutionRecoveryApprovalDeniedError):
                await repository.start_recovered_once(
                    claim_id=claim.claim_id,
                    verified_scope=_scope(claim),
                    recovery_policy=_policy(),
                )
            assert await _execution_count(engine, claim.claim_id) == 0

    asyncio.run(run_scenario())


def test_recovery_refuses_approval_recorded_outside_decision_window() -> None:
    async def run_scenario() -> None:
        async with _approved_claim() as (engine, claim):
            async with engine.begin() as connection:
                await connection.execute(
                    sa.update(approval_decisions_table)
                    .where(approval_decisions_table.c.request_id == claim.request_id)
                    .values(recorded_at=sa.func.clock_timestamp() - timedelta(days=1))
                )
            repository = PostgresRemediationExecutionRepository(engine=engine)
            with pytest.raises(RemediationExecutionRecoveryApprovalDeniedError):
                await repository.start_recovered_once(
                    claim_id=claim.claim_id,
                    verified_scope=_scope(claim),
                    recovery_policy=_policy(),
                )
            assert await _execution_count(engine, claim.claim_id) == 0

    asyncio.run(run_scenario())


@pytest.mark.parametrize("time_offset", (timedelta(minutes=-30), timedelta(minutes=30)))
def test_recovery_refuses_claim_outside_postgres_time_window(time_offset: timedelta) -> None:
    async def run_scenario() -> None:
        async with _approved_claim() as (engine, claim):
            async with engine.begin() as connection:
                await connection.execute(
                    sa.update(execution_claims_table)
                    .where(execution_claims_table.c.claim_id == claim.claim_id)
                    .values(claimed_at=sa.func.clock_timestamp() + time_offset)
                )
            repository = PostgresRemediationExecutionRepository(engine=engine)
            with pytest.raises(RemediationExecutionRecoveryWindowNotSatisfiedError):
                await repository.start_recovered_once(
                    claim_id=claim.claim_id,
                    verified_scope=_scope(claim),
                    recovery_policy=_policy(),
                )
            assert await _execution_count(engine, claim.claim_id) == 0

    asyncio.run(run_scenario())


def test_recovery_refuses_existing_standard_execution() -> None:
    async def run_scenario() -> None:
        async with _approved_claim() as (engine, claim):
            repository = PostgresRemediationExecutionRepository(engine=engine)
            initial = await repository.start_once(claim_id=claim.claim_id)
            with pytest.raises(RemediationExecutionAlreadyStartedError):
                await repository.start_recovered_once(
                    claim_id=claim.claim_id,
                    verified_scope=_scope(claim),
                    recovery_policy=_policy(),
                )
            assert await _execution_count(engine, claim.claim_id) == 1
            assert await repository.get_by_claim_id(claim_id=claim.claim_id) == initial

    asyncio.run(run_scenario())


@pytest.mark.parametrize(
    "second_operation",
    ("recovery", "standard"),
    ids=("recovery-vs-recovery", "recovery-vs-standard-start"),
)
def test_concurrent_recovery_and_standard_start_have_exactly_one_winner(
    second_operation: str,
) -> None:
    """Both workers attempt to lock one claim before the blocker releases it."""

    async def run_scenario() -> None:
        async with _approved_claim() as (setup_engine, claim):
            config = DatabaseConfig.from_environment()
            worker_engines = (
                create_database_engine(config),
                create_database_engine(config),
            )
            lock_dispatched = (asyncio.Event(), asyncio.Event())
            workers: list[asyncio.Task[RemediationExecution]] = []

            def make_lock_listener(signal: asyncio.Event) -> Callable[..., None]:
                def before_cursor_execute(
                    _connection: object,
                    _cursor: object,
                    statement: str,
                    _parameters: object,
                    _context: object,
                    _executemany: bool,
                ) -> None:
                    sql = statement.upper()
                    if "REMEDIATION_EXECUTION_CLAIMS" in sql and "FOR UPDATE" in sql:
                        signal.set()

                return before_cursor_execute

            listeners = tuple(make_lock_listener(event) for event in lock_dispatched)
            registered: list[tuple[AsyncEngine, Callable[..., None]]] = []

            try:
                for engine, listener in zip(worker_engines, listeners, strict=True):
                    sa.event.listen(engine.sync_engine, "before_cursor_execute", listener)
                    registered.append((engine, listener))

                recovery_repository = PostgresRemediationExecutionRepository(
                    engine=worker_engines[0]
                )
                competing_repository = PostgresRemediationExecutionRepository(
                    engine=worker_engines[1]
                )

                # Hold the claim's row lock until both independent workers issue
                # their SELECT ... FOR UPDATE statements to PostgreSQL.
                async with setup_engine.begin() as blocker:
                    locked_id = await blocker.scalar(
                        sa.select(execution_claims_table.c.claim_id)
                        .where(execution_claims_table.c.claim_id == claim.claim_id)
                        .with_for_update()
                    )
                    assert locked_id == claim.claim_id

                    second_attempt = (
                        competing_repository.start_recovered_once(
                            claim_id=claim.claim_id,
                            verified_scope=_scope(claim),
                            recovery_policy=_policy(),
                        )
                        if second_operation == "recovery"
                        else competing_repository.start_once(claim_id=claim.claim_id)
                    )
                    workers = [
                        asyncio.create_task(
                            recovery_repository.start_recovered_once(
                                claim_id=claim.claim_id,
                                verified_scope=_scope(claim),
                                recovery_policy=_policy(),
                            )
                        ),
                        asyncio.create_task(second_attempt),
                    ]
                    await asyncio.wait_for(
                        asyncio.gather(*(event.wait() for event in lock_dispatched)),
                        timeout=10,
                    )
                    assert all(not worker.done() for worker in workers)

                # The lock has been released. Exactly one worker may commit.
                results = await asyncio.wait_for(
                    asyncio.gather(*workers, return_exceptions=True), timeout=10
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
                assert winner.claim_id == claim.claim_id
                assert winner.status is RemediationExecutionStatus.EXECUTING
                assert winner.status_changed_at is None
                assert winner.started_at.tzinfo is UTC

                # Read from a different connection after both transactions finish.
                async with setup_engine.connect() as connection:
                    persisted = (
                        (
                            await connection.execute(
                                sa.select(remediation_executions_table).where(
                                    remediation_executions_table.c.claim_id == claim.claim_id
                                )
                            )
                        )
                        .mappings()
                        .all()
                    )
                assert len(persisted) == 1
                assert persisted[0]["execution_id"] == winner.execution_id
                assert persisted[0]["claim_id"] == claim.claim_id
                assert persisted[0]["status"] == "executing"
                assert persisted[0]["started_at"] == winner.started_at
                assert persisted[0]["status_changed_at"] is None
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

    asyncio.run(run_scenario())
