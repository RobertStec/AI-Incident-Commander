"""Opt-in integration tests for PostgreSQL execution claim reservations."""

import asyncio
import os
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncEngine

from ai_incident_commander.application.execution_claim_repository import (
    ExecutionClaimAlreadyExistsError,
    ExecutionClaimApprovalDeniedError,
    ExecutionClaimScopeMismatchError,
)
from ai_incident_commander.domain.execution_claim import ExecutionClaim
from ai_incident_commander.domain.remediation_approval import (
    RemediationApprovalDecision,
    RemediationApprovalOutcome,
    RemediationApprovalRequest,
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

_FINGERPRINT = "afp:v2:" + "a" * 64
_POLICY_VERSION = "apv:v1:" + "b" * 64


def _require_database_tests() -> None:
    if os.environ.get("RUN_DB_APPROVAL_TESTS") != "1":
        pytest.skip("Set RUN_DB_APPROVAL_TESTS=1 to enable database integration tests")


async def _database_now(engine: AsyncEngine) -> datetime:
    async with engine.connect() as connection:
        timestamp = await connection.scalar(sa.select(sa.func.clock_timestamp()))
    assert isinstance(timestamp, datetime)
    return timestamp.astimezone(UTC)


def _request(now: datetime, *, plan_id: UUID, step_id: UUID) -> RemediationApprovalRequest:
    return RemediationApprovalRequest(
        plan_id=plan_id,
        step_id=step_id,
        action_fingerprint=_FINGERPRINT,
        policy_version=_POLICY_VERSION,
        requested_at=now - timedelta(minutes=5),
        expires_at=now + timedelta(minutes=25),
    )


async def _seed_decision(
    repository: PostgresApprovalRepository,
    request: RemediationApprovalRequest,
    now: datetime,
    outcome: RemediationApprovalOutcome,
) -> None:
    await repository.record_decision_once(
        RemediationApprovalDecision(
            request_id=request.request_id,
            operator_id="execution-claim-test-operator",
            outcome=outcome,
            decided_at=now,
            reason="Decision made by integration-test operator.",
        )
    )


async def _clean_test_requests(engine: AsyncEngine, request_ids: list[UUID]) -> None:
    """Delete ONLY test-owned rows, in reverse foreign-key order."""
    if not request_ids:
        return
    async with engine.begin() as connection:
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


def _arguments(request: RemediationApprovalRequest) -> dict[str, UUID | str]:
    return {
        "request_id": request.request_id,
        "plan_id": request.plan_id,
        "step_id": request.step_id,
        "action_fingerprint": request.action_fingerprint,
        "policy_version": request.policy_version,
    }


def test_claim_once_persists_approved_scope_using_postgres_time() -> None:
    _require_database_tests()

    async def run_scenario() -> None:
        engine = create_database_engine(DatabaseConfig.from_environment())
        request = _request(await _database_now(engine), plan_id=uuid4(), step_id=uuid4())
        try:
            approvals = PostgresApprovalRepository(engine=engine)
            claims = PostgresExecutionClaimRepository(engine=engine)
            await approvals.create_request(request)
            await _seed_decision(
                approvals,
                request,
                await _database_now(engine),
                RemediationApprovalOutcome.APPROVED,
            )
            before = await _database_now(engine)
            claim = await claims.claim_once(**_arguments(request))
            after = await _database_now(engine)

            assert isinstance(claim, ExecutionClaim)
            assert claim.plan_id == request.plan_id
            assert claim.step_id == request.step_id
            assert claim.request_id == request.request_id
            assert claim.action_fingerprint == request.action_fingerprint
            assert claim.policy_version == request.policy_version
            assert claim.claimed_at.tzinfo is UTC
            assert before <= claim.claimed_at <= after

            # Read the committed claim from a separate database connection.
            async with engine.connect() as connection:
                persisted = (
                    (
                        await connection.execute(
                            sa.select(execution_claims_table).where(
                                execution_claims_table.c.request_id == request.request_id
                            )
                        )
                    )
                    .mappings()
                    .one()
                )
            assert persisted["claim_id"] == claim.claim_id
            assert persisted["claimed_at"] == claim.claimed_at
            assert persisted["plan_id"] == claim.plan_id
            assert persisted["step_id"] == claim.step_id
        finally:
            try:
                await _clean_test_requests(engine, [request.request_id])
            finally:
                await engine.dispose()

    asyncio.run(run_scenario())


@pytest.mark.parametrize("scenario", ["missing", "pending", "rejected"])
def test_claim_once_denies_unapproved_requests(scenario: str) -> None:
    _require_database_tests()

    async def run_scenario() -> None:
        engine = create_database_engine(DatabaseConfig.from_environment())
        now = await _database_now(engine)
        request = _request(now, plan_id=uuid4(), step_id=uuid4())
        try:
            approvals = PostgresApprovalRepository(engine=engine)
            claims = PostgresExecutionClaimRepository(engine=engine)
            if scenario != "missing":
                await approvals.create_request(request)
            if scenario == "rejected":
                await _seed_decision(approvals, request, now, RemediationApprovalOutcome.REJECTED)

            with pytest.raises(ExecutionClaimApprovalDeniedError):
                await claims.claim_once(**_arguments(request))

            async with engine.connect() as connection:
                count = await connection.scalar(
                    sa.select(sa.func.count())
                    .select_from(execution_claims_table)
                    .where(execution_claims_table.c.request_id == request.request_id)
                )
            assert count == 0
        finally:
            try:
                await _clean_test_requests(engine, [request.request_id])
            finally:
                await engine.dispose()

    asyncio.run(run_scenario())


@pytest.mark.parametrize(
    "changed_field", ["plan_id", "step_id", "action_fingerprint", "policy_version"]
)
def test_claim_once_denies_mismatched_scope(changed_field: str) -> None:
    _require_database_tests()

    async def run_scenario() -> None:
        engine = create_database_engine(DatabaseConfig.from_environment())
        now = await _database_now(engine)
        request = _request(now, plan_id=uuid4(), step_id=uuid4())
        try:
            approvals = PostgresApprovalRepository(engine=engine)
            claims = PostgresExecutionClaimRepository(engine=engine)
            await approvals.create_request(request)
            await _seed_decision(approvals, request, now, RemediationApprovalOutcome.APPROVED)
            changes: dict[str, UUID | str] = {
                "plan_id": uuid4(),
                "step_id": uuid4(),
                "action_fingerprint": "afp:v2:" + "c" * 64,
                "policy_version": "apv:v1:" + "d" * 64,
            }
            arguments = _arguments(request)
            arguments[changed_field] = changes[changed_field]
            with pytest.raises(ExecutionClaimScopeMismatchError):
                await claims.claim_once(**arguments)

            async with engine.connect() as connection:
                count = await connection.scalar(
                    sa.select(sa.func.count())
                    .select_from(execution_claims_table)
                    .where(execution_claims_table.c.request_id == request.request_id)
                )
            assert count == 0
        finally:
            try:
                await _clean_test_requests(engine, [request.request_id])
            finally:
                await engine.dispose()

    asyncio.run(run_scenario())


def test_claim_once_rejects_identical_retry_without_issuing_new_claim() -> None:
    _require_database_tests()

    async def run_scenario() -> None:
        engine = create_database_engine(DatabaseConfig.from_environment())
        now = await _database_now(engine)
        request = _request(now, plan_id=uuid4(), step_id=uuid4())
        try:
            approvals = PostgresApprovalRepository(engine=engine)
            claims = PostgresExecutionClaimRepository(engine=engine)
            await approvals.create_request(request)
            await _seed_decision(approvals, request, now, RemediationApprovalOutcome.APPROVED)
            first = await claims.claim_once(**_arguments(request))
            with pytest.raises(ExecutionClaimAlreadyExistsError):
                await claims.claim_once(**_arguments(request))
            async with engine.connect() as connection:
                existing = (
                    (
                        await connection.execute(
                            sa.select(execution_claims_table).where(
                                execution_claims_table.c.request_id == request.request_id
                            )
                        )
                    )
                    .mappings()
                    .all()
                )
            assert len(existing) == 1
            assert existing[0]["claim_id"] == first.claim_id
        finally:
            try:
                await _clean_test_requests(engine, [request.request_id])
            finally:
                await engine.dispose()

    asyncio.run(run_scenario())


def test_claim_once_rejects_another_approved_request_for_same_step() -> None:
    _require_database_tests()

    async def run_scenario() -> None:
        engine = create_database_engine(DatabaseConfig.from_environment())
        now = await _database_now(engine)
        plan_id, step_id = uuid4(), uuid4()
        first_request = _request(now, plan_id=plan_id, step_id=step_id)
        second_request = replace(first_request, request_id=uuid4())
        request_ids = [first_request.request_id, second_request.request_id]
        try:
            approvals = PostgresApprovalRepository(engine=engine)
            claims = PostgresExecutionClaimRepository(engine=engine)
            for request in (first_request, second_request):
                await approvals.create_request(request)
                await _seed_decision(approvals, request, now, RemediationApprovalOutcome.APPROVED)

            first_claim = await claims.claim_once(**_arguments(first_request))
            with pytest.raises(ExecutionClaimAlreadyExistsError):
                await claims.claim_once(**_arguments(second_request))
            async with engine.connect() as connection:
                persisted = (
                    (
                        await connection.execute(
                            sa.select(execution_claims_table).where(
                                execution_claims_table.c.plan_id == plan_id,
                                execution_claims_table.c.step_id == step_id,
                            )
                        )
                    )
                    .mappings()
                    .all()
                )
            assert len(persisted) == 1
            assert persisted[0]["claim_id"] == first_claim.claim_id
            assert persisted[0]["request_id"] == first_request.request_id
        finally:
            try:
                await _clean_test_requests(engine, request_ids)
            finally:
                await engine.dispose()

    asyncio.run(run_scenario())


@pytest.mark.parametrize(
    "different_approvals",
    (False, True),
    ids=("same-approval", "different-approvals-same-step"),
)
def test_claim_once_allows_only_one_concurrent_worker(different_approvals: bool) -> None:
    """Two genuine contenders must produce exactly one committed execution claim."""
    _require_database_tests()

    async def run_scenario() -> None:
        engine = create_database_engine(DatabaseConfig.from_environment())
        now = await _database_now(engine)
        plan_id, step_id = uuid4(), uuid4()
        first_request = _request(now, plan_id=plan_id, step_id=step_id)
        second_request = (
            replace(first_request, request_id=uuid4()) if different_approvals else first_request
        )
        requests_to_seed = (
            (first_request, second_request) if different_approvals else (first_request,)
        )
        request_ids = [request.request_id for request in requests_to_seed]
        pending: list[asyncio.Task[ExecutionClaim]] = []

        try:
            approvals = PostgresApprovalRepository(engine=engine)
            claims = PostgresExecutionClaimRepository(engine=engine)
            for request in requests_to_seed:
                await approvals.create_request(request)
                await _seed_decision(
                    approvals,
                    request,
                    now,
                    RemediationApprovalOutcome.APPROVED,
                )

            # Lock all relevant approval request rows BEFORE starting the workers.
            # This ensures both workers pass their initial read and contend at
            # the real SELECT ... FOR UPDATE, without timing-based sleeps.
            blocked_requests = (
                sa.select(approval_requests_table.c.request_id)
                .where(approval_requests_table.c.request_id.in_(request_ids))
                .order_by(approval_requests_table.c.request_id)
                .with_for_update()
            )
            both_lock_attempts_started = asyncio.Event()
            competing_connections: set[int] = set()

            def observe_lock_attempt(
                connection: object,
                _cursor: object,
                statement: str,
                _parameters: object,
                _context: object,
                _executemany: bool,
            ) -> None:
                sql = statement.upper()
                if "FOR UPDATE" not in sql or "REMEDIATION_APPROVAL_REQUESTS" not in sql:
                    return
                competing_connections.add(id(connection))
                if len(competing_connections) == 2:
                    both_lock_attempts_started.set()

            async with engine.begin() as blocker:
                locked_ids = (await blocker.execute(blocked_requests)).scalars().all()
                assert set(locked_ids) == set(request_ids)

                # Register only after the blocker has acquired its locks.
                sa.event.listen(engine.sync_engine, "before_cursor_execute", observe_lock_attempt)
                try:
                    pending = [
                        asyncio.create_task(claims.claim_once(**_arguments(request)))
                        for request in (first_request, second_request)
                    ]
                    await asyncio.wait_for(both_lock_attempts_started.wait(), timeout=10)
                    assert len(competing_connections) == 2
                    assert all(not task.done() for task in pending)
                finally:
                    sa.event.remove(
                        engine.sync_engine, "before_cursor_execute", observe_lock_attempt
                    )

            # The blocking transaction has committed and released both locks.
            results = await asyncio.wait_for(
                asyncio.gather(*pending, return_exceptions=True), timeout=10
            )
            successful_claims = [result for result in results if isinstance(result, ExecutionClaim)]
            refused_claims = [
                result for result in results if isinstance(result, ExecutionClaimAlreadyExistsError)
            ]
            assert len(successful_claims) == 1
            assert len(refused_claims) == 1
            winner = successful_claims[0]
            assert winner.plan_id == plan_id
            assert winner.step_id == step_id
            assert winner.request_id in request_ids

            # Verify the committed result through an independent connection.
            async with engine.connect() as connection:
                persisted = (
                    (
                        await connection.execute(
                            sa.select(execution_claims_table).where(
                                execution_claims_table.c.plan_id == plan_id,
                                execution_claims_table.c.step_id == step_id,
                            )
                        )
                    )
                    .mappings()
                    .all()
                )
            assert len(persisted) == 1
            assert persisted[0]["claim_id"] == winner.claim_id
            assert persisted[0]["request_id"] == winner.request_id
        finally:
            for task in pending:
                if not task.done():
                    task.cancel()
            if pending:
                await asyncio.gather(*pending, return_exceptions=True)
            try:
                await _clean_test_requests(engine, request_ids)
            finally:
                await engine.dispose()

    asyncio.run(run_scenario())
