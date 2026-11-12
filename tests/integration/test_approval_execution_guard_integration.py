"""Opt-in integration tests for approval eligibility backed by real PostgreSQL."""

import asyncio
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, replace
from datetime import timedelta
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncEngine

from ai_incident_commander.application.approval_authorization import (
    ApprovalPermissionDeniedError,
    AuthenticatedOperatorContext,
)
from ai_incident_commander.application.approval_execution_guard import (
    ApprovalExecutionDeniedError,
    ApprovalExecutionGuard,
    ApprovalExecutionScopeMismatchError,
)
from ai_incident_commander.application.approval_request_service import (
    ApprovalRequestCreationService,
)
from ai_incident_commander.application.approval_service import ApprovalApplicationService
from ai_incident_commander.application.execution_claim_repository import (
    ExecutionClaimAlreadyExistsError,
)
from ai_incident_commander.application.execution_claim_service import ExecutionClaimService
from ai_incident_commander.domain.action_catalog import (
    ActionCatalog,
    ActionDefinition,
    ActionEffect,
)
from ai_incident_commander.domain.execution_claim import ExecutionClaim
from ai_incident_commander.domain.remediation import RemediationRiskLevel, RemediationStep
from ai_incident_commander.domain.remediation_approval import (
    RemediationApprovalDecision,
    RemediationApprovalOutcome,
    RemediationApprovalRequest,
)
from ai_incident_commander.domain.target_identity import ResolvedTarget
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
from ai_incident_commander.infrastructure.system_clock import SystemClock

pytestmark = pytest.mark.skipif(
    os.environ.get("RUN_DB_APPROVAL_TESTS") != "1",
    reason="Set RUN_DB_APPROVAL_TESTS=1 to enable approval database tests",
)


class SingleOperatorAuthorizer:
    """Test-only authorization boundary that permits one explicit operator."""

    def __init__(self, allowed_operator_id: str) -> None:
        self._allowed_operator_id = allowed_operator_id

    async def ensure_can_decide(
        self,
        *,
        operator: AuthenticatedOperatorContext,
        request: RemediationApprovalRequest,
        outcome: RemediationApprovalOutcome,
    ) -> None:
        if operator.operator_id != self._allowed_operator_id:
            raise ApprovalPermissionDeniedError("Test operator is not authorized.")


class MutableTargetResolver:
    """Test-only inventory that can simulate a changed resource identity."""

    def __init__(self, result: ResolvedTarget) -> None:
        self.result = result
        self.calls: list[tuple[str, str]] = []

    async def resolve(self, *, target: str, environment: str) -> ResolvedTarget:
        self.calls.append((target, environment))
        return self.result


@dataclass(slots=True)
class Scenario:
    request_id: UUID
    step: RemediationStep
    guard: ApprovalExecutionGuard
    resolver: MutableTargetResolver
    reader_repository: PostgresApprovalRepository
    decision: RemediationApprovalDecision | None
    reader_engine: AsyncEngine


async def _remove_test_request(engine: AsyncEngine, request_id: UUID) -> None:
    """Remove only this scenario's rows (FK RESTRICT: child before parent)."""
    async with engine.begin() as connection:
        await connection.execute(
            sa.delete(execution_claims_table).where(
                execution_claims_table.c.request_id == request_id
            )
        )
        await connection.execute(
            sa.delete(approval_decisions_table).where(
                approval_decisions_table.c.request_id == request_id
            )
        )
        await connection.execute(
            sa.delete(approval_requests_table).where(
                approval_requests_table.c.request_id == request_id
            )
        )


@asynccontextmanager
async def _scenario(
    outcome: RemediationApprovalOutcome | None,
) -> AsyncIterator[Scenario]:
    """Create a request/decision using one engine and check using another."""
    config = DatabaseConfig.from_environment()
    writer_engine = create_database_engine(config)
    reader_engine = create_database_engine(config)
    request_id: UUID | None = None

    try:
        writer_repository = PostgresApprovalRepository(engine=writer_engine)
        reader_repository = PostgresApprovalRepository(engine=reader_engine)
        step = RemediationStep(
            plan_id=uuid4(),
            position=1,
            action_name="restart_service",
            target="payments-api",
            environment="incident-lab",
            risk_level=RemediationRiskLevel.HIGH,
        )
        catalog = ActionCatalog(
            definitions=(
                ActionDefinition(
                    action_name="restart_service",
                    description="Restart a service in the incident lab.",
                    effect=ActionEffect.MUTATING,
                    risk_level=RemediationRiskLevel.HIGH,
                    allowed_environments=("incident-lab",),
                ),
            )
        )
        resolver = MutableTargetResolver(
            ResolvedTarget(
                target="payments-api",
                resource_id="payments-api-integration-resource",
                environment="incident-lab",
                source="integration-test-inventory",
            )
        )
        creator = ApprovalRequestCreationService(
            repository=writer_repository,
            clock=SystemClock(),
            catalog=catalog,
            resolver=resolver,
            validity_period=timedelta(minutes=30),
        )
        request = await creator.create_for_step(step)
        request_id = request.request_id

        decision: RemediationApprovalDecision | None = None
        if outcome is not None:
            operator = AuthenticatedOperatorContext(operator_id="guard-integration-operator")
            decision_service = ApprovalApplicationService(
                repository=writer_repository,
                authorizer=SingleOperatorAuthorizer(operator.operator_id),
                clock=SystemClock(),
            )
            decision = await decision_service.decide(
                request_id=request_id,
                operator=operator,
                outcome=outcome,
                reason="Reviewed by the integration-test operator.",
            )

        resolver.calls.clear()  # Guard must perform its own preflight if eligible.
        guard = ApprovalExecutionGuard(
            repository=reader_repository,
            catalog=catalog,
            resolver=resolver,
        )
        yield Scenario(
            request_id, step, guard, resolver, reader_repository, decision, reader_engine
        )
    finally:
        try:
            if request_id is not None:
                await _remove_test_request(writer_engine, request_id)
        finally:
            try:
                await reader_engine.dispose()
            finally:
                await writer_engine.dispose()


def test_guard_accepts_committed_approval_from_independent_engine() -> None:
    async def run_scenario() -> None:
        async with _scenario(RemediationApprovalOutcome.APPROVED) as case:
            persisted = await case.reader_repository.get_decision(case.request_id)
            assert persisted is not None
            assert persisted == case.decision
            assert persisted.outcome is RemediationApprovalOutcome.APPROVED

            assert (
                await case.guard.validate_for_step(request_id=case.request_id, step=case.step)
                is None
            )
            assert case.resolver.calls == [(case.step.target, case.step.environment)]

    asyncio.run(run_scenario())


def test_guard_denies_rejected_decision_before_preflight() -> None:
    async def run_scenario() -> None:
        async with _scenario(RemediationApprovalOutcome.REJECTED) as case:
            assert await case.reader_repository.get_decision(case.request_id) == case.decision
            with pytest.raises(ApprovalExecutionDeniedError, match="not been approved"):
                await case.guard.validate_for_step(request_id=case.request_id, step=case.step)
            assert case.resolver.calls == []

    asyncio.run(run_scenario())


def test_guard_denies_pending_request_before_preflight() -> None:
    async def run_scenario() -> None:
        async with _scenario(None) as case:
            assert await case.reader_repository.get_decision(case.request_id) is None
            with pytest.raises(ApprovalExecutionDeniedError, match="decision does not exist"):
                await case.guard.validate_for_step(request_id=case.request_id, step=case.step)
            assert case.resolver.calls == []

    asyncio.run(run_scenario())


def test_guard_denies_resource_drift_after_committed_approval() -> None:
    async def run_scenario() -> None:
        async with _scenario(RemediationApprovalOutcome.APPROVED) as case:
            case.resolver.result = replace(
                case.resolver.result,
                resource_id="different-payments-api-resource",
            )
            with pytest.raises(ApprovalExecutionScopeMismatchError, match="fingerprint"):
                await case.guard.validate_for_step(request_id=case.request_id, step=case.step)
            assert case.resolver.calls == [(case.step.target, case.step.environment)]
            assert await case.reader_repository.get_decision(case.request_id) == case.decision

    asyncio.run(run_scenario())


def test_claim_service_commits_verified_approved_step() -> None:
    """The real guard, claim service, and claim repository share persisted approval."""

    async def run_scenario() -> None:
        async with _scenario(RemediationApprovalOutcome.APPROVED) as case:
            service = ExecutionClaimService(
                guard=case.guard,
                repository=PostgresExecutionClaimRepository(engine=case.reader_engine),
            )

            claim = await service.claim_for_step(request_id=case.request_id, step=case.step)
            persisted_request = await case.reader_repository.get_request(case.request_id)

            assert isinstance(claim, ExecutionClaim)
            assert persisted_request is not None
            assert claim.request_id == case.request_id
            assert claim.plan_id == case.step.plan_id
            assert claim.step_id == case.step.step_id
            assert claim.action_fingerprint == persisted_request.action_fingerprint
            assert claim.policy_version == persisted_request.policy_version
            assert claim.claimed_at.utcoffset() == timedelta(0)
            assert case.resolver.calls == [(case.step.target, case.step.environment)]

            # Read durable data independently of the claim_once transaction.
            async with case.reader_engine.connect() as connection:
                result = await connection.execute(
                    sa.select(execution_claims_table).where(
                        execution_claims_table.c.request_id == case.request_id
                    )
                )
                stored = result.mappings().one()

            assert stored["claim_id"] == claim.claim_id
            assert stored["plan_id"] == claim.plan_id
            assert stored["step_id"] == claim.step_id
            assert stored["action_fingerprint"] == claim.action_fingerprint
            assert stored["policy_version"] == claim.policy_version
            assert stored["claimed_at"] == claim.claimed_at

    asyncio.run(run_scenario())


@pytest.mark.parametrize(
    "outcome",
    [None, RemediationApprovalOutcome.REJECTED],
    ids=("pending", "rejected"),
)
def test_claim_service_denies_unapproved_request_without_creating_claim(
    outcome: RemediationApprovalOutcome | None,
) -> None:
    """An absent or REJECTED decision stops the flow before preflight or INSERT."""

    async def run_scenario() -> None:
        async with _scenario(outcome) as case:
            service = ExecutionClaimService(
                guard=case.guard,
                repository=PostgresExecutionClaimRepository(engine=case.reader_engine),
            )

            with pytest.raises(ApprovalExecutionDeniedError):
                await service.claim_for_step(request_id=case.request_id, step=case.step)

            assert case.resolver.calls == []
            async with case.reader_engine.connect() as connection:
                count = await connection.scalar(
                    sa.select(sa.func.count())
                    .select_from(execution_claims_table)
                    .where(execution_claims_table.c.request_id == case.request_id)
                )
            assert count == 0

    asyncio.run(run_scenario())


def test_claim_service_denies_resource_drift_without_creating_claim() -> None:
    """Current resource identity must still match the approved fingerprint."""

    async def run_scenario() -> None:
        async with _scenario(RemediationApprovalOutcome.APPROVED) as case:
            service = ExecutionClaimService(
                guard=case.guard,
                repository=PostgresExecutionClaimRepository(engine=case.reader_engine),
            )
            case.resolver.result = replace(
                case.resolver.result,
                resource_id="unapproved-payments-api-resource",
            )

            with pytest.raises(ApprovalExecutionScopeMismatchError, match="fingerprint"):
                await service.claim_for_step(request_id=case.request_id, step=case.step)

            assert case.resolver.calls == [(case.step.target, case.step.environment)]
            async with case.reader_engine.connect() as connection:
                count = await connection.scalar(
                    sa.select(sa.func.count())
                    .select_from(execution_claims_table)
                    .where(execution_claims_table.c.request_id == case.request_id)
                )
            assert count == 0

    asyncio.run(run_scenario())


def test_claim_service_rejects_identical_retry_and_preserves_first_claim() -> None:
    """Revalidating approval does not grant an already claimed step again."""

    async def run_scenario() -> None:
        async with _scenario(RemediationApprovalOutcome.APPROVED) as case:
            service = ExecutionClaimService(
                guard=case.guard,
                repository=PostgresExecutionClaimRepository(engine=case.reader_engine),
            )
            first_claim = await service.claim_for_step(request_id=case.request_id, step=case.step)

            with pytest.raises(ExecutionClaimAlreadyExistsError):
                await service.claim_for_step(request_id=case.request_id, step=case.step)

            # The guard revalidates once per attempt; each attempt performs one preflight.
            assert case.resolver.calls == [
                (case.step.target, case.step.environment),
                (case.step.target, case.step.environment),
            ]

            async with case.reader_engine.connect() as connection:
                rows = (
                    (
                        await connection.execute(
                            sa.select(execution_claims_table).where(
                                execution_claims_table.c.request_id == case.request_id
                            )
                        )
                    )
                    .mappings()
                    .all()
                )

            assert len(rows) == 1
            assert rows[0]["claim_id"] == first_claim.claim_id
            assert rows[0]["claimed_at"] == first_claim.claimed_at

    asyncio.run(run_scenario())
