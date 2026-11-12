"""Opt-in integration tests for the approval service composition root."""

import asyncio
import os
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncEngine

from ai_incident_commander.application.action_fingerprint import create_action_fingerprint
from ai_incident_commander.application.action_policy_version import create_action_policy_version
from ai_incident_commander.application.approval_authorization import (
    ApprovalPermissionDeniedError,
    AuthenticatedOperatorContext,
)
from ai_incident_commander.application.approval_repository import ApprovalAlreadyDecidedError
from ai_incident_commander.application.remediation_preflight import RemediationPreflightResult
from ai_incident_commander.bootstrap import (
    approval_service_lifespan,
    approval_workflow_lifespan,
)
from ai_incident_commander.domain.action_catalog import (
    ActionCatalog,
    ActionDefinition,
    ActionEffect,
)
from ai_incident_commander.domain.remediation import RemediationRiskLevel, RemediationStep
from ai_incident_commander.domain.remediation_approval import (
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
from ai_incident_commander.infrastructure.postgres_approval_repository import (
    PostgresApprovalRepository,
)


class SingleOperatorAuthorizer:
    """Test-only authorizer permitting exactly one named operator."""

    def __init__(self, allowed_operator_id: str) -> None:
        self._allowed_operator_id = allowed_operator_id
        self.calls: list[
            tuple[
                AuthenticatedOperatorContext,
                RemediationApprovalRequest,
                RemediationApprovalOutcome,
            ]
        ] = []

    async def ensure_can_decide(
        self,
        *,
        operator: AuthenticatedOperatorContext,
        request: RemediationApprovalRequest,
        outcome: RemediationApprovalOutcome,
    ) -> None:
        self.calls.append((operator, request, outcome))
        if operator.operator_id != self._allowed_operator_id:
            raise ApprovalPermissionDeniedError("Test operator is not authorized.")


class StaticTargetResolver:
    """Test-only resolver providing a verified lab resource identity."""

    def __init__(self, result: ResolvedTarget) -> None:
        self._result = result
        self.calls: list[tuple[str, str]] = []

    async def resolve(self, *, target: str, environment: str) -> ResolvedTarget:
        self.calls.append((target, environment))
        return self._result


async def _remove_test_request(engine: AsyncEngine, request_id: UUID) -> None:
    """Delete only test-owned rows, child before parent (FK RESTRICT)."""
    async with engine.begin() as connection:
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


def test_composition_root_records_authorized_decision_in_postgres() -> None:
    """Wire the real service and repository, then verify the committed decision."""
    if os.environ.get("RUN_DB_APPROVAL_TESTS") != "1":
        pytest.skip("Set RUN_DB_APPROVAL_TESTS=1 to enable approval database tests")

    async def run_scenario() -> None:
        config = DatabaseConfig.from_environment()
        setup_engine = create_database_engine(config)
        request_id = uuid4()
        operator = AuthenticatedOperatorContext(operator_id="bootstrap-integration-operator")
        authorizer = SingleOperatorAuthorizer(allowed_operator_id=operator.operator_id)
        reason = "Approved by the authorized integration-test operator."

        try:
            # Anchor the request window to the database clock, as in repository tests.
            async with setup_engine.connect() as connection:
                database_now = await connection.scalar(sa.select(sa.func.clock_timestamp()))
            assert isinstance(database_now, datetime)
            database_now = database_now.astimezone(UTC)

            request = RemediationApprovalRequest(
                request_id=request_id,
                plan_id=uuid4(),
                step_id=uuid4(),
                action_fingerprint="afp:v2:" + "a" * 64,
                policy_version="apv:v1:" + "b" * 64,
                requested_at=database_now - timedelta(minutes=5),
                expires_at=database_now + timedelta(minutes=25),
            )
            await PostgresApprovalRepository(engine=setup_engine).create_request(request)

            # Exercise the production composition root with an explicit test authorizer.
            async with approval_service_lifespan(authorizer=authorizer, config=config) as service:
                decision = await service.decide(
                    request_id=request_id,
                    operator=operator,
                    outcome=RemediationApprovalOutcome.APPROVED,
                    reason=reason,
                )

            assert authorizer.calls == [(operator, request, RemediationApprovalOutcome.APPROVED)]
            assert decision.request_id == request_id
            assert decision.operator_id == operator.operator_id
            assert decision.outcome is RemediationApprovalOutcome.APPROVED
            assert decision.reason == reason
            assert decision.decided_at.utcoffset() == timedelta(0)
            assert request.requested_at <= decision.decided_at < request.expires_at

            # The lifespan has exited; a separate engine/connection must see committed data.
            async with setup_engine.connect() as connection:
                result = await connection.execute(
                    sa.select(approval_decisions_table).where(
                        approval_decisions_table.c.request_id == request_id
                    )
                )
                row = result.mappings().one()

            assert row["decision_id"] == decision.decision_id
            assert row["request_id"] == request_id
            assert row["operator_id"] == operator.operator_id
            assert row["outcome"] == RemediationApprovalOutcome.APPROVED.value
            assert row["reason"] == reason
            assert row["decided_at"] == decision.decided_at
            assert request.requested_at <= row["recorded_at"] < request.expires_at
        finally:
            try:
                await _remove_test_request(setup_engine, request_id)
            finally:
                await setup_engine.dispose()

    asyncio.run(run_scenario())


def test_composition_root_rejects_unauthorized_operator_without_persisting() -> None:
    """A denied operator cannot create a decision through the composed service."""
    if os.environ.get("RUN_DB_APPROVAL_TESTS") != "1":
        pytest.skip("Set RUN_DB_APPROVAL_TESTS=1 to enable approval database tests")

    async def run_scenario() -> None:
        config = DatabaseConfig.from_environment()
        setup_engine = create_database_engine(config)
        request_id = uuid4()
        denied_operator = AuthenticatedOperatorContext(operator_id="unauthorized-operator")
        authorizer = SingleOperatorAuthorizer(allowed_operator_id="authorized-operator")

        try:
            async with setup_engine.connect() as connection:
                database_now = await connection.scalar(sa.select(sa.func.clock_timestamp()))
            assert isinstance(database_now, datetime)
            database_now = database_now.astimezone(UTC)

            request = RemediationApprovalRequest(
                request_id=request_id,
                plan_id=uuid4(),
                step_id=uuid4(),
                action_fingerprint="afp:v2:" + "a" * 64,
                policy_version="apv:v1:" + "b" * 64,
                requested_at=database_now - timedelta(minutes=5),
                expires_at=database_now + timedelta(minutes=25),
            )
            await PostgresApprovalRepository(engine=setup_engine).create_request(request)

            async with approval_service_lifespan(authorizer=authorizer, config=config) as service:
                with pytest.raises(ApprovalPermissionDeniedError):
                    await service.decide(
                        request_id=request_id,
                        operator=denied_operator,
                        outcome=RemediationApprovalOutcome.APPROVED,
                        reason="Unauthorized attempt must not be recorded.",
                    )

            assert authorizer.calls == [
                (denied_operator, request, RemediationApprovalOutcome.APPROVED)
            ]

            # Read from an independent connection after the service lifespan exits.
            async with setup_engine.connect() as connection:
                decision_count = await connection.scalar(
                    sa.select(sa.func.count())
                    .select_from(approval_decisions_table)
                    .where(approval_decisions_table.c.request_id == request_id)
                )
                request_count = await connection.scalar(
                    sa.select(sa.func.count())
                    .select_from(approval_requests_table)
                    .where(approval_requests_table.c.request_id == request_id)
                )

            assert decision_count == 0
            assert request_count == 1
        finally:
            try:
                await _remove_test_request(setup_engine, request_id)
            finally:
                await setup_engine.dispose()

    asyncio.run(run_scenario())


def test_composition_root_rejects_second_decision_across_lifespans() -> None:
    """A new service lifecycle cannot replace a previously committed decision."""
    if os.environ.get("RUN_DB_APPROVAL_TESTS") != "1":
        pytest.skip("Set RUN_DB_APPROVAL_TESTS=1 to enable approval database tests")

    async def run_scenario() -> None:
        config = DatabaseConfig.from_environment()
        setup_engine = create_database_engine(config)
        request_id = uuid4()
        first_operator = AuthenticatedOperatorContext(operator_id="first-bootstrap-operator")
        second_operator = AuthenticatedOperatorContext(operator_id="second-bootstrap-operator")
        first_authorizer = SingleOperatorAuthorizer(allowed_operator_id=first_operator.operator_id)
        second_authorizer = SingleOperatorAuthorizer(
            allowed_operator_id=second_operator.operator_id
        )

        try:
            async with setup_engine.connect() as connection:
                database_now = await connection.scalar(sa.select(sa.func.clock_timestamp()))
            assert isinstance(database_now, datetime)
            database_now = database_now.astimezone(UTC)

            request = RemediationApprovalRequest(
                request_id=request_id,
                plan_id=uuid4(),
                step_id=uuid4(),
                action_fingerprint="afp:v2:" + "a" * 64,
                policy_version="apv:v1:" + "b" * 64,
                requested_at=database_now - timedelta(minutes=5),
                expires_at=database_now + timedelta(minutes=25),
            )
            await PostgresApprovalRepository(engine=setup_engine).create_request(request)

            # The first composed service commits a decision, then disposes its engine.
            async with approval_service_lifespan(
                authorizer=first_authorizer, config=config
            ) as service:
                first_decision = await service.decide(
                    request_id=request_id,
                    operator=first_operator,
                    outcome=RemediationApprovalOutcome.APPROVED,
                    reason="First operator approved the action.",
                )

            statement = sa.select(approval_decisions_table).where(
                approval_decisions_table.c.request_id == request_id
            )
            async with setup_engine.connect() as connection:
                original = dict((await connection.execute(statement)).mappings().one())

            assert original["decision_id"] == first_decision.decision_id

            # A new lifespan has a new engine and a different authorized operator.
            async with approval_service_lifespan(
                authorizer=second_authorizer, config=config
            ) as service:
                with pytest.raises(ApprovalAlreadyDecidedError):
                    await service.decide(
                        request_id=request_id,
                        operator=second_operator,
                        outcome=RemediationApprovalOutcome.REJECTED,
                        reason="Conflicting decision must be rejected.",
                    )

            assert first_authorizer.calls == [
                (first_operator, request, RemediationApprovalOutcome.APPROVED)
            ]
            assert second_authorizer.calls == [
                (second_operator, request, RemediationApprovalOutcome.REJECTED)
            ]

            async with setup_engine.connect() as connection:
                rows = (await connection.execute(statement)).mappings().all()

            assert len(rows) == 1
            assert dict(rows[0]) == original
            assert original["operator_id"] == first_operator.operator_id
            assert original["outcome"] == RemediationApprovalOutcome.APPROVED.value
        finally:
            try:
                await _remove_test_request(setup_engine, request_id)
            finally:
                await setup_engine.dispose()

    asyncio.run(run_scenario())


def test_workflow_creates_request_and_records_decision_in_postgres() -> None:
    """Create and decide on one preflighted action through the full workflow."""
    if os.environ.get("RUN_DB_APPROVAL_TESTS") != "1":
        pytest.skip("Set RUN_DB_APPROVAL_TESTS=1 to enable approval database tests")

    async def run_scenario() -> None:
        config = DatabaseConfig.from_environment()
        setup_engine = create_database_engine(config)
        step = RemediationStep(
            plan_id=uuid4(),
            position=1,
            action_name="restart_service",
            target="payments-api",
            environment="incident-lab",
            risk_level=RemediationRiskLevel.HIGH,
        )
        definition = ActionDefinition(
            action_name="restart_service",
            description="Restart the payments API in the incident lab.",
            effect=ActionEffect.MUTATING,
            risk_level=RemediationRiskLevel.HIGH,
            allowed_environments=("incident-lab",),
        )
        catalog = ActionCatalog(definitions=(definition,))
        resolved_target = ResolvedTarget(
            target="payments-api",
            resource_id="payments-api-integration-resource",
            environment="incident-lab",
            source="integration-test-inventory",
        )
        resolver = StaticTargetResolver(resolved_target)
        operator = AuthenticatedOperatorContext(operator_id="workflow-integration-operator")
        authorizer = SingleOperatorAuthorizer(allowed_operator_id=operator.operator_id)
        validity_period = timedelta(minutes=30)
        reason = "Approved after validated remediation preflight."
        request_id: UUID | None = None

        try:
            async with approval_workflow_lifespan(
                authorizer=authorizer,
                catalog=catalog,
                resolver=resolver,
                validity_period=validity_period,
                config=config,
            ) as services:
                request = await services.requests.create_for_step(step)
                request_id = request.request_id
                decision = await services.decisions.decide(
                    request_id=request_id,
                    operator=operator,
                    outcome=RemediationApprovalOutcome.APPROVED,
                    reason=reason,
                )

            # These are real production services. Only the trust-boundary inputs
            # (authorization and external target inventory) are test doubles.
            expected_fingerprint = create_action_fingerprint(
                step,
                RemediationPreflightResult(
                    action=definition,
                    target=resolved_target,
                    step_snapshot=step,
                    policy_version=create_action_policy_version(catalog),
                ),
            )
            assert resolver.calls == [(step.target, step.environment)]
            assert request.plan_id == step.plan_id
            assert request.step_id == step.step_id
            assert request.action_fingerprint == expected_fingerprint
            assert request.policy_version == create_action_policy_version(catalog)
            assert request.expires_at - request.requested_at == validity_period
            assert authorizer.calls == [(operator, request, RemediationApprovalOutcome.APPROVED)]
            assert decision.request_id == request_id
            assert decision.operator_id == operator.operator_id
            assert decision.outcome is RemediationApprovalOutcome.APPROVED
            assert decision.reason == reason

            # Verify durable writes using a separate engine after the workflow exits.
            async with setup_engine.connect() as connection:
                persisted_request = (
                    (
                        await connection.execute(
                            sa.select(approval_requests_table).where(
                                approval_requests_table.c.request_id == request_id
                            )
                        )
                    )
                    .mappings()
                    .one()
                )
                persisted_decision = (
                    (
                        await connection.execute(
                            sa.select(approval_decisions_table).where(
                                approval_decisions_table.c.request_id == request_id
                            )
                        )
                    )
                    .mappings()
                    .one()
                )

            assert persisted_request["request_id"] == request_id
            assert persisted_request["plan_id"] == step.plan_id
            assert persisted_request["step_id"] == step.step_id
            assert persisted_request["action_fingerprint"] == expected_fingerprint
            assert persisted_request["policy_version"] == request.policy_version
            assert persisted_request["requested_at"] == request.requested_at
            assert persisted_request["expires_at"] == request.expires_at
            assert persisted_decision["decision_id"] == decision.decision_id
            assert persisted_decision["request_id"] == request_id
            assert persisted_decision["operator_id"] == operator.operator_id
            assert persisted_decision["outcome"] == RemediationApprovalOutcome.APPROVED.value
            assert persisted_decision["reason"] == reason
            assert persisted_decision["decided_at"] == decision.decided_at
            assert request.requested_at <= persisted_decision["recorded_at"] < request.expires_at
        finally:
            try:
                if request_id is not None:
                    await _remove_test_request(setup_engine, request_id)
            finally:
                await setup_engine.dispose()

    asyncio.run(run_scenario())
