"""Unit tests for the fail-closed MCP-bound approval composition root."""

import asyncio
import inspect
from dataclasses import replace
from datetime import timedelta
from typing import cast
from unittest.mock import AsyncMock, patch
from uuid import UUID, uuid4

import pytest
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import AsyncEngine

from ai_incident_commander.application.approval_authorization import (
    ApprovalPermissionDeniedError,
    AuthenticatedOperatorContext,
)
from ai_incident_commander.application.approval_execution_guard import (
    ApprovalExecutionGuard,
    ApprovalExecutionScopeMismatchError,
)
from ai_incident_commander.application.approval_request_service import (
    ApprovalRequestConfigurationError,
)
from ai_incident_commander.bootstrap import (
    McpApprovalServices,
    McpApprovalWorkflowConfigurationError,
    mcp_approval_workflow_lifespan,
)
from ai_incident_commander.domain.action_catalog import (
    ActionCatalog,
    ActionDefinition,
    ActionEffect,
)
from ai_incident_commander.domain.mcp_action_binding import (
    TrustedMcpActionBindings,
    TrustedMcpToolBinding,
)
from ai_incident_commander.domain.remediation import RemediationRiskLevel, RemediationStep
from ai_incident_commander.domain.remediation_approval import (
    RemediationApprovalDecision,
    RemediationApprovalOutcome,
    RemediationApprovalRequest,
)
from ai_incident_commander.domain.target_identity import ResolvedTarget
from ai_incident_commander.infrastructure.database_config import DatabaseConfig
from ai_incident_commander.infrastructure.system_clock import SystemClock


class DenyingAuthorizer:
    async def ensure_can_decide(
        self,
        *,
        operator: AuthenticatedOperatorContext,
        request: RemediationApprovalRequest,
        outcome: RemediationApprovalOutcome,
    ) -> None:
        raise ApprovalPermissionDeniedError("Test-only denial.")


class FixedTargetResolver:
    async def resolve(self, *, target: str, environment: str) -> ResolvedTarget:
        return ResolvedTarget(
            target=target,
            resource_id="resource-123",
            environment=environment,
            source="trusted-test-inventory",
        )


class MemoryApprovalRepository:
    """Test double: never touches PostgreSQL or makes authorization decisions."""

    def __init__(self) -> None:
        self.request: RemediationApprovalRequest | None = None
        self.decision: RemediationApprovalDecision | None = None

    async def create_request(self, request: RemediationApprovalRequest) -> None:
        self.request = request

    async def get_request(self, request_id: UUID) -> RemediationApprovalRequest | None:
        if self.request is not None and self.request.request_id == request_id:
            return self.request
        return None

    async def get_decision(self, request_id: UUID) -> RemediationApprovalDecision | None:
        if self.decision is not None and self.decision.request_id == request_id:
            return self.decision
        return None


def _config() -> DatabaseConfig:
    return DatabaseConfig(
        url=make_url("postgresql+psycopg://user:password@127.0.0.1:1/unreachable")
    )


def _catalog() -> ActionCatalog:
    return ActionCatalog(
        definitions=(
            ActionDefinition(
                action_name="restart_service",
                description="Restart in the isolated incident lab.",
                effect=ActionEffect.MUTATING,
                risk_level=RemediationRiskLevel.HIGH,
                allowed_environments=("incident-lab",),
            ),
        )
    )


def _bindings(
    catalog: ActionCatalog, *, tool_name: str = "restart_service"
) -> TrustedMcpActionBindings:
    return TrustedMcpActionBindings(
        catalog=catalog,
        bindings=(
            TrustedMcpToolBinding(
                action_name="restart_service",
                server_id="deployment-mcp",
                tool_name=tool_name,
            ),
        ),
    )


def _step() -> RemediationStep:
    return RemediationStep(
        plan_id=uuid4(),
        position=1,
        action_name="restart_service",
        target="payments-api",
        environment="incident-lab",
        risk_level=RemediationRiskLevel.HIGH,
    )


def test_mcp_lifespan_wires_one_binding_registry_and_shared_database_resources() -> None:
    catalog = _catalog()
    resolver = FixedTargetResolver()
    bindings = _bindings(catalog)
    authorizer = DenyingAuthorizer()
    engine = AsyncMock(spec=AsyncEngine)
    config = _config()

    async def run() -> None:
        async with mcp_approval_workflow_lifespan(
            authorizer=authorizer,
            catalog=catalog,
            resolver=resolver,
            validity_period=timedelta(minutes=15),
            mcp_bindings=bindings,
            config=config,
        ) as services:
            assert isinstance(services, McpApprovalServices)
            assert isinstance(services.guard, ApprovalExecutionGuard)
            assert services.requests._mcp_bindings is bindings
            assert services.guard._mcp_bindings is bindings
            assert services.requests._catalog is services.guard._catalog is catalog
            assert services.requests._resolver is services.guard._resolver is resolver
            assert services.decisions._repository is services.requests._repository
            assert services.guard._repository is services.requests._repository
            assert services.decisions._clock is services.requests._clock
            assert isinstance(services.requests._clock, SystemClock)
            assert services.decisions._authorizer is authorizer
            assert services.requests._repository._engine is engine
            engine.dispose.assert_not_awaited()

    with patch(
        "ai_incident_commander.bootstrap.create_database_engine", return_value=engine
    ) as create_engine:
        asyncio.run(run())

    create_engine.assert_called_once_with(config)
    engine.dispose.assert_awaited_once_with()


def test_mcp_lifespan_creates_v2_and_guard_denies_binding_drift_and_legacy() -> None:
    catalog = _catalog()
    bindings = _bindings(catalog)
    repository = MemoryApprovalRepository()
    engine = AsyncMock(spec=AsyncEngine)
    step = _step()
    resolver = FixedTargetResolver()

    async def run() -> None:
        async with mcp_approval_workflow_lifespan(
            authorizer=DenyingAuthorizer(),
            catalog=catalog,
            resolver=resolver,
            validity_period=timedelta(minutes=15),
            mcp_bindings=bindings,
            config=_config(),
        ) as services:
            request = await services.requests.create_for_step(step)
            assert request.policy_version.startswith("apv:v2:")
            assert repository.request == request
            repository.decision = RemediationApprovalDecision(
                request_id=request.request_id,
                operator_id="test-operator",
                outcome=RemediationApprovalOutcome.APPROVED,
                decided_at=request.requested_at + timedelta(seconds=1),
                reason="Reviewed in test.",
            )
            context = await services.guard.verify_mcp_execution_context_for_step(
                request_id=request.request_id, step=step
            )
            assert context.scope.policy_version == request.policy_version
            assert context.target.resource_id == "resource-123"

            changed_guard = ApprovalExecutionGuard(
                repository=repository,
                catalog=catalog,
                resolver=resolver,
                mcp_bindings=_bindings(catalog, tool_name="force_restart_service"),
            )
            with pytest.raises(ApprovalExecutionScopeMismatchError, match="policy version"):
                await changed_guard.verify_mcp_execution_context_for_step(
                    request_id=request.request_id, step=step
                )

            repository.request = replace(request, policy_version="apv:v1:" + "a" * 64)
            with pytest.raises(ApprovalExecutionScopeMismatchError, match="apv:v2"):
                await services.guard.verify_mcp_execution_context_for_step(
                    request_id=request.request_id, step=step
                )

    with (
        patch("ai_incident_commander.bootstrap.create_database_engine", return_value=engine),
        patch(
            "ai_incident_commander.bootstrap.PostgresApprovalRepository",
            return_value=repository,
        ),
    ):
        asyncio.run(run())

    engine.dispose.assert_awaited_once_with()


@pytest.mark.parametrize("invalid_bindings", [None, object()])
def test_mcp_lifespan_rejects_missing_or_invalid_bindings_before_engine(
    invalid_bindings: object,
) -> None:
    catalog = _catalog()

    async def run() -> None:
        async with mcp_approval_workflow_lifespan(
            authorizer=DenyingAuthorizer(),
            catalog=catalog,
            resolver=FixedTargetResolver(),
            validity_period=timedelta(minutes=15),
            mcp_bindings=cast(TrustedMcpActionBindings, invalid_bindings),
            config=_config(),
        ):
            pytest.fail("Unbound MCP services must never be constructed.")

    with patch("ai_incident_commander.bootstrap.create_database_engine") as create_engine:
        with pytest.raises(
            McpApprovalWorkflowConfigurationError, match="trusted MCP action bindings"
        ):
            asyncio.run(run())
        create_engine.assert_not_called()


def test_mcp_lifespan_rejects_mismatched_catalog_before_engine() -> None:
    first = _catalog()
    changed = ActionCatalog(
        definitions=(replace(first.definitions[0], description="Changed action policy."),)
    )

    async def run() -> None:
        async with mcp_approval_workflow_lifespan(
            authorizer=DenyingAuthorizer(),
            catalog=changed,
            resolver=FixedTargetResolver(),
            validity_period=timedelta(minutes=15),
            mcp_bindings=_bindings(first),
            config=_config(),
        ):
            pytest.fail("Mismatched catalogs must not yield services.")

    with patch("ai_incident_commander.bootstrap.create_database_engine") as create_engine:
        with pytest.raises(McpApprovalWorkflowConfigurationError, match="do not match"):
            asyncio.run(run())
        create_engine.assert_not_called()


def test_mcp_lifespan_rejects_empty_binding_registry_before_engine() -> None:
    catalog = _catalog()
    empty = TrustedMcpActionBindings(catalog=catalog, bindings=())

    async def run() -> None:
        async with mcp_approval_workflow_lifespan(
            authorizer=DenyingAuthorizer(),
            catalog=catalog,
            resolver=FixedTargetResolver(),
            validity_period=timedelta(minutes=15),
            mcp_bindings=empty,
            config=_config(),
        ):
            pytest.fail("Empty MCP bindings must not yield services.")

    with patch("ai_incident_commander.bootstrap.create_database_engine") as create_engine:
        with pytest.raises(McpApprovalWorkflowConfigurationError, match="at least one"):
            asyncio.run(run())
        create_engine.assert_not_called()


def test_mcp_lifespan_disposes_engine_when_body_raises() -> None:
    catalog = _catalog()
    engine = AsyncMock(spec=AsyncEngine)

    async def run() -> None:
        async with mcp_approval_workflow_lifespan(
            authorizer=DenyingAuthorizer(),
            catalog=catalog,
            resolver=FixedTargetResolver(),
            validity_period=timedelta(minutes=15),
            mcp_bindings=_bindings(catalog),
            config=_config(),
        ):
            raise RuntimeError("Simulated workflow failure.")

    with patch("ai_incident_commander.bootstrap.create_database_engine", return_value=engine):
        with pytest.raises(RuntimeError, match="Simulated workflow failure"):
            asyncio.run(run())
    engine.dispose.assert_awaited_once_with()


@pytest.mark.parametrize(
    "constructor_name",
    ["ApprovalApplicationService", "ApprovalRequestCreationService", "ApprovalExecutionGuard"],
)
def test_mcp_lifespan_disposes_engine_when_service_creation_fails(
    constructor_name: str,
) -> None:
    catalog = _catalog()
    engine = AsyncMock(spec=AsyncEngine)

    async def run() -> None:
        async with mcp_approval_workflow_lifespan(
            authorizer=DenyingAuthorizer(),
            catalog=catalog,
            resolver=FixedTargetResolver(),
            validity_period=timedelta(minutes=15),
            mcp_bindings=_bindings(catalog),
            config=_config(),
        ):
            pytest.fail("Failed constructor must not yield services.")

    with (
        patch("ai_incident_commander.bootstrap.create_database_engine", return_value=engine),
        patch(
            f"ai_incident_commander.bootstrap.{constructor_name}",
            side_effect=RuntimeError("Simulated composition failure."),
        ),
    ):
        with pytest.raises(RuntimeError, match="Simulated composition failure"):
            asyncio.run(run())
    engine.dispose.assert_awaited_once_with()


def test_mcp_lifespan_disposes_engine_for_invalid_validity_period() -> None:
    catalog = _catalog()
    engine = AsyncMock(spec=AsyncEngine)

    async def run() -> None:
        async with mcp_approval_workflow_lifespan(
            authorizer=DenyingAuthorizer(),
            catalog=catalog,
            resolver=FixedTargetResolver(),
            validity_period=timedelta(0),
            mcp_bindings=_bindings(catalog),
            config=_config(),
        ):
            pytest.fail("Invalid validity period must not yield services.")

    with patch("ai_incident_commander.bootstrap.create_database_engine", return_value=engine):
        with pytest.raises(ApprovalRequestConfigurationError):
            asyncio.run(run())
    engine.dispose.assert_awaited_once_with()


def test_mcp_lifespan_uses_environment_config_when_omitted() -> None:
    catalog = _catalog()
    config = _config()
    engine = AsyncMock(spec=AsyncEngine)

    async def run() -> None:
        async with mcp_approval_workflow_lifespan(
            authorizer=DenyingAuthorizer(),
            catalog=catalog,
            resolver=FixedTargetResolver(),
            validity_period=timedelta(minutes=15),
            mcp_bindings=_bindings(catalog),
        ) as services:
            assert isinstance(services, McpApprovalServices)

    with (
        patch.object(DatabaseConfig, "from_environment", return_value=config) as from_env,
        patch("ai_incident_commander.bootstrap.create_database_engine", return_value=engine),
    ):
        asyncio.run(run())
    from_env.assert_called_once_with()
    engine.dispose.assert_awaited_once_with()


def test_mcp_lifespan_requires_all_security_dependencies_explicitly() -> None:
    signature = inspect.signature(mcp_approval_workflow_lifespan)
    for name in ("authorizer", "catalog", "resolver", "validity_period", "mcp_bindings"):
        param = signature.parameters[name]
        assert param.kind is inspect.Parameter.KEYWORD_ONLY
        assert param.default is inspect.Parameter.empty
