"""Application composition root for the remediation approval workflow."""

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import timedelta

from ai_incident_commander.application.approval_authorization import ApprovalAuthorizer
from ai_incident_commander.application.approval_execution_guard import ApprovalExecutionGuard
from ai_incident_commander.application.approval_request_service import (
    ApprovalRequestCreationService,
)
from ai_incident_commander.application.approval_service import ApprovalApplicationService
from ai_incident_commander.application.target_resolver import TargetResolver
from ai_incident_commander.domain.action_catalog import ActionCatalog
from ai_incident_commander.domain.mcp_action_binding import TrustedMcpActionBindings
from ai_incident_commander.infrastructure.database_config import DatabaseConfig
from ai_incident_commander.infrastructure.database_engine import create_database_engine
from ai_incident_commander.infrastructure.postgres_approval_repository import (
    PostgresApprovalRepository,
)
from ai_incident_commander.infrastructure.system_clock import SystemClock


@asynccontextmanager
async def approval_service_lifespan(
    *,
    authorizer: ApprovalAuthorizer,
    config: DatabaseConfig | None = None,
) -> AsyncGenerator[ApprovalApplicationService]:
    """Wire approvals once per process lifecycle and dispose the owned engine.

    Do not enter this context for each request. An authentication/authorization
    boundary must explicitly provide the authorizer; there is no permissive default.
    """
    database_config = config if config is not None else DatabaseConfig.from_environment()
    engine = create_database_engine(database_config)

    try:
        repository = PostgresApprovalRepository(engine=engine)
        service = ApprovalApplicationService(
            repository=repository,
            authorizer=authorizer,
            clock=SystemClock(),
        )
        yield service
    finally:
        await engine.dispose()


@dataclass(frozen=True, slots=True)
class ApprovalServices:
    """Application services sharing approval persistence and lifecycle."""

    decisions: ApprovalApplicationService
    requests: ApprovalRequestCreationService


@asynccontextmanager
async def approval_workflow_lifespan(
    *,
    authorizer: ApprovalAuthorizer,
    catalog: ActionCatalog,
    resolver: TargetResolver,
    validity_period: timedelta,
    config: DatabaseConfig | None = None,
) -> AsyncGenerator[ApprovalServices]:
    """Retain the legacy, catalog-only approval workflow for non-MCP callers.

    Do NOT wire a mutating MCP executor with these unbound services.
    Use mcp_approval_workflow_lifespan for the MCP-bound approval workflow.
    Enter once per process lifecycle, not once per request.
    """
    database_config = config if config is not None else DatabaseConfig.from_environment()
    engine = create_database_engine(database_config)

    try:
        repository = PostgresApprovalRepository(engine=engine)
        clock = SystemClock()
        decisions = ApprovalApplicationService(
            repository=repository,
            authorizer=authorizer,
            clock=clock,
        )
        requests = ApprovalRequestCreationService(
            repository=repository,
            clock=clock,
            catalog=catalog,
            resolver=resolver,
            validity_period=validity_period,
        )
        yield ApprovalServices(decisions=decisions, requests=requests)
    finally:
        await engine.dispose()


class McpApprovalWorkflowConfigurationError(ValueError):
    """A mutating MCP approval workflow has incomplete or mismatched bindings."""


@dataclass(frozen=True, slots=True)
class McpApprovalServices:
    """MCP-bound services sharing one trusted action catalog and binding registry.

    A verified Guard context is not permission to invoke an MCP tool.
    """

    decisions: ApprovalApplicationService
    requests: ApprovalRequestCreationService
    guard: ApprovalExecutionGuard


@asynccontextmanager
async def mcp_approval_workflow_lifespan(
    *,
    authorizer: ApprovalAuthorizer,
    catalog: ActionCatalog,
    resolver: TargetResolver,
    validity_period: timedelta,
    mcp_bindings: TrustedMcpActionBindings,
    config: DatabaseConfig | None = None,
) -> AsyncGenerator[McpApprovalServices]:
    """Wire MCP-bound requests and Guard with identical trusted bindings.

    This explicit entry point never falls back to apv:v1. The caller must load
    the registry from trusted configuration, not from a request or LLM output.
    It creates no MCP client, dispatch capability or external side effect.
    """
    # Reject configuration errors before allocating a database engine.
    if not isinstance(mcp_bindings, TrustedMcpActionBindings):
        raise McpApprovalWorkflowConfigurationError(
            "MCP approval workflow requires trusted MCP action bindings."
        )
    if mcp_bindings.catalog != catalog:
        raise McpApprovalWorkflowConfigurationError(
            "MCP action bindings do not match the approval workflow catalog."
        )
    if not mcp_bindings.bindings:
        raise McpApprovalWorkflowConfigurationError(
            "MCP approval workflow requires at least one mutating action binding."
        )

    database_config = config if config is not None else DatabaseConfig.from_environment()
    engine = create_database_engine(database_config)
    try:
        repository = PostgresApprovalRepository(engine=engine)
        clock = SystemClock()
        decisions = ApprovalApplicationService(
            repository=repository,
            authorizer=authorizer,
            clock=clock,
        )
        requests = ApprovalRequestCreationService(
            repository=repository,
            clock=clock,
            catalog=catalog,
            resolver=resolver,
            validity_period=validity_period,
            mcp_bindings=mcp_bindings,
        )
        guard = ApprovalExecutionGuard(
            repository=repository,
            catalog=catalog,
            resolver=resolver,
            mcp_bindings=mcp_bindings,
        )
        yield McpApprovalServices(decisions=decisions, requests=requests, guard=guard)
    finally:
        await engine.dispose()
