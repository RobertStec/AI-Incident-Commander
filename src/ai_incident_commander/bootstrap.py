"""Application composition root for the remediation approval workflow."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import timedelta

from ai_incident_commander.application.approval_authorization import ApprovalAuthorizer
from ai_incident_commander.application.approval_request_service import (
    ApprovalRequestCreationService,
)
from ai_incident_commander.application.approval_service import ApprovalApplicationService
from ai_incident_commander.application.target_resolver import TargetResolver
from ai_incident_commander.domain.action_catalog import ActionCatalog
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
) -> AsyncIterator[ApprovalApplicationService]:
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
) -> AsyncIterator[ApprovalServices]:
    """Wire request creation and decisions using one owned database engine.

    Enter once per process lifecycle, not once per request. Caller must provide
    trusted authorization, action catalog, target resolver and validity policy.
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
