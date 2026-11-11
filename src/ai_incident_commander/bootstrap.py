"""Application composition root for the remediation approval workflow."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from ai_incident_commander.application.approval_authorization import ApprovalAuthorizer
from ai_incident_commander.application.approval_service import ApprovalApplicationService
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
