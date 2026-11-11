"""Unit tests for the approval composition root and engine ownership."""

import asyncio
import inspect
from unittest.mock import AsyncMock, patch

import pytest
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import AsyncEngine

from ai_incident_commander.application.approval_authorization import (
    ApprovalPermissionDeniedError,
    AuthenticatedOperatorContext,
)
from ai_incident_commander.application.approval_service import ApprovalApplicationService
from ai_incident_commander.bootstrap import approval_service_lifespan
from ai_incident_commander.domain.remediation_approval import (
    RemediationApprovalOutcome,
    RemediationApprovalRequest,
)
from ai_incident_commander.infrastructure.database_config import DatabaseConfig
from ai_incident_commander.infrastructure.postgres_approval_repository import (
    PostgresApprovalRepository,
)
from ai_incident_commander.infrastructure.system_clock import SystemClock


class DenyingAuthorizer:
    """Fail-closed authorizer for dependency-wiring tests."""

    async def ensure_can_decide(
        self,
        *,
        operator: AuthenticatedOperatorContext,
        request: RemediationApprovalRequest,
        outcome: RemediationApprovalOutcome,
    ) -> None:
        raise ApprovalPermissionDeniedError("Approval denied in this test.")


def _config() -> DatabaseConfig:
    """Construct test config without reading secrets or opening a connection."""
    return DatabaseConfig(
        url=make_url("postgresql+psycopg://test_user:test_password@127.0.0.1:1/test_db")
    )


def test_approval_lifespan_wires_dependencies_and_disposes_engine() -> None:
    config = _config()
    authorizer = DenyingAuthorizer()
    engine = AsyncMock(spec=AsyncEngine)

    async def exercise() -> None:
        async with approval_service_lifespan(authorizer=authorizer, config=config) as service:
            assert isinstance(service, ApprovalApplicationService)
            repository = service._repository
            assert isinstance(repository, PostgresApprovalRepository)
            assert repository._engine is engine
            assert service._authorizer is authorizer
            assert isinstance(service._clock, SystemClock)
            engine.dispose.assert_not_awaited()

    with patch(
        "ai_incident_commander.bootstrap.create_database_engine", return_value=engine
    ) as create_engine:
        asyncio.run(exercise())

    create_engine.assert_called_once_with(config)
    engine.dispose.assert_awaited_once_with()


def test_approval_lifespan_disposes_engine_when_body_raises() -> None:
    engine = AsyncMock(spec=AsyncEngine)

    async def exercise() -> None:
        async with approval_service_lifespan(authorizer=DenyingAuthorizer(), config=_config()):
            raise RuntimeError("Simulated workflow failure.")

    with patch("ai_incident_commander.bootstrap.create_database_engine", return_value=engine):
        with pytest.raises(RuntimeError, match="Simulated workflow failure"):
            asyncio.run(exercise())

    engine.dispose.assert_awaited_once_with()


def test_approval_lifespan_disposes_engine_when_service_creation_fails() -> None:
    engine = AsyncMock(spec=AsyncEngine)

    async def exercise() -> None:
        async with approval_service_lifespan(authorizer=DenyingAuthorizer(), config=_config()):
            pytest.fail("A failed service constructor must not yield a service.")

    with (
        patch("ai_incident_commander.bootstrap.create_database_engine", return_value=engine),
        patch(
            "ai_incident_commander.bootstrap.ApprovalApplicationService",
            side_effect=RuntimeError("Simulated composition failure."),
        ),
    ):
        with pytest.raises(RuntimeError, match="Simulated composition failure"):
            asyncio.run(exercise())

    engine.dispose.assert_awaited_once_with()


def test_approval_lifespan_uses_environment_when_config_omitted() -> None:
    config = _config()
    engine = AsyncMock(spec=AsyncEngine)

    async def exercise() -> None:
        async with approval_service_lifespan(authorizer=DenyingAuthorizer()) as service:
            assert isinstance(service, ApprovalApplicationService)

    with (
        patch.object(DatabaseConfig, "from_environment", return_value=config) as from_env,
        patch(
            "ai_incident_commander.bootstrap.create_database_engine", return_value=engine
        ) as create_engine,
    ):
        asyncio.run(exercise())

    from_env.assert_called_once_with()
    create_engine.assert_called_once_with(config)
    engine.dispose.assert_awaited_once_with()


def test_approval_lifespan_requires_explicit_authorizer() -> None:
    param = inspect.signature(approval_service_lifespan).parameters["authorizer"]
    assert param.kind is inspect.Parameter.KEYWORD_ONLY
    assert param.default is inspect.Parameter.empty
