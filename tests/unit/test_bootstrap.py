"""Unit tests for the approval composition root and engine ownership."""

import asyncio
import inspect
from datetime import timedelta
from unittest.mock import AsyncMock, Mock, patch

import pytest
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import AsyncEngine

from ai_incident_commander.application.approval_authorization import (
    ApprovalPermissionDeniedError,
    AuthenticatedOperatorContext,
)
from ai_incident_commander.application.approval_request_service import (
    ApprovalRequestConfigurationError,
    ApprovalRequestCreationService,
)
from ai_incident_commander.application.approval_service import ApprovalApplicationService
from ai_incident_commander.application.target_resolver import TargetResolver
from ai_incident_commander.bootstrap import (
    ApprovalServices,
    approval_service_lifespan,
    approval_workflow_lifespan,
)
from ai_incident_commander.domain.action_catalog import ActionCatalog
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


def _workflow_dependencies() -> tuple[ActionCatalog, TargetResolver]:
    """Provide unused, typed dependency doubles; no external calls are made."""
    return Mock(spec=ActionCatalog), Mock(spec=TargetResolver)


def test_approval_workflow_wires_shared_repository_clock_and_engine() -> None:
    config = _config()
    authorizer = DenyingAuthorizer()
    catalog, resolver = _workflow_dependencies()
    engine = AsyncMock(spec=AsyncEngine)
    validity_period = timedelta(minutes=15)

    async def exercise() -> None:
        async with approval_workflow_lifespan(
            authorizer=authorizer,
            catalog=catalog,
            resolver=resolver,
            validity_period=validity_period,
            config=config,
        ) as services:
            assert isinstance(services, ApprovalServices)
            assert isinstance(services.decisions, ApprovalApplicationService)
            assert isinstance(services.requests, ApprovalRequestCreationService)
            assert services.decisions._authorizer is authorizer
            assert services.decisions._repository is services.requests._repository
            assert services.decisions._clock is services.requests._clock
            assert isinstance(services.decisions._clock, SystemClock)
            repository = services.decisions._repository
            assert isinstance(repository, PostgresApprovalRepository)
            assert repository._engine is engine
            assert services.requests._catalog is catalog
            assert services.requests._resolver is resolver
            assert services.requests._validity_period == validity_period
            engine.dispose.assert_not_awaited()

    with patch(
        "ai_incident_commander.bootstrap.create_database_engine", return_value=engine
    ) as create_engine:
        asyncio.run(exercise())

    create_engine.assert_called_once_with(config)
    engine.dispose.assert_awaited_once_with()


def test_approval_workflow_disposes_engine_when_body_raises() -> None:
    catalog, resolver = _workflow_dependencies()
    engine = AsyncMock(spec=AsyncEngine)

    async def exercise() -> None:
        async with approval_workflow_lifespan(
            authorizer=DenyingAuthorizer(),
            catalog=catalog,
            resolver=resolver,
            validity_period=timedelta(minutes=15),
            config=_config(),
        ):
            raise RuntimeError("Simulated workflow failure.")

    with patch("ai_incident_commander.bootstrap.create_database_engine", return_value=engine):
        with pytest.raises(RuntimeError, match="Simulated workflow failure"):
            asyncio.run(exercise())

    engine.dispose.assert_awaited_once_with()


@pytest.mark.parametrize(
    "constructor_name",
    ["ApprovalApplicationService", "ApprovalRequestCreationService"],
)
def test_approval_workflow_disposes_engine_when_service_creation_fails(
    constructor_name: str,
) -> None:
    catalog, resolver = _workflow_dependencies()
    engine = AsyncMock(spec=AsyncEngine)

    async def exercise() -> None:
        async with approval_workflow_lifespan(
            authorizer=DenyingAuthorizer(),
            catalog=catalog,
            resolver=resolver,
            validity_period=timedelta(minutes=15),
            config=_config(),
        ):
            pytest.fail("A failed service constructor must not yield services.")

    with (
        patch("ai_incident_commander.bootstrap.create_database_engine", return_value=engine),
        patch(
            f"ai_incident_commander.bootstrap.{constructor_name}",
            side_effect=RuntimeError("Simulated composition failure."),
        ),
    ):
        with pytest.raises(RuntimeError, match="Simulated composition failure"):
            asyncio.run(exercise())

    engine.dispose.assert_awaited_once_with()


def test_approval_workflow_disposes_engine_on_invalid_validity_period() -> None:
    catalog, resolver = _workflow_dependencies()
    engine = AsyncMock(spec=AsyncEngine)

    async def exercise() -> None:
        async with approval_workflow_lifespan(
            authorizer=DenyingAuthorizer(),
            catalog=catalog,
            resolver=resolver,
            validity_period=timedelta(0),
            config=_config(),
        ):
            pytest.fail("Invalid validity policy must not yield services.")

    with patch("ai_incident_commander.bootstrap.create_database_engine", return_value=engine):
        with pytest.raises(ApprovalRequestConfigurationError):
            asyncio.run(exercise())

    engine.dispose.assert_awaited_once_with()


def test_approval_workflow_uses_environment_when_config_omitted() -> None:
    catalog, resolver = _workflow_dependencies()
    config = _config()
    engine = AsyncMock(spec=AsyncEngine)

    async def exercise() -> None:
        async with approval_workflow_lifespan(
            authorizer=DenyingAuthorizer(),
            catalog=catalog,
            resolver=resolver,
            validity_period=timedelta(minutes=15),
        ) as services:
            assert isinstance(services, ApprovalServices)

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


def test_approval_workflow_requires_explicit_security_dependencies() -> None:
    signature = inspect.signature(approval_workflow_lifespan)
    for name in ("authorizer", "catalog", "resolver", "validity_period"):
        parameter = signature.parameters[name]
        assert parameter.kind is inspect.Parameter.KEYWORD_ONLY
        assert parameter.default is inspect.Parameter.empty
