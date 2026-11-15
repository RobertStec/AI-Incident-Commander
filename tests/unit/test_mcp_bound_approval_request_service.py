"""MCP-bound approval request creation: fail-closed unit and compatibility tests."""

import asyncio
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from re import fullmatch
from uuid import UUID, uuid4

import pytest

from ai_incident_commander.application.action_fingerprint import create_action_fingerprint
from ai_incident_commander.application.action_policy_version import (
    create_mcp_bound_action_policy_version,
)
from ai_incident_commander.application.approval_request_service import (
    ApprovalRequestClockError,
    ApprovalRequestConfigurationError,
    ApprovalRequestCreationService,
)
from ai_incident_commander.application.remediation_preflight import RemediationPreflightResult
from ai_incident_commander.application.target_resolver import TargetSourceUnavailableError
from ai_incident_commander.application.target_verification import TargetIdentityMismatchError
from ai_incident_commander.domain.action_catalog import (
    ActionCatalog,
    ActionDefinition,
    ActionEffect,
    UnknownActionError,
)
from ai_incident_commander.domain.mcp_action_binding import (
    McpActionBindingNotFoundError,
    TrustedMcpActionBindings,
    TrustedMcpToolBinding,
)
from ai_incident_commander.domain.remediation import RemediationRiskLevel, RemediationStep
from ai_incident_commander.domain.remediation_approval import RemediationApprovalRequest
from ai_incident_commander.domain.target_identity import ResolvedTarget

_START = datetime(2026, 11, 15, 12, 0, tzinfo=UTC)


class RecordingResolver:
    def __init__(self, events: list[str]) -> None:
        self.events = events
        self.target = ResolvedTarget(
            target="payments-api",
            resource_id="service-123",
            environment="incident-lab",
            source="test-inventory",
        )
        self.error: Exception | None = None

    async def resolve(self, *, target: str, environment: str) -> ResolvedTarget:
        self.events.append("resolver")
        if self.error is not None:
            raise self.error
        return self.target


class RecordingClock:
    def __init__(self, events: list[str]) -> None:
        self.events = events
        self.value: object = _START

    def now(self) -> datetime:
        self.events.append("clock")
        assert isinstance(self.value, datetime)
        return self.value


class RecordingRepository:
    def __init__(self, events: list[str]) -> None:
        self.events = events
        self.saved: list[RemediationApprovalRequest] = []
        self.error: Exception | None = None

    async def create_request(self, request: RemediationApprovalRequest) -> None:
        self.events.append("create_request")
        if self.error is not None:
            raise self.error
        self.saved.append(request)

    async def get_request(self, request_id: UUID) -> RemediationApprovalRequest | None:
        return next((item for item in self.saved if item.request_id == request_id), None)

    async def get_decision(self, request_id: UUID) -> None:
        return None

    async def record_decision_once(self, decision: object) -> None:
        raise AssertionError("Approval creation must not record a decision.")


@dataclass
class Harness:
    service: ApprovalRequestCreationService
    catalog: ActionCatalog
    bindings: TrustedMcpActionBindings
    step: RemediationStep
    events: list[str]
    resolver: RecordingResolver
    clock: RecordingClock
    repository: RecordingRepository


def _binding(*, tool_name: str = "restart_service") -> TrustedMcpToolBinding:
    return TrustedMcpToolBinding(
        action_name="restart_service", server_id="deployment-mcp", tool_name=tool_name
    )


def _make_harness(
    *,
    bindings_enabled: bool = True,
    tool_name: str = "restart_service",
    registered: bool = True,
) -> Harness:
    events: list[str] = []
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
    bindings = TrustedMcpActionBindings(
        catalog=catalog,
        bindings=(_binding(tool_name=tool_name),) if registered else (),
    )
    step = RemediationStep(
        plan_id=uuid4(),
        position=1,
        action_name="restart_service",
        target="payments-api",
        environment="incident-lab",
        risk_level=RemediationRiskLevel.HIGH,
    )
    resolver = RecordingResolver(events)
    clock = RecordingClock(events)
    repository = RecordingRepository(events)
    service = ApprovalRequestCreationService(
        repository=repository,
        clock=clock,
        catalog=catalog,
        resolver=resolver,
        validity_period=timedelta(minutes=15),
        mcp_bindings=bindings if bindings_enabled else None,
    )
    return Harness(service, catalog, bindings, step, events, resolver, clock, repository)


def test_mcp_creation_persists_v2_policy_and_expected_fingerprint() -> None:
    harness = _make_harness()
    request = asyncio.run(harness.service.create_mcp_bound_for_step(harness.step))
    expected_preflight = RemediationPreflightResult(
        action=harness.catalog.definitions[0],
        target=harness.resolver.target,
        step_snapshot=harness.step,
        policy_version=request.policy_version,
    )

    assert harness.events == ["resolver", "clock", "create_request"]
    assert fullmatch(r"apv:v2:[0-9a-f]{64}", request.policy_version) is not None
    assert request.policy_version == create_mcp_bound_action_policy_version(
        catalog=harness.catalog, bindings=harness.bindings
    )
    assert request.action_fingerprint == create_action_fingerprint(harness.step, expected_preflight)
    assert request.plan_id == harness.step.plan_id
    assert request.step_id == harness.step.step_id
    assert request.requested_at == _START
    assert request.expires_at == _START + timedelta(minutes=15)
    assert harness.repository.saved == [request]


def test_regular_create_for_step_uses_v2_when_service_is_mcp_configured() -> None:
    harness = _make_harness()
    request = asyncio.run(harness.service.create_for_step(harness.step))
    assert request.policy_version.startswith("apv:v2:")
    assert harness.events == ["resolver", "clock", "create_request"]


def test_explicit_mcp_method_refuses_legacy_service_before_side_effects() -> None:
    harness = _make_harness(bindings_enabled=False)
    with pytest.raises(ApprovalRequestConfigurationError, match="MCP-bound"):
        asyncio.run(harness.service.create_mcp_bound_for_step(harness.step))
    assert harness.events == []
    assert harness.repository.saved == []


def test_legacy_creation_retains_v1_for_unconfigured_service() -> None:
    harness = _make_harness(bindings_enabled=False)
    request = asyncio.run(harness.service.create_for_step(harness.step))
    assert request.policy_version.startswith("apv:v1:")
    assert harness.events == ["resolver", "clock", "create_request"]


def test_wrong_bindings_type_rejected_in_constructor() -> None:
    harness = _make_harness()
    with pytest.raises(TypeError, match="trusted action bindings"):
        ApprovalRequestCreationService(
            repository=harness.repository,
            clock=harness.clock,
            catalog=harness.catalog,
            resolver=harness.resolver,
            validity_period=timedelta(minutes=15),
            mcp_bindings="untrusted",  # type: ignore[arg-type]
        )
    assert harness.events == []


def test_bindings_from_different_catalog_rejected_in_constructor() -> None:
    harness = _make_harness()
    changed_catalog = ActionCatalog(
        definitions=(replace(harness.catalog.definitions[0], description="Different policy"),)
    )
    with pytest.raises(ApprovalRequestConfigurationError, match="do not match"):
        ApprovalRequestCreationService(
            repository=harness.repository,
            clock=harness.clock,
            catalog=changed_catalog,
            resolver=harness.resolver,
            validity_period=timedelta(minutes=15),
            mcp_bindings=harness.bindings,
        )
    assert harness.events == []


@pytest.mark.parametrize("entrypoint", ["create_for_step", "create_mcp_bound_for_step"])
def test_unmapped_action_refuses_before_resolver_or_clock(entrypoint: str) -> None:
    harness = _make_harness(registered=False)
    with pytest.raises(McpActionBindingNotFoundError):
        asyncio.run(getattr(harness.service, entrypoint)(harness.step))
    assert harness.events == []
    assert harness.repository.saved == []


def test_invalid_action_refuses_before_resolver_or_clock() -> None:
    harness = _make_harness()
    with pytest.raises(UnknownActionError):
        asyncio.run(
            harness.service.create_mcp_bound_for_step(
                replace(harness.step, action_name="unknown_action")
            )
        )
    assert harness.events == []


def test_mcp_binding_drift_changes_policy_version_and_fingerprint() -> None:
    first = _make_harness(tool_name="restart_service")
    second_bindings = TrustedMcpActionBindings(
        catalog=first.catalog,
        bindings=(_binding(tool_name="force_restart_service"),),
    )
    second_service = ApprovalRequestCreationService(
        repository=first.repository,
        clock=first.clock,
        catalog=first.catalog,
        resolver=first.resolver,
        validity_period=timedelta(minutes=15),
        mcp_bindings=second_bindings,
    )
    first_request = asyncio.run(first.service.create_mcp_bound_for_step(first.step))
    second_request = asyncio.run(second_service.create_mcp_bound_for_step(first.step))

    assert first_request.policy_version != second_request.policy_version
    assert first_request.action_fingerprint != second_request.action_fingerprint
    assert len(first.repository.saved) == 2
    assert first.repository.saved[0] == first_request


def test_equivalent_mcp_bindings_produce_same_policy_version_and_fingerprint() -> None:
    harness = _make_harness()
    equivalent = TrustedMcpActionBindings(
        catalog=ActionCatalog(definitions=harness.catalog.definitions),
        bindings=(_binding(),),
    )
    other_service = ApprovalRequestCreationService(
        repository=harness.repository,
        clock=harness.clock,
        catalog=harness.catalog,
        resolver=harness.resolver,
        validity_period=timedelta(minutes=15),
        mcp_bindings=equivalent,
    )
    first = asyncio.run(harness.service.create_mcp_bound_for_step(harness.step))
    second = asyncio.run(other_service.create_mcp_bound_for_step(harness.step))
    assert first.policy_version == second.policy_version
    assert first.action_fingerprint == second.action_fingerprint


def test_resolver_unavailable_aborts_before_clock_or_persistence() -> None:
    harness = _make_harness()
    error = TargetSourceUnavailableError("Inventory offline")
    harness.resolver.error = error
    with pytest.raises(TargetSourceUnavailableError) as captured:
        asyncio.run(harness.service.create_mcp_bound_for_step(harness.step))
    assert captured.value is error
    assert harness.events == ["resolver"]
    assert harness.repository.saved == []


def test_resolved_environment_mismatch_aborts_before_clock_or_persistence() -> None:
    harness = _make_harness()
    harness.resolver.target = replace(harness.resolver.target, environment="production")
    with pytest.raises(TargetIdentityMismatchError):
        asyncio.run(harness.service.create_mcp_bound_for_step(harness.step))
    assert harness.events == ["resolver"]
    assert harness.repository.saved == []


def test_invalid_clock_aborts_after_preflight_without_persistence() -> None:
    harness = _make_harness()
    harness.clock.value = datetime(2026, 11, 15, 12)
    with pytest.raises(ApprovalRequestClockError):
        asyncio.run(harness.service.create_mcp_bound_for_step(harness.step))
    assert harness.events == ["resolver", "clock"]
    assert harness.repository.saved == []


def test_repository_error_is_propagated_without_retry() -> None:
    harness = _make_harness()
    error = RuntimeError("PostgreSQL unavailable")
    harness.repository.error = error
    with pytest.raises(RuntimeError) as captured:
        asyncio.run(harness.service.create_mcp_bound_for_step(harness.step))
    assert captured.value is error
    assert harness.events == ["resolver", "clock", "create_request"]
    assert harness.repository.saved == []
