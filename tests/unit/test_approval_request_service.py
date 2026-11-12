"""Unit tests for creation of approval requests from trusted remediation preflight."""

import asyncio
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta, timezone
from re import fullmatch
from typing import cast
from uuid import UUID, uuid4

import pytest

from ai_incident_commander.application.action_fingerprint import create_action_fingerprint
from ai_incident_commander.application.action_policy_version import create_action_policy_version
from ai_incident_commander.application.approval_repository import (
    ApprovalRepository,
    ApprovalRequestAlreadyExistsError,
)
from ai_incident_commander.application.approval_request_service import (
    ApprovalRequestClockError,
    ApprovalRequestConfigurationError,
    ApprovalRequestCreationService,
)
from ai_incident_commander.application.clock import Clock
from ai_incident_commander.application.remediation_preflight import RemediationPreflightResult
from ai_incident_commander.application.target_resolver import (
    TargetResolver,
    TargetSourceUnavailableError,
)
from ai_incident_commander.application.target_verification import TargetIdentityMismatchError
from ai_incident_commander.domain.action_catalog import (
    ActionCatalog,
    ActionDefinition,
    ActionEffect,
    UnknownActionError,
)
from ai_incident_commander.domain.remediation import RemediationRiskLevel, RemediationStep
from ai_incident_commander.domain.remediation_approval import (
    RemediationApprovalDecision,
    RemediationApprovalRequest,
)
from ai_incident_commander.domain.target_identity import ResolvedTarget

_START = datetime(2026, 11, 11, 12, 0, tzinfo=UTC)
_VALIDITY_PERIOD = timedelta(minutes=15)


class RecordingClock:
    def __init__(self, now: object, events: list[str]) -> None:
        self.value = now
        self.events = events
        self.read_count = 0

    def now(self) -> datetime:
        self.events.append("clock")
        self.read_count += 1
        return cast(datetime, self.value)


class RecordingResolver:
    def __init__(self, target: ResolvedTarget, events: list[str]) -> None:
        self.target = target
        self.events = events
        self.error: Exception | None = None
        self.calls: list[tuple[str, str]] = []

    async def resolve(self, *, target: str, environment: str) -> ResolvedTarget:
        self.events.append("resolver")
        self.calls.append((target, environment))
        if self.error is not None:
            raise self.error
        return self.target


class RecordingRepository:
    def __init__(self, events: list[str]) -> None:
        self.events = events
        self.attempts: list[RemediationApprovalRequest] = []
        self.saved: list[RemediationApprovalRequest] = []
        self.error: Exception | None = None

    async def create_request(self, request: RemediationApprovalRequest) -> None:
        self.events.append("create_request")
        self.attempts.append(request)
        if self.error is not None:
            raise self.error
        self.saved.append(request)

    async def get_request(self, request_id: UUID) -> RemediationApprovalRequest | None:
        return next((request for request in self.saved if request.request_id == request_id), None)

    async def record_decision_once(self, decision: RemediationApprovalDecision) -> None:
        raise AssertionError("Request creation must never record an approval decision.")


@dataclass
class Harness:
    service: ApprovalRequestCreationService
    step: RemediationStep
    catalog: ActionCatalog
    resolver: RecordingResolver
    repository: RecordingRepository
    clock: RecordingClock
    events: list[str]


def _make_harness(
    *,
    now: object = _START,
    validity_period: timedelta = _VALIDITY_PERIOD,
) -> Harness:
    events: list[str] = []
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
    resolved_target = ResolvedTarget(
        target="payments-api",
        resource_id="service-123",
        environment="incident-lab",
        source="test-inventory",
    )
    resolver = RecordingResolver(resolved_target, events)
    repository = RecordingRepository(events)
    clock = RecordingClock(now, events)
    repository_port: ApprovalRepository = repository
    resolver_port: TargetResolver = resolver
    clock_port: Clock = clock
    service = ApprovalRequestCreationService(
        repository=repository_port,
        clock=clock_port,
        catalog=catalog,
        resolver=resolver_port,
        validity_period=validity_period,
    )
    return Harness(service, step, catalog, resolver, repository, clock, events)


def test_creates_persisted_request_from_trusted_preflight() -> None:
    harness = _make_harness()

    request = asyncio.run(harness.service.create_for_step(harness.step))

    assert harness.events == ["resolver", "clock", "create_request"]
    assert harness.resolver.calls == [("payments-api", "incident-lab")]
    assert harness.clock.read_count == 1
    assert harness.repository.attempts == [request]
    assert harness.repository.saved == [request]
    assert request.plan_id == harness.step.plan_id
    assert request.step_id == harness.step.step_id
    assert isinstance(request.request_id, UUID)
    assert request.requested_at == _START
    assert request.expires_at == _START + _VALIDITY_PERIOD
    assert request.policy_version == create_action_policy_version(harness.catalog)
    assert fullmatch(r"afp:v2:[0-9a-f]{64}", request.action_fingerprint) is not None
    assert request.action_fingerprint == create_action_fingerprint(
        harness.step,
        RemediationPreflightResult(
            action=harness.catalog.definitions[0],
            target=harness.resolver.target,
            step_snapshot=harness.step,
            policy_version=request.policy_version,
        ),
    )


@pytest.mark.parametrize(
    "invalid_period",
    [timedelta(0), timedelta(microseconds=-1), cast(timedelta, None)],
)
def test_rejects_invalid_validity_period_without_side_effects(
    invalid_period: timedelta,
) -> None:
    harness = _make_harness()

    with pytest.raises(ApprovalRequestConfigurationError):
        ApprovalRequestCreationService(
            repository=harness.repository,
            clock=harness.clock,
            catalog=harness.catalog,
            resolver=harness.resolver,
            validity_period=invalid_period,
        )

    assert harness.events == []
    assert harness.repository.saved == []


def test_invalid_action_fails_before_resolver_clock_and_repository() -> None:
    harness = _make_harness()
    step = replace(harness.step, action_name="untrusted_action")

    with pytest.raises(UnknownActionError):
        asyncio.run(harness.service.create_for_step(step))

    assert harness.events == []
    assert harness.clock.read_count == 0
    assert harness.repository.attempts == []


def test_resolver_failure_does_not_create_request() -> None:
    harness = _make_harness()
    expected_error = TargetSourceUnavailableError("Test resolver unavailable.")
    harness.resolver.error = expected_error

    with pytest.raises(TargetSourceUnavailableError) as captured:
        asyncio.run(harness.service.create_for_step(harness.step))

    assert captured.value is expected_error
    assert harness.events == ["resolver"]
    assert harness.clock.read_count == 0
    assert harness.repository.attempts == []


def test_mismatched_target_does_not_create_request() -> None:
    harness = _make_harness()
    harness.resolver.target = replace(harness.resolver.target, environment="production")

    with pytest.raises(TargetIdentityMismatchError):
        asyncio.run(harness.service.create_for_step(harness.step))

    assert harness.events == ["resolver"]
    assert harness.clock.read_count == 0
    assert harness.repository.attempts == []


@pytest.mark.parametrize(
    "invalid_time",
    [
        datetime(2026, 11, 11, 12),
        datetime(2026, 11, 11, 12, tzinfo=timezone(timedelta(hours=1))),
        None,
    ],
)
def test_invalid_clock_prevents_persistence(invalid_time: object) -> None:
    harness = _make_harness(now=invalid_time)

    with pytest.raises(ApprovalRequestClockError):
        asyncio.run(harness.service.create_for_step(harness.step))

    assert harness.events == ["resolver", "clock"]
    assert harness.repository.attempts == []


def test_clock_overflow_prevents_persistence() -> None:
    harness = _make_harness(now=datetime.max.replace(tzinfo=UTC))

    with pytest.raises(ApprovalRequestClockError, match="out of range"):
        asyncio.run(harness.service.create_for_step(harness.step))

    assert harness.repository.attempts == []


def test_repository_error_is_propagated_after_preflight_and_clock() -> None:
    harness = _make_harness()
    error = ApprovalRequestAlreadyExistsError("Duplicate approval request identifier.")
    harness.repository.error = error

    with pytest.raises(ApprovalRequestAlreadyExistsError) as captured:
        asyncio.run(harness.service.create_for_step(harness.step))

    assert captured.value is error
    assert harness.events == ["resolver", "clock", "create_request"]
    assert len(harness.repository.attempts) == 1
    assert harness.repository.saved == []
