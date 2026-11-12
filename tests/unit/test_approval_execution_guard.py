"""Unit tests for approval eligibility before any remediation execution claim."""

import asyncio
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest

from ai_incident_commander.application.approval_execution_guard import (
    ApprovalExecutionDeniedError,
    ApprovalExecutionGuard,
    ApprovalExecutionScopeMismatchError,
)
from ai_incident_commander.application.approval_request_service import (
    ApprovalRequestCreationService,
)
from ai_incident_commander.domain.action_catalog import (
    ActionCatalog,
    ActionDefinition,
    ActionEffect,
)
from ai_incident_commander.domain.remediation import RemediationRiskLevel, RemediationStep
from ai_incident_commander.domain.remediation_approval import (
    RemediationApprovalDecision,
    RemediationApprovalOutcome,
    RemediationApprovalRequest,
)
from ai_incident_commander.domain.target_identity import ResolvedTarget

_NOW = datetime(2026, 11, 11, 12, 0, tzinfo=UTC)


class FixedClock:
    def now(self) -> datetime:
        return _NOW


class RecordingResolver:
    def __init__(self, target: ResolvedTarget) -> None:
        self.target = target
        self.calls: list[tuple[str, str]] = []

    async def resolve(self, *, target: str, environment: str) -> ResolvedTarget:
        self.calls.append((target, environment))
        return self.target


class MemoryApprovalRepository:
    """Test-only implementation of the complete approval persistence port."""

    def __init__(self) -> None:
        self.request: RemediationApprovalRequest | None = None
        self.decision: RemediationApprovalDecision | None = None
        self.reads: list[str] = []

    async def create_request(self, request: RemediationApprovalRequest) -> None:
        self.request = request

    async def get_request(self, request_id: UUID) -> RemediationApprovalRequest | None:
        self.reads.append("request")
        if self.request is not None and self.request.request_id == request_id:
            return self.request
        return None

    async def get_decision(self, request_id: UUID) -> RemediationApprovalDecision | None:
        self.reads.append("decision")
        return self.decision

    async def record_decision_once(self, decision: RemediationApprovalDecision) -> None:
        if self.decision is not None:
            raise AssertionError("Test fixture already contains a decision.")
        self.decision = decision


@dataclass
class Harness:
    guard: ApprovalExecutionGuard
    step: RemediationStep
    request: RemediationApprovalRequest
    repository: MemoryApprovalRepository
    resolver: RecordingResolver


def _make_harness() -> Harness:
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
    resolver = RecordingResolver(
        ResolvedTarget(
            target="payments-api",
            resource_id="service-123",
            environment="incident-lab",
            source="test-inventory",
        )
    )
    repository = MemoryApprovalRepository()
    creator = ApprovalRequestCreationService(
        repository=repository,
        clock=FixedClock(),
        catalog=catalog,
        resolver=resolver,
        validity_period=timedelta(minutes=15),
    )
    request = asyncio.run(creator.create_for_step(step))
    resolver.calls.clear()
    guard = ApprovalExecutionGuard(repository=repository, catalog=catalog, resolver=resolver)
    return Harness(guard, step, request, repository, resolver)


def _decide(harness: Harness, outcome: RemediationApprovalOutcome) -> None:
    harness.repository.decision = RemediationApprovalDecision(
        request_id=harness.request.request_id,
        operator_id="authorized-operator",
        outcome=outcome,
        decided_at=_NOW + timedelta(minutes=1),
        reason="Reviewed in unit test.",
    )


def _validate(harness: Harness, step: RemediationStep | None = None) -> None:
    asyncio.run(
        harness.guard.validate_for_step(
            request_id=harness.request.request_id,
            step=step if step is not None else harness.step,
        )
    )


def test_missing_request_denies_without_reading_decision_or_resolving_target() -> None:
    harness = _make_harness()
    harness.repository.request = None

    with pytest.raises(ApprovalExecutionDeniedError, match="request does not exist"):
        _validate(harness)

    assert harness.repository.reads == ["request"]
    assert harness.resolver.calls == []


def test_pending_request_denies_before_preflight() -> None:
    harness = _make_harness()

    with pytest.raises(ApprovalExecutionDeniedError, match="decision does not exist"):
        _validate(harness)

    assert harness.repository.reads == ["request", "decision"]
    assert harness.resolver.calls == []


def test_rejected_decision_denies_before_preflight() -> None:
    harness = _make_harness()
    _decide(harness, RemediationApprovalOutcome.REJECTED)

    with pytest.raises(ApprovalExecutionDeniedError, match="not been approved"):
        _validate(harness)

    assert harness.resolver.calls == []


def test_matching_approved_decision_passes_current_preflight() -> None:
    harness = _make_harness()
    _decide(harness, RemediationApprovalOutcome.APPROVED)

    _validate(harness)

    assert harness.repository.reads == ["request", "decision"]
    assert harness.resolver.calls == [("payments-api", "incident-lab")]


def test_different_step_identity_denied_before_preflight() -> None:
    harness = _make_harness()
    _decide(harness, RemediationApprovalOutcome.APPROVED)

    with pytest.raises(ApprovalExecutionScopeMismatchError, match="step identity"):
        _validate(harness, replace(harness.step, step_id=uuid4()))

    assert harness.resolver.calls == []


def test_changed_step_position_denies_due_to_fingerprint_mismatch() -> None:
    harness = _make_harness()
    _decide(harness, RemediationApprovalOutcome.APPROVED)

    with pytest.raises(ApprovalExecutionScopeMismatchError, match="fingerprint"):
        _validate(harness, replace(harness.step, position=2))

    assert harness.resolver.calls == [("payments-api", "incident-lab")]


def test_changed_resolved_resource_denies_due_to_fingerprint_mismatch() -> None:
    harness = _make_harness()
    _decide(harness, RemediationApprovalOutcome.APPROVED)
    harness.resolver.target = replace(harness.resolver.target, resource_id="service-replaced")

    with pytest.raises(ApprovalExecutionScopeMismatchError, match="fingerprint"):
        _validate(harness)


def test_mismatched_policy_version_denies_before_fingerprint_check() -> None:
    harness = _make_harness()
    _decide(harness, RemediationApprovalOutcome.APPROVED)
    harness.repository.request = replace(harness.request, policy_version="apv:v1:" + "f" * 64)

    with pytest.raises(ApprovalExecutionScopeMismatchError, match="policy version"):
        _validate(harness)


def test_inconsistent_persisted_decision_denied() -> None:
    harness = _make_harness()
    _decide(harness, RemediationApprovalOutcome.APPROVED)
    assert harness.repository.decision is not None
    harness.repository.decision = replace(harness.repository.decision, request_id=uuid4())

    with pytest.raises(ApprovalExecutionDeniedError, match="inconsistent"):
        _validate(harness)

    assert harness.resolver.calls == []
