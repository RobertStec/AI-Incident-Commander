"""Unit tests for trusted orchestration of one scope-bound dispatch reservation."""

import asyncio
from dataclasses import FrozenInstanceError, dataclass
from datetime import UTC, datetime
from unittest.mock import AsyncMock, Mock, call
from uuid import UUID, uuid4

import pytest

from ai_incident_commander.application.approval_execution_guard import (
    ApprovalExecutionDeniedError,
    ApprovalExecutionGuard,
    ApprovalExecutionScopeMismatchError,
    VerifiedExecutionContext,
    VerifiedExecutionScope,
)
from ai_incident_commander.application.execution_claim_repository import ExecutionClaimRepository
from ai_incident_commander.application.remediation_dispatch_repository import (
    RemediationDispatchAlreadyReservedError,
    RemediationDispatchApprovalDeniedError,
    RemediationDispatchExecutionNotExecutingError,
    RemediationDispatchExecutionNotFoundError,
    RemediationDispatchScopeMismatchError,
    RemediationVerifiedDispatchRepository,
)
from ai_incident_commander.application.remediation_execution_repository import (
    RemediationExecutionClaimNotFoundError,
    RemediationExecutionRepository,
)
from ai_incident_commander.application.remediation_trusted_dispatch_service import (
    RemediationTrustedDispatchService,
    ReservedVerifiedDispatch,
)
from ai_incident_commander.domain.execution_claim import ExecutionClaim
from ai_incident_commander.domain.remediation import RemediationRiskLevel, RemediationStep
from ai_incident_commander.domain.remediation_dispatch import RemediationDispatch
from ai_incident_commander.domain.remediation_execution import RemediationExecution
from ai_incident_commander.domain.target_identity import ResolvedTarget

_NOW = datetime(2026, 11, 14, 19, 0, tzinfo=UTC)
_FINGERPRINT = "afp:v2:" + "a" * 64
_POLICY_VERSION = "apv:v1:" + "b" * 64


@dataclass
class Harness:
    service: RemediationTrustedDispatchService
    request_id: UUID
    step: RemediationStep
    context: VerifiedExecutionContext
    claim: ExecutionClaim
    execution: RemediationExecution
    dispatch: RemediationDispatch
    guard: Mock
    claims: Mock
    executions: Mock
    reservations: Mock


def _harness() -> Harness:
    request_id = uuid4()
    step = RemediationStep(
        plan_id=uuid4(),
        position=1,
        action_name="restart_service",
        target="payments-api",
        environment="incident-lab",
        risk_level=RemediationRiskLevel.HIGH,
    )
    scope = VerifiedExecutionScope(
        request_id=request_id,
        plan_id=step.plan_id,
        step_id=step.step_id,
        action_fingerprint=_FINGERPRINT,
        policy_version=_POLICY_VERSION,
    )
    context = VerifiedExecutionContext(
        scope=scope,
        target=ResolvedTarget(
            target=step.target,
            resource_id="service-123",
            environment=step.environment,
            source="test-inventory",
        ),
    )
    claim = ExecutionClaim(
        request_id=request_id,
        plan_id=step.plan_id,
        step_id=step.step_id,
        action_fingerprint=_FINGERPRINT,
        policy_version=_POLICY_VERSION,
        claimed_at=_NOW,
    )
    execution = RemediationExecution(claim_id=claim.claim_id, started_at=_NOW)
    dispatch = RemediationDispatch(execution_id=execution.execution_id, reserved_at=_NOW)

    guard = Mock(spec=ApprovalExecutionGuard)
    guard.verify_execution_context_for_step = AsyncMock(return_value=context)
    claims = Mock(spec=ExecutionClaimRepository)
    claims.get_by_request_id = AsyncMock(return_value=claim)
    executions = Mock(spec=RemediationExecutionRepository)
    executions.get_by_claim_id = AsyncMock(return_value=execution)
    reservations = Mock(spec=RemediationVerifiedDispatchRepository)
    reservations.reserve_verified_once = AsyncMock(return_value=dispatch)
    service = RemediationTrustedDispatchService(
        guard=guard,
        claim_repository=claims,
        execution_repository=executions,
        dispatch_repository=reservations,
    )
    return Harness(
        service=service,
        request_id=request_id,
        step=step,
        context=context,
        claim=claim,
        execution=execution,
        dispatch=dispatch,
        guard=guard,
        claims=claims,
        executions=executions,
        reservations=reservations,
    )


def _reserve(harness: Harness) -> ReservedVerifiedDispatch:
    return asyncio.run(
        harness.service.reserve_for_step(request_id=harness.request_id, step=harness.step)
    )


def test_reservation_uses_existing_execution_and_fresh_verified_context() -> None:
    harness = _harness()
    trace = Mock()
    trace.attach_mock(harness.claims.get_by_request_id, "claim")
    trace.attach_mock(harness.executions.get_by_claim_id, "execution")
    trace.attach_mock(harness.guard.verify_execution_context_for_step, "guard")
    trace.attach_mock(harness.reservations.reserve_verified_once, "reserve")

    result = _reserve(harness)

    assert result == ReservedVerifiedDispatch(dispatch=harness.dispatch, context=harness.context)
    assert result.dispatch.execution_id == harness.execution.execution_id
    assert result.context.target.resource_id == "service-123"
    assert trace.mock_calls == [
        call.claim(request_id=harness.request_id),
        call.execution(claim_id=harness.claim.claim_id),
        call.guard(request_id=harness.request_id, step=harness.step),
        call.reserve(
            execution_id=harness.execution.execution_id,
            verified_scope=harness.context.scope,
        ),
    ]
    harness.guard.verify_scope_for_step.assert_not_called()
    harness.executions.start_once.assert_not_called()


def test_missing_claim_fails_before_execution_lookup_or_guard() -> None:
    harness = _harness()
    harness.claims.get_by_request_id.return_value = None

    with pytest.raises(RemediationExecutionClaimNotFoundError):
        _reserve(harness)

    harness.executions.get_by_claim_id.assert_not_awaited()
    harness.guard.verify_execution_context_for_step.assert_not_awaited()
    harness.reservations.reserve_verified_once.assert_not_awaited()


def test_missing_execution_fails_before_guard_and_reservation() -> None:
    harness = _harness()
    harness.executions.get_by_claim_id.return_value = None

    with pytest.raises(RemediationDispatchExecutionNotFoundError):
        _reserve(harness)

    harness.guard.verify_execution_context_for_step.assert_not_awaited()
    harness.reservations.reserve_verified_once.assert_not_awaited()


@pytest.mark.parametrize(
    "denial",
    [
        ApprovalExecutionDeniedError("Approval was denied"),
        ApprovalExecutionScopeMismatchError("Current target changed"),
    ],
)
def test_guard_refusal_prevents_reservation(denial: Exception) -> None:
    harness = _harness()
    harness.guard.verify_execution_context_for_step.side_effect = denial

    with pytest.raises(type(denial), match=str(denial)):
        _reserve(harness)

    harness.reservations.reserve_verified_once.assert_not_awaited()


def test_unexpected_guard_error_propagates_without_reservation() -> None:
    harness = _harness()
    harness.guard.verify_execution_context_for_step.side_effect = RuntimeError("resolver offline")
    with pytest.raises(RuntimeError, match="resolver offline"):
        _reserve(harness)
    harness.reservations.reserve_verified_once.assert_not_awaited()


def test_claim_lookup_error_propagates_without_retry() -> None:
    harness = _harness()
    harness.claims.get_by_request_id.side_effect = RuntimeError("database unavailable")
    with pytest.raises(RuntimeError, match="database unavailable"):
        _reserve(harness)
    harness.claims.get_by_request_id.assert_awaited_once()
    harness.guard.verify_execution_context_for_step.assert_not_awaited()


def test_execution_lookup_error_propagates_without_retry() -> None:
    harness = _harness()
    harness.executions.get_by_claim_id.side_effect = RuntimeError("database unavailable")
    with pytest.raises(RuntimeError, match="database unavailable"):
        _reserve(harness)
    harness.executions.get_by_claim_id.assert_awaited_once()
    harness.guard.verify_execution_context_for_step.assert_not_awaited()


@pytest.mark.parametrize(
    "refusal",
    [
        RemediationDispatchApprovalDeniedError("Approval no longer valid"),
        RemediationDispatchScopeMismatchError("Execution mismatch"),
        RemediationDispatchAlreadyReservedError("Already reserved"),
        RemediationDispatchExecutionNotExecutingError("Already terminal"),
    ],
)
def test_atomic_database_refusal_propagates_unchanged(refusal: Exception) -> None:
    harness = _harness()
    harness.reservations.reserve_verified_once.side_effect = refusal

    with pytest.raises(type(refusal), match=str(refusal)):
        _reserve(harness)

    harness.reservations.reserve_verified_once.assert_awaited_once_with(
        execution_id=harness.execution.execution_id,
        verified_scope=harness.context.scope,
    )
    harness.executions.start_once.assert_not_called()


def test_unexpected_database_reservation_failure_is_not_retried() -> None:
    harness = _harness()
    harness.reservations.reserve_verified_once.side_effect = RuntimeError("connection lost")
    with pytest.raises(RuntimeError, match="connection lost"):
        _reserve(harness)
    harness.reservations.reserve_verified_once.assert_awaited_once()


def test_identical_second_request_must_reach_database_and_be_refused() -> None:
    harness = _harness()
    harness.reservations.reserve_verified_once.side_effect = [
        harness.dispatch,
        RemediationDispatchAlreadyReservedError("Already reserved"),
    ]
    assert _reserve(harness).dispatch is harness.dispatch
    with pytest.raises(RemediationDispatchAlreadyReservedError):
        _reserve(harness)
    assert harness.reservations.reserve_verified_once.await_count == 2
    assert harness.guard.verify_execution_context_for_step.await_count == 2


def test_returned_record_is_immutable_and_does_not_grant_mcp_retry() -> None:
    harness = _harness()
    result = _reserve(harness)
    with pytest.raises(FrozenInstanceError):
        result.context = harness.context  # type: ignore[misc]
    assert result.dispatch == harness.dispatch
