"""Unit tests for coordinating the trusted approval guard and a claim repository."""

import asyncio
from dataclasses import dataclass
from datetime import UTC, datetime
from unittest.mock import create_autospec
from uuid import UUID, uuid4

import pytest

from ai_incident_commander.application.approval_execution_guard import (
    ApprovalExecutionDeniedError,
    ApprovalExecutionGuard,
    ApprovalExecutionScopeMismatchError,
    VerifiedExecutionScope,
)
from ai_incident_commander.application.execution_claim_repository import (
    ExecutionClaimAlreadyExistsError,
    ExecutionClaimApprovalDeniedError,
    ExecutionClaimScopeMismatchError,
)
from ai_incident_commander.application.execution_claim_service import ExecutionClaimService
from ai_incident_commander.domain.execution_claim import ExecutionClaim
from ai_incident_commander.domain.remediation import RemediationRiskLevel, RemediationStep

_FINGERPRINT = "afp:v2:" + "a" * 64
_POLICY_VERSION = "apv:v1:" + "b" * 64


class RecordingClaimRepository:
    def __init__(self, claim: ExecutionClaim) -> None:
        self.claim = claim
        self.error: Exception | None = None
        self.calls: list[dict[str, UUID | str]] = []

    async def claim_once(
        self,
        *,
        request_id: UUID,
        plan_id: UUID,
        step_id: UUID,
        action_fingerprint: str,
        policy_version: str,
    ) -> ExecutionClaim:
        self.calls.append(
            {
                "request_id": request_id,
                "plan_id": plan_id,
                "step_id": step_id,
                "action_fingerprint": action_fingerprint,
                "policy_version": policy_version,
            }
        )
        if self.error is not None:
            raise self.error
        return self.claim


@dataclass
class Harness:
    service: ExecutionClaimService
    guard: ApprovalExecutionGuard
    repository: RecordingClaimRepository
    request_id: UUID
    step: RemediationStep
    scope: VerifiedExecutionScope
    claim: ExecutionClaim


def _make_harness() -> Harness:
    plan_id = uuid4()
    request_id = uuid4()
    step = RemediationStep(
        plan_id=plan_id,
        position=1,
        action_name="restart_service",
        target="payments-api",
        environment="incident-lab",
        risk_level=RemediationRiskLevel.HIGH,
    )
    scope = VerifiedExecutionScope(
        request_id=request_id,
        plan_id=plan_id,
        step_id=step.step_id,
        action_fingerprint=_FINGERPRINT,
        policy_version=_POLICY_VERSION,
    )
    claim = ExecutionClaim(
        request_id=scope.request_id,
        plan_id=scope.plan_id,
        step_id=scope.step_id,
        action_fingerprint=scope.action_fingerprint,
        policy_version=scope.policy_version,
        claimed_at=datetime(2026, 11, 12, 12, 0, tzinfo=UTC),
    )
    guard = create_autospec(ApprovalExecutionGuard, instance=True)
    guard.verify_scope_for_step.return_value = scope
    repository = RecordingClaimRepository(claim)
    service = ExecutionClaimService(guard=guard, repository=repository)
    return Harness(service, guard, repository, request_id, step, scope, claim)


def _claim(harness: Harness) -> ExecutionClaim:
    return asyncio.run(
        harness.service.claim_for_step(request_id=harness.request_id, step=harness.step)
    )


def test_claim_forwards_exactly_guard_verified_scope_and_returns_committed_claim() -> None:
    harness = _make_harness()

    result = _claim(harness)

    assert result is harness.claim
    harness.guard.verify_scope_for_step.assert_awaited_once_with(
        request_id=harness.request_id, step=harness.step
    )
    assert harness.repository.calls == [
        {
            "request_id": harness.scope.request_id,
            "plan_id": harness.scope.plan_id,
            "step_id": harness.scope.step_id,
            "action_fingerprint": harness.scope.action_fingerprint,
            "policy_version": harness.scope.policy_version,
        }
    ]
    harness.guard.validate_for_step.assert_not_called()


@pytest.mark.parametrize(
    "failure",
    [
        ApprovalExecutionDeniedError("Approval is missing or rejected."),
        ApprovalExecutionScopeMismatchError("Approval scope has changed."),
    ],
)
def test_guard_denial_never_calls_claim_repository(failure: Exception) -> None:
    harness = _make_harness()
    harness.guard.verify_scope_for_step.side_effect = failure

    with pytest.raises(type(failure)) as captured:
        _claim(harness)

    assert captured.value is failure
    harness.guard.verify_scope_for_step.assert_awaited_once()
    assert harness.repository.calls == []


@pytest.mark.parametrize(
    "failure",
    [
        ExecutionClaimAlreadyExistsError("The step is already claimed."),
        ExecutionClaimApprovalDeniedError("Stored approval is not valid."),
        ExecutionClaimScopeMismatchError("Stored scope does not match."),
    ],
)
def test_repository_refusal_propagates_without_retry(failure: Exception) -> None:
    harness = _make_harness()
    harness.repository.error = failure

    with pytest.raises(type(failure)) as captured:
        _claim(harness)

    assert captured.value is failure
    harness.guard.verify_scope_for_step.assert_awaited_once()
    assert len(harness.repository.calls) == 1


def test_unexpected_repository_error_is_not_converted_to_a_success() -> None:
    harness = _make_harness()
    failure = RuntimeError("Database connection failed.")
    harness.repository.error = failure

    with pytest.raises(RuntimeError) as captured:
        _claim(harness)

    assert captured.value is failure
    harness.guard.verify_scope_for_step.assert_awaited_once()
    assert len(harness.repository.calls) == 1


def test_second_call_does_not_hide_existing_claim_refusal() -> None:
    harness = _make_harness()
    assert _claim(harness) is harness.claim

    harness.repository.error = ExecutionClaimAlreadyExistsError("Already claimed.")
    with pytest.raises(ExecutionClaimAlreadyExistsError):
        _claim(harness)

    assert harness.guard.verify_scope_for_step.await_count == 2
    assert len(harness.repository.calls) == 2
