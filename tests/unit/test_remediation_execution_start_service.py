"""Unit tests for the fail-closed claim-to-execution-start orchestration."""

import asyncio
from dataclasses import dataclass
from datetime import UTC, datetime
from unittest.mock import create_autospec
from uuid import UUID, uuid4

import pytest

from ai_incident_commander.application.approval_execution_guard import (
    ApprovalExecutionDeniedError,
    ApprovalExecutionScopeMismatchError,
)
from ai_incident_commander.application.execution_claim_repository import (
    ExecutionClaimAlreadyExistsError,
    ExecutionClaimApprovalDeniedError,
    ExecutionClaimScopeMismatchError,
)
from ai_incident_commander.application.execution_claim_service import ExecutionClaimService
from ai_incident_commander.application.remediation_execution_repository import (
    RemediationExecutionAlreadyStartedError,
    RemediationExecutionClaimNotFoundError,
)
from ai_incident_commander.application.remediation_execution_start_service import (
    RemediationExecutionStartService,
)
from ai_incident_commander.domain.execution_claim import ExecutionClaim
from ai_incident_commander.domain.remediation import RemediationRiskLevel, RemediationStep
from ai_incident_commander.domain.remediation_execution import (
    RemediationExecution,
    RemediationExecutionStatus,
)

_FINGERPRINT = "afp:v2:" + "a" * 64
_POLICY_VERSION = "apv:v1:" + "b" * 64


class RecordingExecutionRepository:
    def __init__(self, execution: RemediationExecution) -> None:
        self.execution = execution
        self.error: Exception | None = None
        self.calls: list[UUID] = []

    async def start_once(self, *, claim_id: UUID) -> RemediationExecution:
        self.calls.append(claim_id)
        if self.error is not None:
            raise self.error
        return self.execution


@dataclass
class Harness:
    service: RemediationExecutionStartService
    claim_service: ExecutionClaimService
    execution_repository: RecordingExecutionRepository
    request_id: UUID
    step: RemediationStep
    claim: ExecutionClaim
    execution: RemediationExecution


def _make_harness() -> Harness:
    step = RemediationStep(
        plan_id=uuid4(),
        position=1,
        action_name="restart_service",
        target="payments-api",
        environment="incident-lab",
        risk_level=RemediationRiskLevel.HIGH,
    )
    request_id = uuid4()
    claim = ExecutionClaim(
        request_id=request_id,
        plan_id=step.plan_id,
        step_id=step.step_id,
        action_fingerprint=_FINGERPRINT,
        policy_version=_POLICY_VERSION,
        claimed_at=datetime(2026, 11, 13, 10, 0, tzinfo=UTC),
    )
    execution = RemediationExecution(
        claim_id=claim.claim_id,
        started_at=datetime(2026, 11, 13, 10, 1, tzinfo=UTC),
    )
    claim_service = create_autospec(ExecutionClaimService, instance=True)
    claim_service.claim_for_step.return_value = claim
    execution_repository = RecordingExecutionRepository(execution)
    service = RemediationExecutionStartService(
        claim_service=claim_service,
        execution_repository=execution_repository,
    )
    return Harness(
        service,
        claim_service,
        execution_repository,
        request_id,
        step,
        claim,
        execution,
    )


def _start(harness: Harness) -> RemediationExecution:
    return asyncio.run(
        harness.service.start_for_step(request_id=harness.request_id, step=harness.step)
    )


def test_start_for_step_passes_committed_claim_id_and_returns_execution() -> None:
    harness = _make_harness()

    result = _start(harness)

    assert result is harness.execution
    assert result.status is RemediationExecutionStatus.EXECUTING
    assert harness.claim.claim_id != harness.step.step_id
    assert harness.claim.claim_id != harness.request_id
    harness.claim_service.claim_for_step.assert_awaited_once_with(
        request_id=harness.request_id, step=harness.step
    )
    assert harness.execution_repository.calls == [harness.claim.claim_id]


@pytest.mark.parametrize(
    "failure",
    [
        ApprovalExecutionDeniedError("Approval denied."),
        ApprovalExecutionScopeMismatchError("Preflight scope changed."),
        ExecutionClaimAlreadyExistsError("Already claimed."),
        ExecutionClaimApprovalDeniedError("Stored decision denied."),
        ExecutionClaimScopeMismatchError("Stored scope mismatch."),
    ],
)
def test_claim_failure_never_starts_execution(failure: Exception) -> None:
    harness = _make_harness()
    harness.claim_service.claim_for_step.side_effect = failure

    with pytest.raises(type(failure)) as captured:
        _start(harness)

    assert captured.value is failure
    harness.claim_service.claim_for_step.assert_awaited_once_with(
        request_id=harness.request_id, step=harness.step
    )
    assert harness.execution_repository.calls == []


def test_unexpected_claim_error_never_starts_execution() -> None:
    harness = _make_harness()
    failure = RuntimeError("Claim database connection lost.")
    harness.claim_service.claim_for_step.side_effect = failure

    with pytest.raises(RuntimeError) as captured:
        _start(harness)

    assert captured.value is failure
    assert harness.execution_repository.calls == []


@pytest.mark.parametrize(
    "failure",
    [
        RemediationExecutionClaimNotFoundError("Committed claim not found."),
        RemediationExecutionAlreadyStartedError("Execution already started."),
    ],
)
def test_start_refusal_propagates_without_retry(failure: Exception) -> None:
    harness = _make_harness()
    harness.execution_repository.error = failure

    with pytest.raises(type(failure)) as captured:
        _start(harness)

    assert captured.value is failure
    harness.claim_service.claim_for_step.assert_awaited_once()
    assert harness.execution_repository.calls == [harness.claim.claim_id]


def test_unexpected_start_error_is_not_converted_to_success() -> None:
    harness = _make_harness()
    failure = RuntimeError("Execution database connection lost after claim.")
    harness.execution_repository.error = failure

    with pytest.raises(RuntimeError) as captured:
        _start(harness)

    assert captured.value is failure
    harness.claim_service.claim_for_step.assert_awaited_once()
    assert harness.execution_repository.calls == [harness.claim.claim_id]


def test_second_invocation_cannot_reuse_existing_claim() -> None:
    harness = _make_harness()
    assert _start(harness) is harness.execution

    refusal = ExecutionClaimAlreadyExistsError("Step already claimed.")
    harness.claim_service.claim_for_step.side_effect = refusal

    with pytest.raises(ExecutionClaimAlreadyExistsError) as captured:
        _start(harness)

    assert captured.value is refusal
    assert harness.claim_service.claim_for_step.await_count == 2
    assert harness.execution_repository.calls == [harness.claim.claim_id]
