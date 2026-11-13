"""Unit tests for trusted, fail-closed claim recovery orchestration."""

import asyncio
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from unittest.mock import create_autospec
from uuid import UUID, uuid4

import pytest

from ai_incident_commander.application.approval_execution_guard import (
    ApprovalExecutionDeniedError,
    ApprovalExecutionGuard,
    ApprovalExecutionScopeMismatchError,
    VerifiedExecutionScope,
)
from ai_incident_commander.application.execution_claim_repository import ExecutionClaimRepository
from ai_incident_commander.application.remediation_execution_recovery_service import (
    RemediationExecutionRecoveryService,
)
from ai_incident_commander.application.remediation_execution_repository import (
    RemediationExecutionAlreadyStartedError,
    RemediationExecutionClaimNotFoundError,
    RemediationExecutionRecoveryApprovalDeniedError,
    RemediationExecutionRecoveryRepository,
    RemediationExecutionRecoveryScopeMismatchError,
    RemediationExecutionRecoveryWindowNotSatisfiedError,
)
from ai_incident_commander.domain.execution_claim import ExecutionClaim
from ai_incident_commander.domain.execution_claim_recovery_policy import (
    ExecutionClaimRecoveryWindowPolicy,
)
from ai_incident_commander.domain.remediation import RemediationRiskLevel, RemediationStep
from ai_incident_commander.domain.remediation_execution import (
    RemediationExecution,
    RemediationExecutionStatus,
)

_FINGERPRINT = "afp:v2:" + "a" * 64
_POLICY_VERSION = "apv:v1:" + "b" * 64


@dataclass
class Harness:
    service: RemediationExecutionRecoveryService
    guard: ApprovalExecutionGuard
    claims: ExecutionClaimRepository
    recovery: RemediationExecutionRecoveryRepository
    policy: ExecutionClaimRecoveryWindowPolicy
    request_id: UUID
    step: RemediationStep
    claim: ExecutionClaim
    scope: VerifiedExecutionScope
    execution: RemediationExecution


def _make_harness() -> Harness:
    request_id = uuid4()
    step = RemediationStep(
        plan_id=uuid4(),
        position=1,
        action_name="restart_service",
        target="payments-api",
        environment="incident-lab",
        risk_level=RemediationRiskLevel.HIGH,
    )
    claim = ExecutionClaim(
        request_id=request_id,
        plan_id=step.plan_id,
        step_id=step.step_id,
        action_fingerprint=_FINGERPRINT,
        policy_version=_POLICY_VERSION,
        claimed_at=datetime(2026, 11, 13, 12, 0, tzinfo=UTC),
    )
    scope = VerifiedExecutionScope(
        request_id=request_id,
        plan_id=step.plan_id,
        step_id=step.step_id,
        action_fingerprint=_FINGERPRINT,
        policy_version=_POLICY_VERSION,
    )
    execution = RemediationExecution(
        claim_id=claim.claim_id,
        started_at=datetime(2026, 11, 13, 12, 1, tzinfo=UTC),
    )
    policy = ExecutionClaimRecoveryWindowPolicy(max_claim_age=timedelta(minutes=10))
    guard = create_autospec(ApprovalExecutionGuard, instance=True)
    claims = create_autospec(ExecutionClaimRepository, instance=True)
    recovery = create_autospec(RemediationExecutionRecoveryRepository, instance=True)
    claims.get_by_request_id.return_value = claim
    guard.verify_scope_for_step.return_value = scope
    recovery.start_recovered_once.return_value = execution
    service = RemediationExecutionRecoveryService(
        guard=guard,
        claim_repository=claims,
        recovery_repository=recovery,
        recovery_policy=policy,
    )
    return Harness(
        service=service,
        guard=guard,
        claims=claims,
        recovery=recovery,
        policy=policy,
        request_id=request_id,
        step=step,
        claim=claim,
        scope=scope,
        execution=execution,
    )


def _recover(harness: Harness) -> RemediationExecution:
    return asyncio.run(
        harness.service.recover_for_step(request_id=harness.request_id, step=harness.step)
    )


def test_recovery_uses_existing_claim_and_fresh_guard_scope_without_reclaiming() -> None:
    harness = _make_harness()

    result = _recover(harness)

    assert result is harness.execution
    assert result.status is RemediationExecutionStatus.EXECUTING
    harness.claims.get_by_request_id.assert_awaited_once_with(request_id=harness.request_id)
    harness.claims.claim_once.assert_not_called()
    harness.guard.verify_scope_for_step.assert_awaited_once_with(
        request_id=harness.request_id, step=harness.step
    )
    harness.guard.validate_for_step.assert_not_called()
    harness.recovery.start_recovered_once.assert_awaited_once_with(
        claim_id=harness.claim.claim_id,
        verified_scope=harness.scope,
        recovery_policy=harness.policy,
    )


def test_recovery_calls_lookup_before_guard_and_database_start() -> None:
    harness = _make_harness()
    steps: list[str] = []

    async def read_claim(*, request_id: UUID) -> ExecutionClaim:
        assert request_id == harness.request_id
        steps.append("claim-read")
        return harness.claim

    async def verify(*, request_id: UUID, step: RemediationStep) -> VerifiedExecutionScope:
        assert request_id == harness.request_id and step is harness.step
        steps.append("fresh-guard")
        return harness.scope

    async def recover(
        *,
        claim_id: UUID,
        verified_scope: VerifiedExecutionScope,
        recovery_policy: ExecutionClaimRecoveryWindowPolicy,
    ) -> RemediationExecution:
        assert claim_id == harness.claim.claim_id
        assert verified_scope is harness.scope
        assert recovery_policy is harness.policy
        steps.append("atomic-recovery")
        return harness.execution

    harness.claims.get_by_request_id.side_effect = read_claim
    harness.guard.verify_scope_for_step.side_effect = verify
    harness.recovery.start_recovered_once.side_effect = recover

    assert _recover(harness) is harness.execution
    assert steps == ["claim-read", "fresh-guard", "atomic-recovery"]


def test_missing_claim_fails_closed_without_guard_or_recovery() -> None:
    harness = _make_harness()
    harness.claims.get_by_request_id.return_value = None

    with pytest.raises(RemediationExecutionClaimNotFoundError):
        _recover(harness)

    harness.claims.get_by_request_id.assert_awaited_once_with(request_id=harness.request_id)
    harness.guard.verify_scope_for_step.assert_not_called()
    harness.recovery.start_recovered_once.assert_not_called()
    harness.claims.claim_once.assert_not_called()


def test_claim_read_error_propagates_without_guard_or_recovery() -> None:
    harness = _make_harness()
    failure = RuntimeError("Claim database unavailable")
    harness.claims.get_by_request_id.side_effect = failure

    with pytest.raises(RuntimeError) as captured:
        _recover(harness)

    assert captured.value is failure
    harness.guard.verify_scope_for_step.assert_not_called()
    harness.recovery.start_recovered_once.assert_not_called()


@pytest.mark.parametrize(
    "failure",
    [
        ApprovalExecutionDeniedError("Approval has been revoked."),
        ApprovalExecutionScopeMismatchError("Current preflight differs."),
    ],
)
def test_guard_refusal_never_calls_recovery(failure: Exception) -> None:
    harness = _make_harness()
    harness.guard.verify_scope_for_step.side_effect = failure

    with pytest.raises(type(failure)) as captured:
        _recover(harness)

    assert captured.value is failure
    harness.claims.get_by_request_id.assert_awaited_once()
    harness.recovery.start_recovered_once.assert_not_called()
    harness.claims.claim_once.assert_not_called()


def test_unexpected_guard_error_propagates_without_recovery() -> None:
    harness = _make_harness()
    failure = RuntimeError("Target resolver failed")
    harness.guard.verify_scope_for_step.side_effect = failure

    with pytest.raises(RuntimeError) as captured:
        _recover(harness)

    assert captured.value is failure
    harness.recovery.start_recovered_once.assert_not_called()


@pytest.mark.parametrize(
    "failure",
    [
        RemediationExecutionClaimNotFoundError("Claim deleted after lookup."),
        RemediationExecutionAlreadyStartedError("Already executing."),
        RemediationExecutionRecoveryApprovalDeniedError("Decision no longer approved."),
        RemediationExecutionRecoveryScopeMismatchError("Persisted scope mismatch."),
        RemediationExecutionRecoveryWindowNotSatisfiedError("Claim expired."),
    ],
)
def test_recovery_database_refusal_propagates_once_without_retry(failure: Exception) -> None:
    harness = _make_harness()
    harness.recovery.start_recovered_once.side_effect = failure

    with pytest.raises(type(failure)) as captured:
        _recover(harness)

    assert captured.value is failure
    harness.guard.verify_scope_for_step.assert_awaited_once()
    harness.recovery.start_recovered_once.assert_awaited_once()
    harness.claims.claim_once.assert_not_called()


def test_unexpected_recovery_database_error_is_not_converted_to_success() -> None:
    harness = _make_harness()
    failure = RuntimeError("PostgreSQL connection interrupted")
    harness.recovery.start_recovered_once.side_effect = failure

    with pytest.raises(RuntimeError) as captured:
        _recover(harness)

    assert captured.value is failure
    harness.recovery.start_recovered_once.assert_awaited_once()


def test_identical_second_recovery_does_not_reuse_existing_execution() -> None:
    harness = _make_harness()
    assert _recover(harness) is harness.execution

    refusal = RemediationExecutionAlreadyStartedError("Already started.")
    harness.recovery.start_recovered_once.side_effect = refusal
    with pytest.raises(RemediationExecutionAlreadyStartedError) as captured:
        _recover(harness)

    assert captured.value is refusal
    assert harness.claims.get_by_request_id.await_count == 2
    assert harness.guard.verify_scope_for_step.await_count == 2
    assert harness.recovery.start_recovered_once.await_count == 2
    harness.claims.claim_once.assert_not_called()
