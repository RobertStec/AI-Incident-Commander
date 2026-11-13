"""Unit tests for the specialized recovery repository port."""

import inspect
from typing import Protocol, get_type_hints
from uuid import UUID

import pytest

from ai_incident_commander.application.approval_execution_guard import (
    VerifiedExecutionScope,
)
from ai_incident_commander.application.remediation_execution_repository import (
    RemediationExecutionAlreadyStartedError,
    RemediationExecutionClaimNotFoundError,
    RemediationExecutionRecoveryApprovalDeniedError,
    RemediationExecutionRecoveryDeniedError,
    RemediationExecutionRecoveryRepository,
    RemediationExecutionRecoveryScopeMismatchError,
    RemediationExecutionRecoveryWindowNotSatisfiedError,
    RemediationExecutionRepository,
    RemediationExecutionRepositoryError,
)
from ai_incident_commander.domain.execution_claim_recovery_policy import (
    ExecutionClaimRecoveryWindowPolicy,
)
from ai_incident_commander.domain.remediation_execution import RemediationExecution


def test_recovery_port_is_separate_from_standard_start_port() -> None:
    assert issubclass(RemediationExecutionRecoveryRepository, Protocol)
    assert not hasattr(RemediationExecutionRepository, "start_recovered_once")


def test_recovery_method_has_explicit_keyword_only_dependencies() -> None:
    method = RemediationExecutionRecoveryRepository.start_recovered_once
    assert inspect.iscoroutinefunction(method)
    signature = inspect.signature(method)
    assert tuple(signature.parameters) == ("self", "claim_id", "verified_scope", "recovery_policy")
    for name in ("claim_id", "verified_scope", "recovery_policy"):
        assert signature.parameters[name].kind is inspect.Parameter.KEYWORD_ONLY
    assert get_type_hints(method) == {
        "claim_id": UUID,
        "verified_scope": VerifiedExecutionScope,
        "recovery_policy": ExecutionClaimRecoveryWindowPolicy,
        "return": RemediationExecution,
    }


@pytest.mark.parametrize(
    "error_type",
    [
        RemediationExecutionRecoveryApprovalDeniedError,
        RemediationExecutionRecoveryScopeMismatchError,
        RemediationExecutionRecoveryWindowNotSatisfiedError,
    ],
)
def test_recovery_refusals_share_distinct_repository_error_base(
    error_type: type[Exception],
) -> None:
    assert issubclass(error_type, RemediationExecutionRecoveryDeniedError)
    assert issubclass(error_type, RemediationExecutionRepositoryError)


def test_existing_start_refusals_remain_reusable_for_recovery() -> None:
    assert issubclass(RemediationExecutionAlreadyStartedError, RemediationExecutionRepositoryError)
    assert issubclass(RemediationExecutionClaimNotFoundError, RemediationExecutionRepositoryError)


def test_distinct_recovery_refusal_types() -> None:
    refusal_types = (
        RemediationExecutionRecoveryApprovalDeniedError,
        RemediationExecutionRecoveryScopeMismatchError,
        RemediationExecutionRecoveryWindowNotSatisfiedError,
    )
    assert len(set(refusal_types)) == len(refusal_types)
