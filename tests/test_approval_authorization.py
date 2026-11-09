"""Tests for the application approval authorization port."""

import asyncio
import inspect
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from ai_incident_commander.application.approval_authorization import (
    ApprovalAuthorizationError,
    ApprovalAuthorizer,
    ApprovalPermissionDeniedError,
)
from ai_incident_commander.domain.remediation_approval import (
    RemediationApprovalOutcome,
    RemediationApprovalRequest,
)


class RecordingApprovalAuthorizer:
    """Test double recording authorization requests."""

    def __init__(self, *, allowed: bool) -> None:
        self.allowed = allowed
        self.calls: list[
            tuple[
                str,
                RemediationApprovalRequest,
                RemediationApprovalOutcome,
            ]
        ] = []

    async def ensure_can_decide(
        self,
        *,
        operator_id: str,
        request: RemediationApprovalRequest,
        outcome: RemediationApprovalOutcome,
    ) -> None:
        self.calls.append((operator_id, request, outcome))

        if not self.allowed:
            raise ApprovalPermissionDeniedError(
                "Operator is not authorized to decide this request."
            )


class FailingApprovalAuthorizer:
    """Test double simulating an unavailable authorization backend."""

    def __init__(self, error: Exception) -> None:
        self.error = error

    async def ensure_can_decide(
        self,
        *,
        operator_id: str,
        request: RemediationApprovalRequest,
        outcome: RemediationApprovalOutcome,
    ) -> None:
        raise self.error


def _make_request() -> RemediationApprovalRequest:
    """Create a valid approval request for contract tests."""
    requested_at = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)

    return RemediationApprovalRequest(
        plan_id=uuid4(),
        step_id=uuid4(),
        action_fingerprint="afp:v2:" + "a" * 64,
        policy_version="apv:v1:" + "b" * 64,
        requested_at=requested_at,
        expires_at=requested_at + timedelta(minutes=15),
    )


def test_authorizer_supports_structural_protocol() -> None:
    authorizer: ApprovalAuthorizer = RecordingApprovalAuthorizer(allowed=True)

    assert isinstance(authorizer, RecordingApprovalAuthorizer)


def test_authorization_contract_is_asynchronous() -> None:
    assert inspect.iscoroutinefunction(ApprovalAuthorizer.ensure_can_decide)
    assert inspect.iscoroutinefunction(RecordingApprovalAuthorizer.ensure_can_decide)


@pytest.mark.parametrize(
    "outcome",
    [
        RemediationApprovalOutcome.APPROVED,
        RemediationApprovalOutcome.REJECTED,
    ],
)
def test_allowed_authorizer_accepts_both_outcomes(
    outcome: RemediationApprovalOutcome,
) -> None:
    request = _make_request()
    recorder = RecordingApprovalAuthorizer(allowed=True)
    authorizer: ApprovalAuthorizer = recorder

    asyncio.run(
        authorizer.ensure_can_decide(
            operator_id="operator-123",
            request=request,
            outcome=outcome,
        )
    )

    assert len(recorder.calls) == 1

    recorded_operator, recorded_request, recorded_outcome = recorder.calls[0]

    assert recorded_operator == "operator-123"
    assert recorded_request is request
    assert recorded_outcome is outcome


@pytest.mark.parametrize(
    "outcome",
    [
        RemediationApprovalOutcome.APPROVED,
        RemediationApprovalOutcome.REJECTED,
    ],
)
def test_denied_authorization_raises_permission_error(
    outcome: RemediationApprovalOutcome,
) -> None:
    request = _make_request()
    recorder = RecordingApprovalAuthorizer(allowed=False)
    authorizer: ApprovalAuthorizer = recorder

    with pytest.raises(ApprovalPermissionDeniedError):
        asyncio.run(
            authorizer.ensure_can_decide(
                operator_id="operator-without-permission",
                request=request,
                outcome=outcome,
            )
        )

    assert recorder.calls == [("operator-without-permission", request, outcome)]


def test_permission_denied_error_inherits_authorization_error() -> None:
    assert issubclass(
        ApprovalPermissionDeniedError,
        ApprovalAuthorizationError,
    )


def test_authorization_backend_failure_is_propagated() -> None:
    request = _make_request()
    expected_error = RuntimeError("Authorization backend unavailable.")
    authorizer: ApprovalAuthorizer = FailingApprovalAuthorizer(expected_error)

    with pytest.raises(RuntimeError) as captured:
        asyncio.run(
            authorizer.ensure_can_decide(
                operator_id="operator-123",
                request=request,
                outcome=RemediationApprovalOutcome.APPROVED,
            )
        )

    assert captured.value is expected_error
