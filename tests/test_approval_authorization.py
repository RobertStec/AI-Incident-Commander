"""Tests for the application approval authorization port."""

import asyncio
import inspect
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta
from inspect import Parameter, signature
from typing import cast
from uuid import uuid4

import pytest

from ai_incident_commander.application.approval_authorization import (
    ApprovalAuthorizationError,
    ApprovalAuthorizer,
    ApprovalPermissionDeniedError,
    AuthenticatedOperatorContext,
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
                AuthenticatedOperatorContext,
                RemediationApprovalRequest,
                RemediationApprovalOutcome,
            ]
        ] = []

    async def ensure_can_decide(
        self,
        *,
        operator: AuthenticatedOperatorContext,
        request: RemediationApprovalRequest,
        outcome: RemediationApprovalOutcome,
    ) -> None:
        self.calls.append((operator, request, outcome))

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
        operator: AuthenticatedOperatorContext,
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
    operator = AuthenticatedOperatorContext(operator_id="operator-123")

    asyncio.run(
        authorizer.ensure_can_decide(
            operator=operator,
            request=request,
            outcome=outcome,
        )
    )

    assert len(recorder.calls) == 1

    recorded_operator, recorded_request, recorded_outcome = recorder.calls[0]

    assert recorded_operator is operator
    assert recorded_operator.operator_id == "operator-123"
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
    operator = AuthenticatedOperatorContext(operator_id="operator-without-permission")

    with pytest.raises(ApprovalPermissionDeniedError):
        asyncio.run(
            authorizer.ensure_can_decide(
                operator=operator,
                request=request,
                outcome=outcome,
            )
        )

    assert recorder.calls == [(operator, request, outcome)]


def test_permission_denied_error_inherits_authorization_error() -> None:
    assert issubclass(
        ApprovalPermissionDeniedError,
        ApprovalAuthorizationError,
    )


def test_authorization_backend_failure_is_propagated() -> None:
    request = _make_request()
    expected_error = RuntimeError("Authorization backend unavailable.")
    authorizer: ApprovalAuthorizer = FailingApprovalAuthorizer(expected_error)
    operator = AuthenticatedOperatorContext(operator_id="operator-123")

    with pytest.raises(RuntimeError) as captured:
        asyncio.run(
            authorizer.ensure_can_decide(
                operator=operator,
                request=request,
                outcome=RemediationApprovalOutcome.APPROVED,
            )
        )

    assert captured.value is expected_error


@pytest.mark.parametrize(
    "operator_id",
    [
        "operator-123",
        "tenant-7:user-9",
        "żółw-42",
    ],
)
def test_authenticated_operator_context_accepts_canonical_id(
    operator_id: str,
) -> None:
    context = AuthenticatedOperatorContext(operator_id=operator_id)

    assert context.operator_id == operator_id


@pytest.mark.parametrize(
    "operator_id",
    ["", " ", "\t", "\n", "\u00a0"],
)
def test_authenticated_operator_context_rejects_empty_or_whitespace_id(
    operator_id: str,
) -> None:
    with pytest.raises(ValueError, match="Authenticated operator_id"):
        AuthenticatedOperatorContext(operator_id=operator_id)


@pytest.mark.parametrize(
    "operator_id",
    [" operator-123", "operator-123 ", "\toperator-123", "operator-123\n"],
)
def test_authenticated_operator_context_rejects_uncanonical_whitespace(
    operator_id: str,
) -> None:
    with pytest.raises(ValueError, match="Authenticated operator_id"):
        AuthenticatedOperatorContext(operator_id=operator_id)


class OperatorIdSubclass(str):
    """A string subclass must not bypass exact-type validation."""


@pytest.mark.parametrize(
    "invalid_id",
    [None, 123, True, b"operator-123", OperatorIdSubclass("operator-123")],
    ids=["none", "integer", "boolean", "bytes", "string-subclass"],
)
def test_authenticated_operator_context_rejects_non_plain_strings(
    invalid_id: object,
) -> None:
    # Deliberately bypass the static type to test runtime validation.
    with pytest.raises(ValueError, match="Authenticated operator_id"):
        AuthenticatedOperatorContext(operator_id=cast(str, invalid_id))


def test_authenticated_operator_context_is_immutable() -> None:
    context = AuthenticatedOperatorContext(operator_id="operator-123")
    field_name = "operator_id"

    with pytest.raises(FrozenInstanceError):
        setattr(context, field_name, "another-operator")

    assert context.operator_id == "operator-123"


def test_authenticated_operator_context_uses_slots() -> None:
    context = AuthenticatedOperatorContext(operator_id="operator-123")

    assert not hasattr(context, "__dict__")


def test_authenticated_operator_context_requires_keyword_argument() -> None:
    operator_id_parameter = signature(AuthenticatedOperatorContext).parameters["operator_id"]

    assert operator_id_parameter.kind is Parameter.KEYWORD_ONLY
