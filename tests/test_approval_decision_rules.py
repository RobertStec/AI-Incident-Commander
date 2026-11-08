"""Unit tests for matching remediation approval decisions to requests."""

from datetime import UTC, datetime, timedelta, timezone
from uuid import UUID

import pytest

from ai_incident_commander.domain.approval_decision_rules import (
    ApprovalDecisionOutsideWindowError,
    ApprovalDecisionRequestMismatchError,
    validate_approval_decision_for_request,
)
from ai_incident_commander.domain.remediation_approval import (
    RemediationApprovalDecision,
    RemediationApprovalOutcome,
    RemediationApprovalRequest,
)

_REQUEST_ID = UUID("00000000-0000-0000-0000-000000000001")
_OTHER_REQUEST_ID = UUID("00000000-0000-0000-0000-000000000002")
_PLAN_ID = UUID("00000000-0000-0000-0000-000000000003")
_STEP_ID = UUID("00000000-0000-0000-0000-000000000004")
_REQUESTED_AT = datetime(2026, 11, 8, 12, 0, tzinfo=UTC)
_EXPIRES_AT = _REQUESTED_AT + timedelta(minutes=15)


def _make_request() -> RemediationApprovalRequest:
    """Create a request with a known 15-minute approval window."""
    return RemediationApprovalRequest(
        request_id=_REQUEST_ID,
        plan_id=_PLAN_ID,
        step_id=_STEP_ID,
        action_fingerprint="afp:v2:" + "a" * 64,
        policy_version="apv:v1:" + "b" * 64,
        requested_at=_REQUESTED_AT,
        expires_at=_EXPIRES_AT,
    )


def _make_decision(
    *,
    request_id: UUID = _REQUEST_ID,
    decided_at: datetime = _REQUESTED_AT + timedelta(minutes=1),
    outcome: RemediationApprovalOutcome = RemediationApprovalOutcome.APPROVED,
) -> RemediationApprovalDecision:
    """Create a structurally valid decision with configurable context."""
    return RemediationApprovalDecision(
        request_id=request_id,
        operator_id="oncall-operator",
        outcome=outcome,
        decided_at=decided_at,
        reason="Reviewed incident evidence.",
    )


@pytest.mark.parametrize("outcome", list(RemediationApprovalOutcome))
def test_matching_request_accepts_both_decision_outcomes(
    outcome: RemediationApprovalOutcome,
) -> None:
    request = _make_request()
    decision = _make_decision(outcome=outcome)

    validate_approval_decision_for_request(request, decision)


def test_decision_exactly_at_request_start_is_accepted() -> None:
    request = _make_request()
    decision = _make_decision(decided_at=_REQUESTED_AT)

    validate_approval_decision_for_request(request, decision)


def test_decision_one_microsecond_before_expiration_is_accepted() -> None:
    request = _make_request()
    decision = _make_decision(
        decided_at=_EXPIRES_AT - timedelta(microseconds=1),
    )

    validate_approval_decision_for_request(request, decision)


@pytest.mark.parametrize(
    "offset",
    [timedelta(0), timedelta(microseconds=1), timedelta(minutes=1)],
)
def test_decision_at_or_after_expiration_is_rejected(
    offset: timedelta,
) -> None:
    request = _make_request()
    decision = _make_decision(decided_at=_EXPIRES_AT + offset)

    with pytest.raises(
        ApprovalDecisionOutsideWindowError,
        match="outside the request validity window",
    ):
        validate_approval_decision_for_request(request, decision)


@pytest.mark.parametrize(
    "offset",
    [timedelta(microseconds=1), timedelta(minutes=1)],
)
def test_decision_before_request_start_is_rejected(
    offset: timedelta,
) -> None:
    request = _make_request()
    decision = _make_decision(decided_at=_REQUESTED_AT - offset)

    with pytest.raises(ApprovalDecisionOutsideWindowError):
        validate_approval_decision_for_request(request, decision)


def test_decision_for_another_request_is_rejected() -> None:
    request = _make_request()
    decision = _make_decision(request_id=_OTHER_REQUEST_ID)

    with pytest.raises(
        ApprovalDecisionRequestMismatchError,
        match="does not belong to the approval request",
    ):
        validate_approval_decision_for_request(request, decision)


def test_request_mismatch_is_checked_before_timestamp() -> None:
    request = _make_request()
    decision = _make_decision(
        request_id=_OTHER_REQUEST_ID,
        decided_at=_EXPIRES_AT,
    )

    with pytest.raises(ApprovalDecisionRequestMismatchError):
        validate_approval_decision_for_request(request, decision)


def test_explicit_zero_utc_offset_is_accepted() -> None:
    request = _make_request()
    decided_at = datetime(
        2026,
        11,
        8,
        12,
        5,
        tzinfo=timezone(timedelta(0), "UTC+00"),
    )
    decision = _make_decision(decided_at=decided_at)

    validate_approval_decision_for_request(request, decision)


def test_validation_does_not_modify_request_or_decision() -> None:
    request = _make_request()
    decision = _make_decision()
    original_request = request
    original_decision = decision

    validate_approval_decision_for_request(request, decision)

    assert request is original_request
    assert decision is original_decision
    assert request.request_id == _REQUEST_ID
    assert request.expires_at == _EXPIRES_AT
    assert decision.decided_at == _REQUESTED_AT + timedelta(minutes=1)


def test_rule_checks_stored_timestamp_not_current_clock() -> None:
    request = _make_request()
    decision = _make_decision(decided_at=_REQUESTED_AT + timedelta(minutes=5))

    # This domain rule does not establish the real time of the decision.
    validate_approval_decision_for_request(request, decision)
