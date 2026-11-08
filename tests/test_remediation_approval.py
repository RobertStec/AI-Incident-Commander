"""Unit tests for requests to approve individual remediation actions."""

from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta, timezone
from typing import cast
from uuid import UUID

import pytest

from ai_incident_commander.domain.remediation_approval import (
    RemediationApprovalDecision,
    RemediationApprovalOutcome,
    RemediationApprovalRequest,
)

_PLAN_ID = UUID("00000000-0000-0000-0000-000000000001")
_STEP_ID = UUID("00000000-0000-0000-0000-000000000002")
_REQUEST_ID = UUID("00000000-0000-0000-0000-000000000003")
_ACTION_FINGERPRINT = "afp:v2:" + "a" * 64
_POLICY_VERSION = "apv:v1:" + "b" * 64
_REQUESTED_AT = datetime(2026, 11, 8, 12, 0, tzinfo=UTC)
_EXPIRES_AT = _REQUESTED_AT + timedelta(minutes=15)


def _make_request(
    *,
    request_id: UUID = _REQUEST_ID,
    plan_id: UUID = _PLAN_ID,
    step_id: UUID = _STEP_ID,
    action_fingerprint: str = _ACTION_FINGERPRINT,
    policy_version: str = _POLICY_VERSION,
    requested_at: datetime = _REQUESTED_AT,
    expires_at: datetime = _EXPIRES_AT,
) -> RemediationApprovalRequest:
    """Create a valid approval request with overridable inputs."""
    return RemediationApprovalRequest(
        request_id=request_id,
        plan_id=plan_id,
        step_id=step_id,
        action_fingerprint=action_fingerprint,
        policy_version=policy_version,
        requested_at=requested_at,
        expires_at=expires_at,
    )


def test_approval_request_preserves_all_fields() -> None:
    request = _make_request()

    assert request.request_id == _REQUEST_ID
    assert request.plan_id == _PLAN_ID
    assert request.step_id == _STEP_ID
    assert request.action_fingerprint == _ACTION_FINGERPRINT
    assert request.policy_version == _POLICY_VERSION
    assert request.requested_at == _REQUESTED_AT
    assert request.expires_at == _EXPIRES_AT


def test_approval_request_generates_unique_request_ids() -> None:
    first = RemediationApprovalRequest(
        plan_id=_PLAN_ID,
        step_id=_STEP_ID,
        action_fingerprint=_ACTION_FINGERPRINT,
        policy_version=_POLICY_VERSION,
        requested_at=_REQUESTED_AT,
        expires_at=_EXPIRES_AT,
    )
    second = RemediationApprovalRequest(
        plan_id=_PLAN_ID,
        step_id=_STEP_ID,
        action_fingerprint=_ACTION_FINGERPRINT,
        policy_version=_POLICY_VERSION,
        requested_at=_REQUESTED_AT,
        expires_at=_EXPIRES_AT,
    )

    assert isinstance(first.request_id, UUID)
    assert isinstance(second.request_id, UUID)
    assert first.request_id != second.request_id


def test_approval_request_accepts_explicit_zero_utc_offset() -> None:
    requested_at = datetime(2026, 11, 8, 12, 0, tzinfo=timezone(timedelta(0), "zero-offset"))
    request = _make_request(
        requested_at=requested_at,
        expires_at=requested_at + timedelta(minutes=15),
    )

    assert request.requested_at.utcoffset() == timedelta(0)


@pytest.mark.parametrize("field_name", ["request_id", "plan_id", "step_id"])
@pytest.mark.parametrize("invalid_value", [None, "not-a-uuid"])
def test_approval_request_rejects_non_uuid_identifiers(
    field_name: str, invalid_value: object
) -> None:
    invalid_uuid = cast(UUID, invalid_value)
    with pytest.raises(ValueError, match=f"Approval request {field_name} must be a UUID"):
        if field_name == "request_id":
            _make_request(request_id=invalid_uuid)
        elif field_name == "plan_id":
            _make_request(plan_id=invalid_uuid)
        else:
            _make_request(step_id=invalid_uuid)


@pytest.mark.parametrize(
    "action_fingerprint",
    [
        "",
        "afp:v1:" + "a" * 64,
        "afp:v2:" + "a" * 63,
        "afp:v2:" + "g" * 64,
        "afp:v2:" + "A" * 64,
    ],
)
def test_approval_request_rejects_invalid_fingerprint_format(
    action_fingerprint: str,
) -> None:
    with pytest.raises(ValueError, match="requires a valid action fingerprint"):
        _make_request(action_fingerprint=action_fingerprint)


@pytest.mark.parametrize("invalid_value", [None, 123])
def test_approval_request_rejects_non_string_fingerprint(
    invalid_value: object,
) -> None:
    with pytest.raises(ValueError, match="requires a valid action fingerprint"):
        _make_request(action_fingerprint=cast(str, invalid_value))


@pytest.mark.parametrize(
    "policy_version",
    [
        "",
        "apv:v2:" + "b" * 64,
        "apv:v1:" + "b" * 63,
        "apv:v1:" + "g" * 64,
        "apv:v1:" + "B" * 64,
    ],
)
def test_approval_request_rejects_invalid_policy_version_format(
    policy_version: str,
) -> None:
    with pytest.raises(ValueError, match="requires a valid policy version"):
        _make_request(policy_version=policy_version)


@pytest.mark.parametrize("invalid_value", [None, 42])
def test_approval_request_rejects_non_string_policy_version(
    invalid_value: object,
) -> None:
    with pytest.raises(ValueError, match="requires a valid policy version"):
        _make_request(policy_version=cast(str, invalid_value))


@pytest.mark.parametrize("field_name", ["requested_at", "expires_at"])
@pytest.mark.parametrize(
    "invalid_timestamp",
    [
        datetime(2026, 11, 8, 12, 0),
        datetime(2026, 11, 8, 12, 0, tzinfo=timezone(timedelta(hours=1))),
    ],
)
def test_approval_request_requires_utc_timestamps(
    field_name: str, invalid_timestamp: datetime
) -> None:
    with pytest.raises(ValueError, match=f"{field_name} must use UTC"):
        if field_name == "requested_at":
            _make_request(requested_at=invalid_timestamp)
        else:
            _make_request(expires_at=invalid_timestamp)


@pytest.mark.parametrize("field_name", ["requested_at", "expires_at"])
def test_approval_request_rejects_non_datetime_timestamps(
    field_name: str,
) -> None:
    invalid_datetime = cast(datetime, None)
    with pytest.raises(ValueError, match=f"{field_name} must use UTC"):
        if field_name == "requested_at":
            _make_request(requested_at=invalid_datetime)
        else:
            _make_request(expires_at=invalid_datetime)


@pytest.mark.parametrize(
    "expires_at",
    [_REQUESTED_AT, _REQUESTED_AT - timedelta(seconds=1)],
)
def test_approval_request_rejects_expiry_not_after_request(
    expires_at: datetime,
) -> None:
    with pytest.raises(ValueError, match="expires_at must be later than requested_at"):
        _make_request(expires_at=expires_at)


def test_approval_request_cannot_be_modified() -> None:
    request = _make_request()
    field_name = "policy_version"

    with pytest.raises(FrozenInstanceError):
        setattr(request, field_name, "apv:v1:" + "c" * 64)

    assert request.policy_version == _POLICY_VERSION


_DECISION_ID = UUID("00000000-0000-0000-0000-000000000004")
_DECIDED_AT = _REQUESTED_AT + timedelta(minutes=5)


def _make_decision(
    *,
    request_id: UUID = _REQUEST_ID,
    operator_id: str = "operator-123",
    outcome: RemediationApprovalOutcome = RemediationApprovalOutcome.APPROVED,
    decided_at: datetime = _DECIDED_AT,
    reason: str = "Approved for controlled incident remediation.",
    decision_id: UUID = _DECISION_ID,
) -> RemediationApprovalDecision:
    """Create a valid approval decision with overridable inputs."""
    return RemediationApprovalDecision(
        request_id=request_id,
        operator_id=operator_id,
        outcome=outcome,
        decided_at=decided_at,
        reason=reason,
        decision_id=decision_id,
    )


def test_approval_decision_preserves_all_fields() -> None:
    decision = _make_decision()

    assert decision.decision_id == _DECISION_ID
    assert decision.request_id == _REQUEST_ID
    assert decision.operator_id == "operator-123"
    assert decision.outcome is RemediationApprovalOutcome.APPROVED
    assert decision.decided_at == _DECIDED_AT
    assert decision.reason == "Approved for controlled incident remediation."


@pytest.mark.parametrize(
    "outcome",
    [RemediationApprovalOutcome.APPROVED, RemediationApprovalOutcome.REJECTED],
)
def test_approval_decision_accepts_both_outcomes(
    outcome: RemediationApprovalOutcome,
) -> None:
    decision = _make_decision(outcome=outcome)

    assert decision.outcome is outcome
    assert decision.outcome.value in ("approved", "rejected")


def test_approval_decision_generates_unique_decision_ids() -> None:
    first = RemediationApprovalDecision(
        request_id=_REQUEST_ID,
        operator_id="operator-123",
        outcome=RemediationApprovalOutcome.APPROVED,
        decided_at=_DECIDED_AT,
        reason="Approved following review.",
    )
    second = RemediationApprovalDecision(
        request_id=_REQUEST_ID,
        operator_id="operator-123",
        outcome=RemediationApprovalOutcome.APPROVED,
        decided_at=_DECIDED_AT,
        reason="Approved following review.",
    )

    assert isinstance(first.decision_id, UUID)
    assert isinstance(second.decision_id, UUID)
    assert first.decision_id != second.decision_id


@pytest.mark.parametrize("field_name", ["decision_id", "request_id"])
@pytest.mark.parametrize("invalid_value", [None, "not-a-uuid", 123])
def test_approval_decision_rejects_non_uuid_identifiers(
    field_name: str,
    invalid_value: object,
) -> None:
    invalid_uuid = cast(UUID, invalid_value)

    with pytest.raises(
        ValueError,
        match=f"Approval decision {field_name} must be a UUID",
    ):
        if field_name == "decision_id":
            _make_decision(decision_id=invalid_uuid)
        else:
            _make_decision(request_id=invalid_uuid)


@pytest.mark.parametrize("operator_id", ["", " ", "\t\n "])
def test_approval_decision_rejects_blank_operator_id(operator_id: str) -> None:
    with pytest.raises(ValueError, match="operator_id must be a non-empty string"):
        _make_decision(operator_id=operator_id)


@pytest.mark.parametrize("invalid_value", [None, 123, True])
def test_approval_decision_rejects_non_string_operator_id(
    invalid_value: object,
) -> None:
    with pytest.raises(ValueError, match="operator_id must be a non-empty string"):
        _make_decision(operator_id=cast(str, invalid_value))


@pytest.mark.parametrize(
    "invalid_value",
    ["approved", "rejected", "pending", None, 42],
)
def test_approval_decision_requires_explicit_outcome_enum(
    invalid_value: object,
) -> None:
    with pytest.raises(ValueError, match="outcome must be a valid approval outcome"):
        _make_decision(outcome=cast(RemediationApprovalOutcome, invalid_value))


@pytest.mark.parametrize("reason", ["", " ", "\t\n "])
def test_approval_decision_rejects_blank_reason(reason: str) -> None:
    with pytest.raises(ValueError, match="reason must be a non-empty string"):
        _make_decision(reason=reason)


@pytest.mark.parametrize("invalid_value", [None, 123, False])
def test_approval_decision_rejects_non_string_reason(
    invalid_value: object,
) -> None:
    with pytest.raises(ValueError, match="reason must be a non-empty string"):
        _make_decision(reason=cast(str, invalid_value))


@pytest.mark.parametrize(
    "invalid_timestamp",
    [
        datetime(2026, 11, 8, 12, 5),
        datetime(2026, 11, 8, 12, 5, tzinfo=timezone(timedelta(hours=1))),
        datetime(2026, 11, 8, 12, 5, tzinfo=timezone(timedelta(hours=-5))),
    ],
)
def test_approval_decision_requires_utc_timestamp(
    invalid_timestamp: datetime,
) -> None:
    with pytest.raises(ValueError, match="decided_at must use UTC"):
        _make_decision(decided_at=invalid_timestamp)


@pytest.mark.parametrize("invalid_value", [None, "2026-11-08T12:05:00Z", 123])
def test_approval_decision_rejects_non_datetime_timestamp(
    invalid_value: object,
) -> None:
    with pytest.raises(ValueError, match="decided_at must use UTC"):
        _make_decision(decided_at=cast(datetime, invalid_value))


def test_approval_decision_accepts_explicit_zero_utc_offset() -> None:
    decided_at = datetime(2026, 11, 8, 12, 5, tzinfo=timezone(timedelta(0), "zero-offset"))

    decision = _make_decision(decided_at=decided_at)

    assert decision.decided_at is decided_at
    assert decision.decided_at.utcoffset() == timedelta(0)


def test_approval_decision_does_not_normalize_audit_strings() -> None:
    decision = _make_decision(
        operator_id=" oncall-operator-7 ",
        reason="  Reviewed during incident bridge.  ",
    )

    assert decision.operator_id == " oncall-operator-7 "
    assert decision.reason == "  Reviewed during incident bridge.  "


def test_approval_decision_cannot_be_modified() -> None:
    decision = _make_decision()
    field_name = "outcome"

    with pytest.raises(FrozenInstanceError):
        setattr(decision, field_name, RemediationApprovalOutcome.REJECTED)

    assert decision.outcome is RemediationApprovalOutcome.APPROVED
