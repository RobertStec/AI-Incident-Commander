"""Domain tests for a single remediation execution attempt lifecycle."""

from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime, timedelta, timezone
from uuid import UUID, uuid4

import pytest

from ai_incident_commander.domain.remediation_execution import (
    RemediationExecution,
    RemediationExecutionStatus,
    RemediationExecutionTransitionError,
    can_transition_remediation_execution_status,
)

_STARTED = datetime(2026, 11, 12, 18, 0, tzinfo=UTC)
_LATER = _STARTED + timedelta(minutes=2)
_TERMINAL = (
    RemediationExecutionStatus.SUCCEEDED,
    RemediationExecutionStatus.FAILED,
    RemediationExecutionStatus.UNKNOWN,
)


def _new_execution() -> RemediationExecution:
    return RemediationExecution(claim_id=uuid4(), started_at=_STARTED)


def test_execution_statuses_match_domain_contract() -> None:
    assert {status.value for status in RemediationExecutionStatus} == {
        "executing",
        "succeeded",
        "failed",
        "unknown",
    }


@pytest.mark.parametrize("target", list(RemediationExecutionStatus))
@pytest.mark.parametrize("current", list(RemediationExecutionStatus))
def test_execution_transition_matrix(
    current: RemediationExecutionStatus, target: RemediationExecutionStatus
) -> None:
    assert can_transition_remediation_execution_status(current, target) is (
        current is RemediationExecutionStatus.EXECUTING and target in _TERMINAL
    )


def test_new_execution_has_expected_defaults_and_explicit_time() -> None:
    claim_id = uuid4()
    execution = RemediationExecution(claim_id=claim_id, started_at=_STARTED)
    assert execution.claim_id == claim_id
    assert isinstance(execution.execution_id, UUID)
    assert execution.status is RemediationExecutionStatus.EXECUTING
    assert execution.status_changed_at is None
    assert execution.started_at == _STARTED


def test_execution_identifiers_are_distinct_by_default() -> None:
    first = _new_execution()
    second = _new_execution()
    assert first.execution_id != second.execution_id


@pytest.mark.parametrize("target", _TERMINAL)
def test_transition_returns_new_snapshot_without_mutating_original(
    target: RemediationExecutionStatus,
) -> None:
    execution = _new_execution()
    transitioned = execution.transition_to(target, occurred_at=_LATER)
    assert transitioned is not execution
    assert transitioned.status is target
    assert transitioned.status_changed_at == _LATER
    assert transitioned.execution_id == execution.execution_id
    assert transitioned.claim_id == execution.claim_id
    assert transitioned.started_at == execution.started_at
    assert execution.status is RemediationExecutionStatus.EXECUTING
    assert execution.status_changed_at is None


@pytest.mark.parametrize("target", _TERMINAL)
def test_terminal_or_unknown_status_cannot_be_retried_or_changed(
    target: RemediationExecutionStatus,
) -> None:
    terminal = _new_execution().transition_to(target, occurred_at=_LATER)
    with pytest.raises(RemediationExecutionTransitionError, match="not allowed"):
        terminal.transition_to(RemediationExecutionStatus.EXECUTING, occurred_at=_LATER)


def test_executing_to_executing_is_not_a_new_attempt() -> None:
    with pytest.raises(RemediationExecutionTransitionError, match="not allowed"):
        _new_execution().transition_to(RemediationExecutionStatus.EXECUTING, occurred_at=_LATER)


def test_execution_snapshot_is_immutable() -> None:
    execution = _new_execution()
    with pytest.raises(FrozenInstanceError):
        execution.status = RemediationExecutionStatus.SUCCEEDED  # type: ignore[misc]


@pytest.mark.parametrize("field_name", ("claim_id", "execution_id"))
def test_execution_rejects_non_uuid_identifiers(field_name: str) -> None:
    fields: dict[str, object] = {"claim_id": uuid4(), "started_at": _STARTED}
    fields[field_name] = "invalid"
    with pytest.raises(ValueError, match=f"{field_name} must be a UUID"):
        RemediationExecution(**fields)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "invalid_time",
    (
        datetime(2026, 11, 12, 18, 0),
        datetime(2026, 11, 12, 19, 0, tzinfo=timezone(timedelta(hours=1))),
    ),
)
def test_execution_rejects_non_utc_start(invalid_time: datetime) -> None:
    with pytest.raises(ValueError, match="started_at must use UTC"):
        RemediationExecution(claim_id=uuid4(), started_at=invalid_time)


def test_executing_cannot_have_a_terminal_timestamp() -> None:
    with pytest.raises(ValueError, match="EXECUTING must not have"):
        replace(_new_execution(), status_changed_at=_LATER)


@pytest.mark.parametrize("target", _TERMINAL)
def test_terminal_snapshot_requires_transition_timestamp(
    target: RemediationExecutionStatus,
) -> None:
    with pytest.raises(ValueError, match="requires status_changed_at"):
        replace(_new_execution(), status=target)


def test_terminal_timestamp_must_be_utc() -> None:
    with pytest.raises(ValueError, match="status_changed_at must use UTC"):
        _new_execution().transition_to(
            RemediationExecutionStatus.UNKNOWN,
            occurred_at=datetime(2026, 11, 12, 19, 0, tzinfo=timezone(timedelta(hours=1))),
        )


def test_terminal_timestamp_cannot_precede_start() -> None:
    with pytest.raises(ValueError, match="must not precede started_at"):
        _new_execution().transition_to(
            RemediationExecutionStatus.FAILED,
            occurred_at=_STARTED - timedelta(seconds=1),
        )


def test_invalid_status_is_rejected() -> None:
    with pytest.raises(ValueError, match="must be a valid status"):
        replace(_new_execution(), status="made-up")  # type: ignore[arg-type]


def test_rehydrated_terminal_snapshot_preserves_identifier_and_time() -> None:
    execution_id, claim_id = uuid4(), uuid4()
    execution = RemediationExecution(
        execution_id=execution_id,
        claim_id=claim_id,
        started_at=_STARTED,
        status=RemediationExecutionStatus.UNKNOWN,
        status_changed_at=_LATER,
    )
    assert execution.execution_id == execution_id
    assert execution.claim_id == claim_id
    assert execution.status is RemediationExecutionStatus.UNKNOWN
    assert execution.status_changed_at == _LATER
