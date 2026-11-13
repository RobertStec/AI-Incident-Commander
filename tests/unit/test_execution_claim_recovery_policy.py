"""Pure domain tests for the execution-claim recovery time window."""

from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta, timezone
from typing import cast
from uuid import uuid4

import pytest

from ai_incident_commander.domain.execution_claim import ExecutionClaim
from ai_incident_commander.domain.execution_claim_recovery_policy import (
    ExecutionClaimRecoveryWindowPolicy,
)

_CLAIMED_AT = datetime(2026, 11, 13, 10, 0, tzinfo=UTC)


def _claim() -> ExecutionClaim:
    return ExecutionClaim(
        plan_id=uuid4(),
        step_id=uuid4(),
        request_id=uuid4(),
        action_fingerprint="afp:v2:" + "a" * 64,
        policy_version="apv:v1:" + "b" * 64,
        claimed_at=_CLAIMED_AT,
    )


def _policy(*, minutes: int = 15) -> ExecutionClaimRecoveryWindowPolicy:
    return ExecutionClaimRecoveryWindowPolicy(max_claim_age=timedelta(minutes=minutes))


@pytest.mark.parametrize(
    ("observed_at", "expected"),
    [
        (_CLAIMED_AT, True),
        (_CLAIMED_AT + timedelta(microseconds=1), True),
        (_CLAIMED_AT + timedelta(minutes=14, seconds=59), True),
        (_CLAIMED_AT + timedelta(minutes=15) - timedelta(microseconds=1), True),
        (_CLAIMED_AT + timedelta(minutes=15), False),
        (_CLAIMED_AT + timedelta(minutes=15, microseconds=1), False),
        (_CLAIMED_AT - timedelta(microseconds=1), False),
    ],
)
def test_time_window_has_explicit_half_open_boundaries(
    observed_at: datetime, expected: bool
) -> None:
    assert _policy().is_within_time_window(claim=_claim(), observed_at=observed_at) is expected


@pytest.mark.parametrize("invalid_age", [timedelta(0), timedelta(seconds=-1), "15 minutes"])
def test_recovery_window_requires_positive_explicit_timedelta(invalid_age: object) -> None:
    with pytest.raises(ValueError, match="positive timedelta"):
        ExecutionClaimRecoveryWindowPolicy(max_claim_age=cast(timedelta, invalid_age))


@pytest.mark.parametrize(
    "invalid_time",
    [
        datetime(2026, 11, 13, 10, 1),
        datetime(2026, 11, 13, 11, 1, tzinfo=timezone(timedelta(hours=1))),
        "2026-11-13T10:01:00Z",
    ],
)
def test_observation_requires_valid_utc_datetime(invalid_time: object) -> None:
    with pytest.raises(ValueError, match="UTC datetime"):
        _policy().is_within_time_window(claim=_claim(), observed_at=cast(datetime, invalid_time))


def test_policy_maximum_age_is_explicit_and_independent_of_approval_window() -> None:
    claim = _claim()
    now = _CLAIMED_AT + timedelta(minutes=20)
    assert not _policy(minutes=15).is_within_time_window(claim=claim, observed_at=now)
    assert _policy(minutes=30).is_within_time_window(claim=claim, observed_at=now)


def test_policy_is_immutable_and_does_not_mutate_claim() -> None:
    policy = _policy()
    claim = _claim()
    snapshot = claim
    assert policy.is_within_time_window(claim=claim, observed_at=_CLAIMED_AT)
    assert claim == snapshot
    with pytest.raises(FrozenInstanceError):
        policy.max_claim_age = timedelta(days=1)  # type: ignore[misc]


def test_large_configured_window_does_not_overflow_timestamp_arithmetic() -> None:
    policy = ExecutionClaimRecoveryWindowPolicy(max_claim_age=timedelta(days=999_999_999))
    assert policy.is_within_time_window(claim=_claim(), observed_at=_CLAIMED_AT)
