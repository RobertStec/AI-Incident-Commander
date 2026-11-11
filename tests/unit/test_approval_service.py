"""Unit tests for the remediation approval application service."""

import asyncio
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta, timezone
from typing import cast
from uuid import UUID, uuid4

import pytest

from ai_incident_commander.application.approval_authorization import (
    ApprovalAuthorizer,
    ApprovalPermissionDeniedError,
    AuthenticatedOperatorContext,
)
from ai_incident_commander.application.approval_repository import (
    ApprovalAlreadyDecidedError,
    ApprovalRepository,
    ApprovalRepositoryError,
    ApprovalRequestNotActiveError,
    ApprovalRequestNotFoundError,
)
from ai_incident_commander.application.approval_service import (
    ApprovalApplicationService,
    ApprovalClockError,
)
from ai_incident_commander.application.clock import Clock
from ai_incident_commander.domain.approval_decision_rules import (
    ApprovalDecisionOutsideWindowError,
)
from ai_incident_commander.domain.remediation_approval import (
    RemediationApprovalDecision,
    RemediationApprovalOutcome,
    RemediationApprovalRequest,
)

_START = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)


class RecordingClock:
    """Return a controlled time and track reads by the service."""

    def __init__(self, current_time: datetime, events: list[str]) -> None:
        self.current_time = current_time
        self.events = events
        self.read_count = 0

    def now(self) -> datetime:
        self.events.append("clock")
        self.read_count += 1
        return self.current_time


class RecordingAuthorizer:
    """Record authorization calls, optionally raising a supplied error."""

    def __init__(self, events: list[str]) -> None:
        self.events = events
        self.error: Exception | None = None
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
        self.events.append("authorize")
        self.calls.append((operator, request, outcome))
        if self.error is not None:
            raise self.error


class RecordingRepository:
    """Spy on persistence calls; do not emulate database atomicity here."""

    def __init__(self, request: RemediationApprovalRequest, events: list[str]) -> None:
        self.request: RemediationApprovalRequest | None = request
        self.events = events
        self.error: ApprovalRepositoryError | None = None
        self.saved: list[RemediationApprovalDecision] = []
        self.record_attempts: list[RemediationApprovalDecision] = []

    async def create_request(self, request: RemediationApprovalRequest) -> None:
        self.request = request

    async def get_request(self, request_id: UUID) -> RemediationApprovalRequest | None:
        self.events.append("get_request")
        if self.request is None or request_id != self.request.request_id:
            return None
        return self.request

    async def record_decision_once(self, decision: RemediationApprovalDecision) -> None:
        self.events.append("record_decision_once")
        self.record_attempts.append(decision)
        if self.error is not None:
            raise self.error
        self.saved.append(decision)


@dataclass
class ApprovalHarness:
    """Dependencies shared by the application-service unit tests."""

    service: ApprovalApplicationService
    request: RemediationApprovalRequest
    operator: AuthenticatedOperatorContext
    repository: RecordingRepository
    authorizer: RecordingAuthorizer
    clock: RecordingClock
    events: list[str]


def _make_harness() -> ApprovalHarness:
    request = RemediationApprovalRequest(
        plan_id=uuid4(),
        step_id=uuid4(),
        action_fingerprint="afp:v2:" + "a" * 64,
        policy_version="apv:v1:" + "b" * 64,
        requested_at=_START,
        expires_at=_START + timedelta(minutes=15),
    )
    operator = AuthenticatedOperatorContext(operator_id="operator-123")
    events: list[str] = []
    repository = RecordingRepository(request, events)
    authorizer = RecordingAuthorizer(events)
    clock = RecordingClock(_START + timedelta(minutes=5), events)

    repository_port: ApprovalRepository = repository
    authorizer_port: ApprovalAuthorizer = authorizer
    clock_port: Clock = clock
    service = ApprovalApplicationService(
        repository=repository_port,
        authorizer=authorizer_port,
        clock=clock_port,
    )
    return ApprovalHarness(service, request, operator, repository, authorizer, clock, events)


def _decide(
    harness: ApprovalHarness,
    *,
    outcome: RemediationApprovalOutcome = RemediationApprovalOutcome.APPROVED,
    reason: str = "Reviewed remediation evidence.",
    request_id: UUID | None = None,
) -> RemediationApprovalDecision:
    return asyncio.run(
        harness.service.decide(
            request_id=request_id if request_id is not None else harness.request.request_id,
            operator=harness.operator,
            outcome=outcome,
            reason=reason,
        )
    )


@pytest.mark.parametrize(
    "outcome",
    [RemediationApprovalOutcome.APPROVED, RemediationApprovalOutcome.REJECTED],
)
def test_decide_records_exact_authorized_operator_and_outcome(
    outcome: RemediationApprovalOutcome,
) -> None:
    harness = _make_harness()

    decision = _decide(harness, outcome=outcome)

    assert decision.request_id == harness.request.request_id
    assert decision.operator_id == harness.operator.operator_id
    assert decision.outcome is outcome
    assert decision.reason == "Reviewed remediation evidence."
    assert decision.decided_at is harness.clock.current_time
    assert harness.authorizer.calls == [(harness.operator, harness.request, outcome)]
    assert harness.authorizer.calls[0][0] is harness.operator
    assert harness.authorizer.calls[0][1] is harness.request
    assert harness.repository.saved == [decision]
    assert harness.repository.saved[0] is decision
    assert harness.events == ["get_request", "authorize", "clock", "record_decision_once"]
    assert harness.clock.read_count == 1


def test_decide_preserves_supplied_reason() -> None:
    harness = _make_harness()
    decision = _decide(harness, reason="Rollback reduces observed error rate.")
    assert decision.reason == "Rollback reduces observed error rate."


def test_missing_request_aborts_before_authorization_or_clock() -> None:
    harness = _make_harness()

    with pytest.raises(ApprovalRequestNotFoundError):
        _decide(harness, request_id=uuid4())

    assert harness.events == ["get_request"]
    assert harness.authorizer.calls == []
    assert harness.clock.read_count == 0
    assert harness.repository.record_attempts == []


@pytest.mark.parametrize("outcome", list(RemediationApprovalOutcome))
def test_permission_denied_prevents_clock_read_and_write(
    outcome: RemediationApprovalOutcome,
) -> None:
    harness = _make_harness()
    harness.authorizer.error = ApprovalPermissionDeniedError("No approval permission.")

    with pytest.raises(ApprovalPermissionDeniedError):
        _decide(harness, outcome=outcome)

    assert harness.events == ["get_request", "authorize"]
    assert harness.clock.read_count == 0
    assert harness.repository.record_attempts == []


def test_authorization_backend_failure_is_propagated_without_persisting() -> None:
    harness = _make_harness()
    failure = RuntimeError("Authorization backend unavailable.")
    harness.authorizer.error = failure

    with pytest.raises(RuntimeError) as captured:
        _decide(harness)

    assert captured.value is failure
    assert harness.events == ["get_request", "authorize"]
    assert harness.repository.saved == []


@pytest.mark.parametrize(
    "invalid_time",
    [
        datetime(2026, 1, 1, 12, 5),
        datetime(2026, 1, 1, 14, 5, tzinfo=timezone(timedelta(hours=2))),
        None,
        "2026-01-01T12:05:00Z",
    ],
    ids=["naive", "nonzero-offset", "none", "string"],
)
def test_invalid_clock_fails_closed_before_persisting(invalid_time: object) -> None:
    harness = _make_harness()
    harness.clock.current_time = cast(datetime, invalid_time)

    with pytest.raises(ApprovalClockError):
        _decide(harness)

    assert harness.events == ["get_request", "authorize", "clock"]
    assert harness.repository.record_attempts == []


def test_zero_offset_named_timezone_is_accepted() -> None:
    harness = _make_harness()
    harness.clock.current_time = datetime(
        2026, 1, 1, 12, 5, tzinfo=timezone(timedelta(0), "UTC_ALIAS")
    )

    decision = _decide(harness)

    assert decision.decided_at.utcoffset() == timedelta(0)
    assert harness.repository.saved == [decision]


@pytest.mark.parametrize(
    "invalid_time",
    [
        _START - timedelta(microseconds=1),
        _START + timedelta(minutes=15),
        _START + timedelta(minutes=15, microseconds=1),
    ],
    ids=["before-start", "at-expiry", "after-expiry"],
)
def test_decision_outside_request_window_does_not_reach_repository(
    invalid_time: datetime,
) -> None:
    harness = _make_harness()
    harness.clock.current_time = invalid_time

    with pytest.raises(ApprovalDecisionOutsideWindowError):
        _decide(harness)

    assert harness.events == ["get_request", "authorize", "clock"]
    assert harness.repository.record_attempts == []


@pytest.mark.parametrize(
    "valid_time",
    [_START, _START + timedelta(minutes=15) - timedelta(microseconds=1)],
    ids=["at-start", "just-before-expiry"],
)
def test_application_accepts_both_valid_time_boundaries(valid_time: datetime) -> None:
    harness = _make_harness()
    harness.clock.current_time = valid_time

    decision = _decide(harness)

    assert decision.decided_at == valid_time
    assert harness.repository.saved == [decision]


@pytest.mark.parametrize("reason", ["", " ", "\n\t"])
def test_invalid_reason_fails_without_persisting(reason: str) -> None:
    harness = _make_harness()

    with pytest.raises(ValueError, match="reason"):
        _decide(harness, reason=reason)

    assert harness.events == ["get_request", "authorize", "clock"]
    assert harness.repository.record_attempts == []


@pytest.mark.parametrize(
    "error",
    [
        ApprovalAlreadyDecidedError("Already decided."),
        ApprovalRequestNotActiveError("Expired during persistence."),
        ApprovalRequestNotFoundError("Removed before persistence."),
    ],
    ids=["already-decided", "expired-at-storage", "removed-at-storage"],
)
def test_persistence_failure_is_propagated_without_returning_decision(
    error: ApprovalRepositoryError,
) -> None:
    harness = _make_harness()
    harness.repository.error = error

    with pytest.raises(ApprovalRepositoryError) as captured:
        _decide(harness)

    assert captured.value is error
    assert len(harness.repository.record_attempts) == 1
    assert harness.repository.saved == []
    assert harness.events == ["get_request", "authorize", "clock", "record_decision_once"]
