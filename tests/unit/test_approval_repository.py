"""Contract tests for the asynchronous approval repository port."""

import asyncio
import inspect
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest

from ai_incident_commander.application.approval_repository import (
    ApprovalAlreadyDecidedError,
    ApprovalRepository,
    ApprovalRepositoryError,
    ApprovalRequestAlreadyExistsError,
    ApprovalRequestNotActiveError,
    ApprovalRequestNotFoundError,
)
from ai_incident_commander.application.clock import Clock
from ai_incident_commander.domain.remediation_approval import (
    RemediationApprovalDecision,
    RemediationApprovalOutcome,
    RemediationApprovalRequest,
)


class FakeClock:
    """Controllable storage-side clock for repository contract tests."""

    def __init__(self, current_time: datetime) -> None:
        self.current_time = current_time
        self.read_count = 0

    def now(self) -> datetime:
        self.read_count += 1
        return self.current_time


class InMemoryApprovalRepository:
    """Test double with locked, storage-time-checked decision writes."""

    def __init__(self, clock: Clock) -> None:
        self.requests: dict[UUID, RemediationApprovalRequest] = {}
        self.decisions: dict[UUID, RemediationApprovalDecision] = {}
        self._clock = clock
        self._lock = asyncio.Lock()
        self.record_attempt_started = asyncio.Event()
        self.two_record_attempts_started = asyncio.Event()
        self._record_attempt_count = 0

    async def create_request(self, request: RemediationApprovalRequest) -> None:
        async with self._lock:
            if request.request_id in self.requests:
                raise ApprovalRequestAlreadyExistsError("Duplicate request.")
            self.requests[request.request_id] = request

    async def get_request(self, request_id: UUID) -> RemediationApprovalRequest | None:
        return self.requests.get(request_id)

    async def get_decision(self, request_id: UUID) -> RemediationApprovalDecision | None:
        return self.decisions.get(request_id)

    async def record_decision_once(self, decision: RemediationApprovalDecision) -> None:
        self._record_attempt_count += 1
        self.record_attempt_started.set()
        if self._record_attempt_count == 2:
            self.two_record_attempts_started.set()

        async with self._lock:
            request = self.requests.get(decision.request_id)
            if request is None:
                raise ApprovalRequestNotFoundError("Unknown request.")
            if decision.request_id in self.decisions:
                raise ApprovalAlreadyDecidedError("Request already decided.")

            await asyncio.sleep(0)  # Exercise concurrency inside the lock.
            recorded_at = self._clock.now()
            if not (request.requested_at <= recorded_at < request.expires_at):
                raise ApprovalRequestNotActiveError("Inactive approval request.")

            self.decisions[decision.request_id] = decision


def _make_request() -> RemediationApprovalRequest:
    requested_at = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
    return RemediationApprovalRequest(
        plan_id=uuid4(),
        step_id=uuid4(),
        action_fingerprint="afp:v2:" + "a" * 64,
        policy_version="apv:v1:" + "b" * 64,
        requested_at=requested_at,
        expires_at=requested_at + timedelta(minutes=15),
    )


def _make_repository() -> InMemoryApprovalRepository:
    """Use an active, deterministic storage clock in existing tests."""
    current_time = datetime(2026, 1, 1, 12, 5, tzinfo=UTC)
    return InMemoryApprovalRepository(FakeClock(current_time))


def _make_decision(
    request_id: UUID,
    outcome: RemediationApprovalOutcome = RemediationApprovalOutcome.APPROVED,
) -> RemediationApprovalDecision:
    return RemediationApprovalDecision(
        request_id=request_id,
        operator_id="operator-123",
        outcome=outcome,
        decided_at=datetime(2026, 1, 1, 12, 5, tzinfo=UTC),
        reason="Reviewed remediation scope.",
    )


def test_repository_supports_structural_protocol() -> None:
    repository: ApprovalRepository = _make_repository()
    request = _make_request()

    async def scenario() -> None:
        await repository.create_request(request)
        assert await repository.get_request(request.request_id) is request

    asyncio.run(scenario())


def test_repository_operations_are_asynchronous() -> None:
    assert inspect.iscoroutinefunction(ApprovalRepository.create_request)
    assert inspect.iscoroutinefunction(ApprovalRepository.get_request)
    assert inspect.iscoroutinefunction(ApprovalRepository.get_decision)
    assert inspect.iscoroutinefunction(ApprovalRepository.record_decision_once)
    assert inspect.iscoroutinefunction(InMemoryApprovalRepository.create_request)
    assert inspect.iscoroutinefunction(InMemoryApprovalRepository.get_request)
    assert inspect.iscoroutinefunction(InMemoryApprovalRepository.get_decision)
    assert inspect.iscoroutinefunction(InMemoryApprovalRepository.record_decision_once)


def test_unknown_request_returns_none() -> None:
    repository: ApprovalRepository = _make_repository()
    assert asyncio.run(repository.get_request(uuid4())) is None


def test_get_decision_returns_none_for_missing_request() -> None:
    repository: ApprovalRepository = _make_repository()
    assert asyncio.run(repository.get_decision(uuid4())) is None


def test_get_decision_returns_none_before_decision() -> None:
    repository: ApprovalRepository = _make_repository()
    request = _make_request()

    async def scenario() -> None:
        await repository.create_request(request)
        assert await repository.get_decision(request.request_id) is None

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "outcome",
    [RemediationApprovalOutcome.APPROVED, RemediationApprovalOutcome.REJECTED],
)
def test_get_decision_returns_persisted_result(outcome: RemediationApprovalOutcome) -> None:
    repository: ApprovalRepository = _make_repository()
    request = _make_request()
    decision = _make_decision(request.request_id, outcome)

    async def scenario() -> None:
        await repository.create_request(request)
        await repository.record_decision_once(decision)
        assert await repository.get_decision(request.request_id) == decision

    asyncio.run(scenario())


def test_duplicate_request_is_rejected_without_overwrite() -> None:
    repository = _make_repository()
    request = _make_request()

    async def scenario() -> None:
        await repository.create_request(request)
        with pytest.raises(ApprovalRequestAlreadyExistsError):
            await repository.create_request(request)
        assert await repository.get_request(request.request_id) is request
        assert len(repository.requests) == 1

    asyncio.run(scenario())


def test_decision_for_missing_request_is_rejected() -> None:
    repository: ApprovalRepository = _make_repository()
    decision = _make_decision(uuid4())

    with pytest.raises(ApprovalRequestNotFoundError):
        asyncio.run(repository.record_decision_once(decision))


def test_first_decision_is_recorded_unchanged() -> None:
    repository = _make_repository()
    request = _make_request()
    decision = _make_decision(request.request_id)

    async def scenario() -> None:
        await repository.create_request(request)
        await repository.record_decision_once(decision)

    asyncio.run(scenario())
    assert repository.decisions[request.request_id] is decision


@pytest.mark.parametrize(
    "second_outcome",
    [RemediationApprovalOutcome.APPROVED, RemediationApprovalOutcome.REJECTED],
)
def test_second_decision_is_rejected_without_overwrite(
    second_outcome: RemediationApprovalOutcome,
) -> None:
    repository = _make_repository()
    request = _make_request()
    first = _make_decision(request.request_id)
    second = _make_decision(request.request_id, outcome=second_outcome)

    async def scenario() -> None:
        await repository.create_request(request)
        await repository.record_decision_once(first)
        with pytest.raises(ApprovalAlreadyDecidedError):
            await repository.record_decision_once(second)

    asyncio.run(scenario())
    assert repository.decisions[request.request_id] is first


def test_independent_requests_can_each_have_a_decision() -> None:
    repository = _make_repository()
    first_request = _make_request()
    second_request = _make_request()

    async def scenario() -> None:
        await repository.create_request(first_request)
        await repository.create_request(second_request)
        await repository.record_decision_once(_make_decision(first_request.request_id))
        await repository.record_decision_once(
            _make_decision(second_request.request_id, RemediationApprovalOutcome.REJECTED)
        )

    asyncio.run(scenario())
    assert len(repository.decisions) == 2


def test_concurrent_decisions_allow_only_one_winner_in_test_double() -> None:
    repository = _make_repository()
    request = _make_request()
    approved = _make_decision(request.request_id)
    rejected = _make_decision(request.request_id, RemediationApprovalOutcome.REJECTED)

    async def scenario() -> list[None | BaseException]:
        await repository.create_request(request)
        return list(
            await asyncio.gather(
                repository.record_decision_once(approved),
                repository.record_decision_once(rejected),
                return_exceptions=True,
            )
        )

    results = asyncio.run(scenario())
    assert sum(result is None for result in results) == 1
    assert sum(isinstance(result, ApprovalAlreadyDecidedError) for result in results) == 1
    assert repository.decisions[request.request_id] in (approved, rejected)


@pytest.mark.parametrize(
    "recorded_at",
    [
        datetime(2026, 1, 1, 12, 0, tzinfo=UTC),
        datetime(2026, 1, 1, 12, 14, 59, 999999, tzinfo=UTC),
    ],
)
def test_storage_accepts_request_within_active_window(
    recorded_at: datetime,
) -> None:
    clock = FakeClock(recorded_at)
    repository = InMemoryApprovalRepository(clock)
    request = _make_request()
    decision = replace(_make_decision(request.request_id), decided_at=recorded_at)

    async def scenario() -> None:
        await repository.create_request(request)
        await repository.record_decision_once(decision)

    asyncio.run(scenario())

    assert repository.decisions[request.request_id] is decision
    assert clock.read_count == 1


@pytest.mark.parametrize(
    "recorded_at",
    [
        datetime(2026, 1, 1, 11, 59, 59, 999999, tzinfo=UTC),
        datetime(2026, 1, 1, 12, 15, tzinfo=UTC),
        datetime(2026, 1, 1, 12, 15, 0, 1, tzinfo=UTC),
    ],
)
def test_storage_rejects_request_outside_active_window(
    recorded_at: datetime,
) -> None:
    clock = FakeClock(recorded_at)
    repository = InMemoryApprovalRepository(clock)
    request = _make_request()
    decision = _make_decision(request.request_id)

    async def scenario() -> None:
        await repository.create_request(request)
        with pytest.raises(ApprovalRequestNotActiveError):
            await repository.record_decision_once(decision)

    asyncio.run(scenario())

    assert repository.decisions == {}
    assert clock.read_count == 1


def test_backdated_decision_does_not_bypass_storage_expiration() -> None:
    request = _make_request()
    clock = FakeClock(request.expires_at + timedelta(seconds=1))
    repository = InMemoryApprovalRepository(clock)
    decision = _make_decision(request.request_id)
    assert request.requested_at <= decision.decided_at < request.expires_at

    async def scenario() -> None:
        await repository.create_request(request)
        with pytest.raises(ApprovalRequestNotActiveError):
            await repository.record_decision_once(decision)

    asyncio.run(scenario())
    assert request.request_id not in repository.decisions


def test_expiration_while_waiting_for_lock_rejects_decision() -> None:
    request = _make_request()
    clock = FakeClock(request.expires_at - timedelta(microseconds=1))
    repository = InMemoryApprovalRepository(clock)
    decision = _make_decision(request.request_id)

    async def scenario() -> None:
        await repository.create_request(request)
        async with repository._lock:
            pending = asyncio.create_task(repository.record_decision_once(decision))
            await repository.record_attempt_started.wait()
            assert clock.read_count == 0
            clock.current_time = request.expires_at

        with pytest.raises(ApprovalRequestNotActiveError):
            await pending

    asyncio.run(scenario())
    assert repository.decisions == {}
    assert clock.read_count == 1


def test_two_competing_decisions_expire_while_waiting_for_lock() -> None:
    request = _make_request()
    clock = FakeClock(request.expires_at - timedelta(microseconds=1))
    repository = InMemoryApprovalRepository(clock)
    approved = _make_decision(request.request_id)
    rejected = _make_decision(request.request_id, RemediationApprovalOutcome.REJECTED)

    async def scenario() -> list[None | BaseException]:
        await repository.create_request(request)
        async with repository._lock:
            first = asyncio.create_task(repository.record_decision_once(approved))
            second = asyncio.create_task(repository.record_decision_once(rejected))
            await repository.two_record_attempts_started.wait()
            assert clock.read_count == 0
            clock.current_time = request.expires_at

        return list(await asyncio.gather(first, second, return_exceptions=True))

    results = asyncio.run(scenario())
    assert len(results) == 2
    assert all(isinstance(error, ApprovalRequestNotActiveError) for error in results)
    assert repository.decisions == {}
    assert clock.read_count == 2


@pytest.mark.parametrize(
    "error_type",
    [
        ApprovalRequestAlreadyExistsError,
        ApprovalRequestNotFoundError,
        ApprovalRequestNotActiveError,
        ApprovalAlreadyDecidedError,
    ],
)
def test_repository_errors_inherit_from_common_base(
    error_type: type[ApprovalRepositoryError],
) -> None:
    assert isinstance(error_type("Persistence failed."), ApprovalRepositoryError)
