"""Contract tests for the asynchronous approval repository port."""

import asyncio
import inspect
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest

from ai_incident_commander.application.approval_repository import (
    ApprovalAlreadyDecidedError,
    ApprovalRepository,
    ApprovalRepositoryError,
    ApprovalRequestAlreadyExistsError,
    ApprovalRequestNotFoundError,
)
from ai_incident_commander.domain.remediation_approval import (
    RemediationApprovalDecision,
    RemediationApprovalOutcome,
    RemediationApprovalRequest,
)


class InMemoryApprovalRepository:
    """Test double implementing atomic single-decision behavior in one process."""

    def __init__(self) -> None:
        self.requests: dict[UUID, RemediationApprovalRequest] = {}
        self.decisions: dict[UUID, RemediationApprovalDecision] = {}
        self._lock = asyncio.Lock()

    async def create_request(self, request: RemediationApprovalRequest) -> None:
        async with self._lock:
            if request.request_id in self.requests:
                raise ApprovalRequestAlreadyExistsError("Duplicate request.")
            self.requests[request.request_id] = request

    async def get_request(self, request_id: UUID) -> RemediationApprovalRequest | None:
        return self.requests.get(request_id)

    async def record_decision_once(self, decision: RemediationApprovalDecision) -> None:
        async with self._lock:
            if decision.request_id not in self.requests:
                raise ApprovalRequestNotFoundError("Unknown request.")
            if decision.request_id in self.decisions:
                raise ApprovalAlreadyDecidedError("Request already decided.")
            await asyncio.sleep(0)  # Expose races if the lock is removed.
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
    repository: ApprovalRepository = InMemoryApprovalRepository()
    request = _make_request()

    async def scenario() -> None:
        await repository.create_request(request)
        assert await repository.get_request(request.request_id) is request

    asyncio.run(scenario())


def test_repository_operations_are_asynchronous() -> None:
    assert inspect.iscoroutinefunction(ApprovalRepository.create_request)
    assert inspect.iscoroutinefunction(ApprovalRepository.get_request)
    assert inspect.iscoroutinefunction(ApprovalRepository.record_decision_once)
    assert inspect.iscoroutinefunction(InMemoryApprovalRepository.create_request)
    assert inspect.iscoroutinefunction(InMemoryApprovalRepository.get_request)
    assert inspect.iscoroutinefunction(InMemoryApprovalRepository.record_decision_once)


def test_unknown_request_returns_none() -> None:
    repository: ApprovalRepository = InMemoryApprovalRepository()
    assert asyncio.run(repository.get_request(uuid4())) is None


def test_duplicate_request_is_rejected_without_overwrite() -> None:
    repository = InMemoryApprovalRepository()
    request = _make_request()

    async def scenario() -> None:
        await repository.create_request(request)
        with pytest.raises(ApprovalRequestAlreadyExistsError):
            await repository.create_request(request)
        assert await repository.get_request(request.request_id) is request
        assert len(repository.requests) == 1

    asyncio.run(scenario())


def test_decision_for_missing_request_is_rejected() -> None:
    repository: ApprovalRepository = InMemoryApprovalRepository()
    decision = _make_decision(uuid4())

    with pytest.raises(ApprovalRequestNotFoundError):
        asyncio.run(repository.record_decision_once(decision))


def test_first_decision_is_recorded_unchanged() -> None:
    repository = InMemoryApprovalRepository()
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
    repository = InMemoryApprovalRepository()
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
    repository = InMemoryApprovalRepository()
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
    repository = InMemoryApprovalRepository()
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
    "error_type",
    [
        ApprovalRequestAlreadyExistsError,
        ApprovalRequestNotFoundError,
        ApprovalAlreadyDecidedError,
    ],
)
def test_repository_errors_inherit_from_common_base(
    error_type: type[ApprovalRepositoryError],
) -> None:
    assert isinstance(error_type("Persistence failed."), ApprovalRepositoryError)
