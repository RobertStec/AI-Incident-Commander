"""Structural contract tests for the execution-claim repository port.

These do not test atomicity or PostgreSQL authorization; integration tests
will establish those guarantees for the real adapter.
"""

import asyncio
import inspect
from datetime import UTC, datetime
from typing import get_type_hints
from uuid import UUID, uuid4

import pytest

from ai_incident_commander.application.execution_claim_repository import (
    ExecutionClaimAlreadyExistsError,
    ExecutionClaimApprovalDeniedError,
    ExecutionClaimRepository,
    ExecutionClaimRepositoryError,
    ExecutionClaimScopeMismatchError,
)
from ai_incident_commander.domain.execution_claim import ExecutionClaim


class StubClaimRepository:
    """Test double proving the port can be injected and called asynchronously."""

    def __init__(self, claim: ExecutionClaim) -> None:
        self.claim = claim
        self.calls: list[tuple[UUID, UUID, UUID, str, str]] = []

    async def claim_once(
        self,
        *,
        request_id: UUID,
        plan_id: UUID,
        step_id: UUID,
        action_fingerprint: str,
        policy_version: str,
    ) -> ExecutionClaim:
        self.calls.append((request_id, plan_id, step_id, action_fingerprint, policy_version))
        return self.claim


def _make_claim() -> ExecutionClaim:
    return ExecutionClaim(
        request_id=uuid4(),
        plan_id=uuid4(),
        step_id=uuid4(),
        action_fingerprint="afp:v2:" + "a" * 64,
        policy_version="apv:v1:" + "b" * 64,
        claimed_at=datetime(2026, 11, 12, 17, tzinfo=UTC),
    )


def test_claim_once_requires_explicit_keyword_only_scope() -> None:
    parameters = inspect.signature(ExecutionClaimRepository.claim_once).parameters
    assert list(parameters) == [
        "self",
        "request_id",
        "plan_id",
        "step_id",
        "action_fingerprint",
        "policy_version",
    ]
    for name in list(parameters)[1:]:
        assert parameters[name].kind is inspect.Parameter.KEYWORD_ONLY
        assert parameters[name].default is inspect.Parameter.empty


def test_claim_once_does_not_accept_untrusted_timestamp_or_prebuilt_claim() -> None:
    parameters = inspect.signature(ExecutionClaimRepository.claim_once).parameters
    assert "claimed_at" not in parameters
    assert "claim_id" not in parameters
    assert "claim" not in parameters


def test_claim_once_returns_execution_claim() -> None:
    assert get_type_hints(ExecutionClaimRepository.claim_once)["return"] is ExecutionClaim


def test_port_accepts_async_adapter_with_explicit_scope() -> None:
    claim = _make_claim()
    stub: ExecutionClaimRepository = StubClaimRepository(claim)

    result = asyncio.run(
        stub.claim_once(
            request_id=claim.request_id,
            plan_id=claim.plan_id,
            step_id=claim.step_id,
            action_fingerprint=claim.action_fingerprint,
            policy_version=claim.policy_version,
        )
    )

    assert result is claim
    assert isinstance(stub, StubClaimRepository)
    assert stub.calls == [
        (
            claim.request_id,
            claim.plan_id,
            claim.step_id,
            claim.action_fingerprint,
            claim.policy_version,
        )
    ]


@pytest.mark.parametrize(
    "error_type",
    [
        ExecutionClaimAlreadyExistsError,
        ExecutionClaimApprovalDeniedError,
        ExecutionClaimScopeMismatchError,
    ],
)
def test_expected_refusals_share_repository_error_base(
    error_type: type[ExecutionClaimRepositoryError],
) -> None:
    error = error_type("Execution claim refused.")
    assert isinstance(error, ExecutionClaimRepositoryError)
