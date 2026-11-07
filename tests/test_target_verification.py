"""Tests for authoritative remediation target verification."""

import asyncio
from typing import cast
from uuid import uuid4

import pytest

from ai_incident_commander.application.target_resolver import (
    AmbiguousTargetError,
    TargetNotFoundError,
    TargetResolutionError,
    TargetResolver,
    TargetSourceUnavailableError,
)
from ai_incident_commander.application.target_verification import (
    InvalidResolvedTargetError,
    TargetIdentityMismatchError,
    verify_remediation_target,
)
from ai_incident_commander.domain.remediation import (
    RemediationRiskLevel,
    RemediationStep,
)
from ai_incident_commander.domain.target_identity import ResolvedTarget


class StubTargetResolver:
    """Return a controlled result and record resolution requests."""

    def __init__(self, result: object) -> None:
        self.result = result
        self.requests: list[tuple[str, str]] = []

    async def resolve(
        self,
        *,
        target: str,
        environment: str,
    ) -> ResolvedTarget:
        self.requests.append((target, environment))
        return cast(ResolvedTarget, self.result)


class FailingTargetResolver:
    """Simulate a resolver that raises a controlled exception."""

    def __init__(self, error: Exception) -> None:
        self.error = error

    async def resolve(
        self,
        *,
        target: str,
        environment: str,
    ) -> ResolvedTarget:
        raise self.error


def _make_step(
    *,
    target: str = "payments-api",
    environment: str = "incident-lab",
) -> RemediationStep:
    """Create a valid proposed remediation step."""
    return RemediationStep(
        plan_id=uuid4(),
        position=1,
        action_name="restart_service",
        target=target,
        environment=environment,
        risk_level=RemediationRiskLevel.HIGH,
    )


def _make_identity(
    *,
    target: str = "payments-api",
    environment: str = "incident-lab",
) -> ResolvedTarget:
    """Create a resolved identity returned by the test inventory."""
    return ResolvedTarget(
        target=target,
        resource_id="service-123",
        environment=environment,
        source="service-inventory",
    )


def test_target_verification_returns_original_resolved_identity() -> None:
    step = _make_step()
    expected = _make_identity()
    resolver: TargetResolver = StubTargetResolver(expected)

    result = asyncio.run(verify_remediation_target(step, resolver))

    assert result is expected
    assert result.resource_id == "service-123"
    assert result.source == "service-inventory"


def test_target_verification_passes_requested_scope_to_resolver() -> None:
    step = _make_step()
    stub = StubTargetResolver(_make_identity())
    resolver: TargetResolver = stub

    asyncio.run(verify_remediation_target(step, resolver))

    assert stub.requests == [("payments-api", "incident-lab")]


@pytest.mark.parametrize(
    "resolved_name",
    ["other-api", " payments-api "],
)
def test_target_verification_rejects_target_name_mismatch(
    resolved_name: str,
) -> None:
    step = _make_step()
    resolver: TargetResolver = StubTargetResolver(_make_identity(target=resolved_name))

    with pytest.raises(TargetIdentityMismatchError):
        asyncio.run(verify_remediation_target(step, resolver))


@pytest.mark.parametrize(
    "resolved_environment",
    ["staging", "production"],
)
def test_target_verification_rejects_environment_mismatch(
    resolved_environment: str,
) -> None:
    step = _make_step()
    resolver: TargetResolver = StubTargetResolver(_make_identity(environment=resolved_environment))

    with pytest.raises(TargetIdentityMismatchError):
        asyncio.run(verify_remediation_target(step, resolver))


def test_target_verification_rejects_both_identity_mismatches() -> None:
    step = _make_step()
    resolver: TargetResolver = StubTargetResolver(
        _make_identity(
            target="other-api",
            environment="production",
        )
    )

    with pytest.raises(TargetIdentityMismatchError):
        asyncio.run(verify_remediation_target(step, resolver))


@pytest.mark.parametrize(
    "invalid_result",
    [
        None,
        123,
        "payments-api",
        {"target": "payments-api"},
    ],
)
def test_target_verification_rejects_invalid_resolver_results(
    invalid_result: object,
) -> None:
    step = _make_step()
    resolver: TargetResolver = StubTargetResolver(invalid_result)

    with pytest.raises(
        InvalidResolvedTargetError,
        match="Target resolver returned an invalid identity",
    ):
        asyncio.run(verify_remediation_target(step, resolver))


@pytest.mark.parametrize(
    "error_type",
    [
        TargetNotFoundError,
        AmbiguousTargetError,
        TargetSourceUnavailableError,
    ],
)
def test_target_verification_propagates_resolution_errors(
    error_type: type[TargetResolutionError],
) -> None:
    step = _make_step()
    expected_error = error_type("Resolution failed.")
    resolver: TargetResolver = FailingTargetResolver(expected_error)

    with pytest.raises(error_type) as captured:
        asyncio.run(verify_remediation_target(step, resolver))

    assert captured.value is expected_error


def test_target_verification_does_not_swallow_unexpected_errors() -> None:
    step = _make_step()
    expected_error = RuntimeError("Unexpected inventory failure.")
    resolver: TargetResolver = FailingTargetResolver(expected_error)

    with pytest.raises(RuntimeError) as captured:
        asyncio.run(verify_remediation_target(step, resolver))

    assert captured.value is expected_error


@pytest.mark.parametrize(
    "error_type",
    [
        TargetIdentityMismatchError,
        InvalidResolvedTargetError,
    ],
)
def test_target_verification_errors_share_resolution_base(
    error_type: type[TargetResolutionError],
) -> None:
    assert isinstance(error_type("Verification failed."), TargetResolutionError)


def test_target_verification_rejection_does_not_modify_step() -> None:
    step = _make_step()
    original_step_id = step.step_id
    original_target = step.target
    original_environment = step.environment

    resolver: TargetResolver = StubTargetResolver(_make_identity(environment="production"))

    with pytest.raises(TargetIdentityMismatchError):
        asyncio.run(verify_remediation_target(step, resolver))

    assert step.step_id == original_step_id
    assert step.target == original_target
    assert step.environment == original_environment


def test_target_verification_mismatch_error_does_not_expose_identity() -> None:
    step = _make_step()
    resolver: TargetResolver = StubTargetResolver(
        _make_identity(
            target="sensitive-service",
            environment="production",
        )
    )

    with pytest.raises(TargetIdentityMismatchError) as captured:
        asyncio.run(verify_remediation_target(step, resolver))

    message = str(captured.value)

    assert "sensitive-service" not in message
    assert "production" not in message
    assert "service-123" not in message
