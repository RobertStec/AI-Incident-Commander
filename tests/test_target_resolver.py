"""Tests for the application target resolver port."""

import asyncio
import inspect

import pytest

from ai_incident_commander.application.target_resolver import (
    AmbiguousTargetError,
    TargetNotFoundError,
    TargetResolutionError,
    TargetResolver,
    TargetSourceUnavailableError,
)
from ai_incident_commander.domain.target_identity import ResolvedTarget


class StubTargetResolver:
    """Controlled resolver implementation for contract tests."""

    def __init__(self, result: ResolvedTarget) -> None:
        self.result = result
        self.requests: list[tuple[str, str]] = []

    async def resolve(
        self,
        *,
        target: str,
        environment: str,
    ) -> ResolvedTarget:
        self.requests.append((target, environment))
        return self.result


class FailingTargetResolver:
    """Resolver that simulates an authoritative source failure."""

    def __init__(self, error: TargetResolutionError) -> None:
        self.error = error

    async def resolve(
        self,
        *,
        target: str,
        environment: str,
    ) -> ResolvedTarget:
        raise self.error


def _make_resolved_target(
    environment: str = "incident-lab",
) -> ResolvedTarget:
    """Build a resolved identity returned by a test resolver."""
    return ResolvedTarget(
        target="payments-api",
        resource_id="service-123",
        environment=environment,
        source="service-inventory",
    )


def test_target_resolver_accepts_structural_implementation() -> None:
    expected = _make_resolved_target()
    resolver: TargetResolver = StubTargetResolver(expected)

    result = asyncio.run(
        resolver.resolve(
            target="payments-api",
            environment="incident-lab",
        )
    )

    assert result is expected
    assert result.resource_id == "service-123"


def test_target_resolver_receives_requested_scope() -> None:
    stub = StubTargetResolver(_make_resolved_target())
    resolver: TargetResolver = stub

    asyncio.run(
        resolver.resolve(
            target="payments-api",
            environment="incident-lab",
        )
    )

    assert stub.requests == [
        ("payments-api", "incident-lab"),
    ]


def test_target_resolver_contract_is_asynchronous() -> None:
    assert inspect.iscoroutinefunction(TargetResolver.resolve)
    assert inspect.iscoroutinefunction(StubTargetResolver.resolve)


def test_target_resolver_does_not_implicitly_rewrite_environment() -> None:
    expected = _make_resolved_target(environment="production")
    resolver: TargetResolver = StubTargetResolver(expected)

    result = asyncio.run(
        resolver.resolve(
            target="payments-api",
            environment="incident-lab",
        )
    )

    assert result is expected
    assert result.environment == "production"


@pytest.mark.parametrize(
    "error_type",
    [
        TargetNotFoundError,
        AmbiguousTargetError,
        TargetSourceUnavailableError,
    ],
)
def test_target_resolution_errors_inherit_from_common_base(
    error_type: type[TargetResolutionError],
) -> None:
    error = error_type("Resolution failed.")

    assert isinstance(error, TargetResolutionError)


@pytest.mark.parametrize(
    "error_type",
    [
        TargetNotFoundError,
        AmbiguousTargetError,
        TargetSourceUnavailableError,
    ],
)
def test_target_resolver_propagates_resolution_failures(
    error_type: type[TargetResolutionError],
) -> None:
    expected_error = error_type("Resolution failed.")
    resolver: TargetResolver = FailingTargetResolver(expected_error)

    with pytest.raises(error_type) as captured:
        asyncio.run(
            resolver.resolve(
                target="payments-api",
                environment="incident-lab",
            )
        )

    assert captured.value is expected_error
