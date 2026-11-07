"""Tests for application remediation preflight validation."""

import asyncio
from dataclasses import FrozenInstanceError
from typing import cast
from uuid import uuid4

import pytest

from ai_incident_commander.application.remediation_preflight import (
    RemediationPreflightResult,
    validate_remediation_preflight,
)
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
)
from ai_incident_commander.domain.action_catalog import (
    ActionCatalog,
    ActionDefinition,
    ActionEffect,
    ActionEnvironmentNotAllowedError,
    ActionParameterValidationError,
    ActionRiskMismatchError,
    UnknownActionError,
)
from ai_incident_commander.domain.remediation import (
    RemediationParameterValue,
    RemediationRiskLevel,
    RemediationStep,
)
from ai_incident_commander.domain.target_identity import ResolvedTarget


class RecordingTargetResolver:
    """Return a controlled response and record resolver calls."""

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
    """Simulate a resolver failure."""

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
    action_name: str = "restart_service",
    target: str = "payments-api",
    environment: str = "incident-lab",
    risk_level: RemediationRiskLevel = RemediationRiskLevel.HIGH,
    parameters: dict[str, RemediationParameterValue] | None = None,
) -> RemediationStep:
    """Create a proposed remediation step."""
    return RemediationStep(
        plan_id=uuid4(),
        position=1,
        action_name=action_name,
        target=target,
        environment=environment,
        risk_level=risk_level,
        parameters={} if parameters is None else parameters,
    )


def _make_action_definition(
    *,
    effect: ActionEffect = ActionEffect.MUTATING,
    risk_level: RemediationRiskLevel = RemediationRiskLevel.HIGH,
) -> ActionDefinition:
    """Create a trusted action explicitly allowed in the lab."""
    return ActionDefinition(
        action_name="restart_service",
        description="Restart an affected service.",
        effect=effect,
        risk_level=risk_level,
        allowed_environments=("incident-lab",),
    )


def _make_resolved_target(
    *,
    target: str = "payments-api",
    environment: str = "incident-lab",
) -> ResolvedTarget:
    """Create a canonical target identity."""
    return ResolvedTarget(
        target=target,
        resource_id="service-123",
        environment=environment,
        source="service-inventory",
    )


def test_preflight_returns_trusted_action_and_resolved_target() -> None:
    definition = _make_action_definition()
    catalog = ActionCatalog(definitions=(definition,))
    resolved = _make_resolved_target()
    resolver: TargetResolver = RecordingTargetResolver(resolved)

    result = asyncio.run(validate_remediation_preflight(_make_step(), catalog, resolver))

    assert isinstance(result, RemediationPreflightResult)
    assert result.action is definition
    assert result.target is resolved


def test_preflight_passes_requested_scope_to_resolver() -> None:
    definition = _make_action_definition()
    catalog = ActionCatalog(definitions=(definition,))
    stub = RecordingTargetResolver(_make_resolved_target())
    resolver: TargetResolver = stub

    asyncio.run(validate_remediation_preflight(_make_step(), catalog, resolver))

    assert stub.requests == [("payments-api", "incident-lab")]


def test_preflight_result_cannot_be_modified() -> None:
    definition = _make_action_definition()
    catalog = ActionCatalog(definitions=(definition,))
    resolver: TargetResolver = RecordingTargetResolver(_make_resolved_target())

    result = asyncio.run(validate_remediation_preflight(_make_step(), catalog, resolver))

    field_name = "target"

    with pytest.raises(FrozenInstanceError):
        setattr(
            result,
            field_name,
            _make_resolved_target(target="other-api"),
        )

    assert result.target.target == "payments-api"


def test_preflight_accepts_valid_read_only_action() -> None:
    definition = _make_action_definition(
        effect=ActionEffect.READ_ONLY,
        risk_level=RemediationRiskLevel.LOW,
    )
    catalog = ActionCatalog(definitions=(definition,))
    resolver: TargetResolver = RecordingTargetResolver(_make_resolved_target())
    step = _make_step(risk_level=RemediationRiskLevel.LOW)

    result = asyncio.run(validate_remediation_preflight(step, catalog, resolver))

    assert result.action is definition
    assert result.action.effect is ActionEffect.READ_ONLY


@pytest.mark.parametrize(
    ("action_name", "risk_level", "environment", "parameters", "error_type"),
    [
        (
            "unknown_action",
            RemediationRiskLevel.HIGH,
            "incident-lab",
            {},
            UnknownActionError,
        ),
        (
            "restart_service",
            RemediationRiskLevel.LOW,
            "incident-lab",
            {},
            ActionRiskMismatchError,
        ),
        (
            "restart_service",
            RemediationRiskLevel.HIGH,
            "production",
            {},
            ActionEnvironmentNotAllowedError,
        ),
        (
            "restart_service",
            RemediationRiskLevel.HIGH,
            "incident-lab",
            {"unexpected": True},
            ActionParameterValidationError,
        ),
    ],
)
def test_preflight_rejects_invalid_catalog_input_without_resolver_call(
    action_name: str,
    risk_level: RemediationRiskLevel,
    environment: str,
    parameters: dict[str, RemediationParameterValue],
    error_type: type[Exception],
) -> None:
    catalog = ActionCatalog(definitions=(_make_action_definition(),))
    stub = RecordingTargetResolver(_make_resolved_target())
    resolver: TargetResolver = stub
    step = _make_step(
        action_name=action_name,
        risk_level=risk_level,
        environment=environment,
        parameters=parameters,
    )

    with pytest.raises(error_type):
        asyncio.run(validate_remediation_preflight(step, catalog, resolver))

    assert stub.requests == []


def test_preflight_preserves_catalog_validation_order() -> None:
    catalog = ActionCatalog(definitions=(_make_action_definition(),))
    stub = RecordingTargetResolver(_make_resolved_target())
    resolver: TargetResolver = stub
    step = _make_step(
        environment="production",
        risk_level=RemediationRiskLevel.LOW,
        parameters={"unexpected": True},
    )

    with pytest.raises(ActionRiskMismatchError):
        asyncio.run(validate_remediation_preflight(step, catalog, resolver))

    assert stub.requests == []


@pytest.mark.parametrize(
    ("resolved_target", "expected_error"),
    [
        (
            _make_resolved_target(target="other-api"),
            TargetIdentityMismatchError,
        ),
        (
            _make_resolved_target(environment="production"),
            TargetIdentityMismatchError,
        ),
    ],
)
def test_preflight_rejects_resolved_identity_mismatch(
    resolved_target: ResolvedTarget,
    expected_error: type[TargetResolutionError],
) -> None:
    catalog = ActionCatalog(definitions=(_make_action_definition(),))
    resolver: TargetResolver = RecordingTargetResolver(resolved_target)

    with pytest.raises(expected_error):
        asyncio.run(validate_remediation_preflight(_make_step(), catalog, resolver))


@pytest.mark.parametrize(
    "invalid_result",
    [
        None,
        "payments-api",
        {"target": "payments-api"},
    ],
)
def test_preflight_rejects_invalid_resolver_result(
    invalid_result: object,
) -> None:
    catalog = ActionCatalog(definitions=(_make_action_definition(),))
    resolver: TargetResolver = RecordingTargetResolver(invalid_result)

    with pytest.raises(InvalidResolvedTargetError):
        asyncio.run(validate_remediation_preflight(_make_step(), catalog, resolver))


@pytest.mark.parametrize(
    "error_type",
    [
        TargetNotFoundError,
        AmbiguousTargetError,
        TargetSourceUnavailableError,
    ],
)
def test_preflight_propagates_target_resolution_errors(
    error_type: type[TargetResolutionError],
) -> None:
    catalog = ActionCatalog(definitions=(_make_action_definition(),))
    expected_error = error_type("Target resolution failed.")
    resolver: TargetResolver = FailingTargetResolver(expected_error)

    with pytest.raises(error_type) as captured:
        asyncio.run(validate_remediation_preflight(_make_step(), catalog, resolver))

    assert captured.value is expected_error


def test_preflight_propagates_unexpected_resolver_error() -> None:
    catalog = ActionCatalog(definitions=(_make_action_definition(),))
    expected_error = RuntimeError("Unexpected inventory failure.")
    resolver: TargetResolver = FailingTargetResolver(expected_error)

    with pytest.raises(RuntimeError) as captured:
        asyncio.run(validate_remediation_preflight(_make_step(), catalog, resolver))

    assert captured.value is expected_error


def test_preflight_does_not_modify_remediation_step() -> None:
    catalog = ActionCatalog(definitions=(_make_action_definition(),))
    resolver: TargetResolver = RecordingTargetResolver(_make_resolved_target())
    step = _make_step()
    original_step_id = step.step_id
    original_parameters = dict(step.parameters)

    asyncio.run(validate_remediation_preflight(step, catalog, resolver))

    assert step.step_id == original_step_id
    assert step.action_name == "restart_service"
    assert step.target == "payments-api"
    assert step.environment == "incident-lab"
    assert dict(step.parameters) == original_parameters
