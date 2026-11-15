"""Fail-closed tests for explicit MCP-bound remediation preflight (apv:v2)."""

import asyncio
from dataclasses import replace
from re import fullmatch
from uuid import uuid4

import pytest

from ai_incident_commander.application.action_policy_version import (
    create_action_policy_version,
    create_mcp_bound_action_policy_version,
)
from ai_incident_commander.application.remediation_preflight import (
    RemediationPreflightResult,
    validate_mcp_bound_remediation_preflight,
    validate_remediation_preflight,
)
from ai_incident_commander.application.target_verification import TargetIdentityMismatchError
from ai_incident_commander.domain.action_catalog import (
    ActionCatalog,
    ActionDefinition,
    ActionEffect,
    ActionEnvironmentNotAllowedError,
    ActionRiskMismatchError,
    UnknownActionError,
)
from ai_incident_commander.domain.mcp_action_binding import (
    McpActionBindingNotFoundError,
    McpActionNotMutatingError,
    TrustedMcpActionBindings,
    TrustedMcpToolBinding,
)
from ai_incident_commander.domain.remediation import RemediationRiskLevel, RemediationStep
from ai_incident_commander.domain.target_identity import ResolvedTarget


class RecordingResolver:
    def __init__(self, *, target: ResolvedTarget | None = None, error: Exception | None = None):
        self.target = target or ResolvedTarget(
            target="payments-api",
            resource_id="service-123",
            environment="incident-lab",
            source="service-inventory",
        )
        self.error = error
        self.requests: list[tuple[str, str]] = []

    async def resolve(self, *, target: str, environment: str) -> ResolvedTarget:
        self.requests.append((target, environment))
        if self.error is not None:
            raise self.error
        return self.target


def _catalog(*, effect: ActionEffect = ActionEffect.MUTATING) -> ActionCatalog:
    return ActionCatalog(
        definitions=(
            ActionDefinition(
                action_name="restart_service",
                description="Restart an affected service.",
                effect=effect,
                risk_level=RemediationRiskLevel.HIGH,
                allowed_environments=("incident-lab",),
            ),
        )
    )


def _step() -> RemediationStep:
    return RemediationStep(
        plan_id=uuid4(),
        action_name="restart_service",
        target="payments-api",
        environment="incident-lab",
        position=1,
        risk_level=RemediationRiskLevel.HIGH,
    )


def _bindings(
    catalog: ActionCatalog,
    *,
    server_id: str = "deployment-mcp",
    tool_name: str = "restart_service",
    mapped: bool = True,
) -> TrustedMcpActionBindings:
    return TrustedMcpActionBindings(
        catalog=catalog,
        bindings=(
            (
                TrustedMcpToolBinding(
                    action_name="restart_service",
                    server_id=server_id,
                    tool_name=tool_name,
                ),
            )
            if mapped
            else ()
        ),
    )


def _run(
    step: RemediationStep,
    catalog: ActionCatalog,
    resolver: RecordingResolver,
    bindings: TrustedMcpActionBindings,
) -> RemediationPreflightResult:
    return asyncio.run(
        validate_mcp_bound_remediation_preflight(step, catalog, resolver, bindings=bindings)
    )


def test_mcp_bound_preflight_yields_v2_scope_and_same_target() -> None:
    catalog = _catalog()
    step = _step()
    resolver = RecordingResolver()
    bindings = _bindings(catalog)

    result = _run(step, catalog, resolver, bindings)

    assert result.action is catalog.definitions[0]
    assert result.target is resolver.target
    assert result.step_snapshot is step
    assert result.policy_version == create_mcp_bound_action_policy_version(
        catalog=catalog, bindings=bindings
    )
    assert result.policy_version is not None
    assert fullmatch(r"apv:v2:[0-9a-f]{64}", result.policy_version)
    assert resolver.requests == [("payments-api", "incident-lab")]


def test_legacy_preflight_remains_catalog_only_for_compatibility() -> None:
    catalog = _catalog()
    resolver = RecordingResolver()
    result = asyncio.run(validate_remediation_preflight(_step(), catalog, resolver))
    assert result.policy_version == create_action_policy_version(catalog)
    assert result.policy_version is not None
    assert result.policy_version.startswith("apv:v1:")


@pytest.mark.parametrize(
    "changed_routing",
    [
        {"server_id": "alternate-mcp"},
        {"tool_name": "force_restart_service"},
    ],
)
def test_mcp_bound_policy_changes_when_routing_changes(changed_routing: dict[str, str]) -> None:
    catalog = _catalog()
    step = _step()
    first = _run(step, catalog, RecordingResolver(), _bindings(catalog))
    changed = _run(step, catalog, RecordingResolver(), _bindings(catalog, **changed_routing))
    assert first.policy_version != changed.policy_version
    assert changed.policy_version is not None
    assert changed.policy_version.startswith("apv:v2:")


def test_mcp_bound_policy_is_stable_for_equivalent_configuration() -> None:
    left_catalog = _catalog()
    right_catalog = _catalog()
    step = _step()
    left = _run(step, left_catalog, RecordingResolver(), _bindings(left_catalog))
    right = _run(step, right_catalog, RecordingResolver(), _bindings(right_catalog))
    assert left.policy_version == right.policy_version


def test_mcp_bound_preflight_does_not_accept_missing_bindings() -> None:
    catalog = _catalog()
    resolver = RecordingResolver()
    with pytest.raises(TypeError):
        asyncio.run(
            validate_mcp_bound_remediation_preflight(  # type: ignore[call-arg]
                _step(), catalog, resolver
            )
        )
    assert resolver.requests == []


def test_mcp_bound_preflight_rejects_forged_binding_object_before_resolution() -> None:
    catalog = _catalog()
    resolver = RecordingResolver()
    with pytest.raises(TypeError, match="trusted MCP action bindings"):
        asyncio.run(
            validate_mcp_bound_remediation_preflight(
                _step(),
                catalog,
                resolver,
                bindings=object(),  # type: ignore[arg-type]
            )
        )
    assert resolver.requests == []


def test_mcp_bound_preflight_rejects_registry_for_different_catalog() -> None:
    catalog = _catalog()
    changed_catalog = ActionCatalog(
        definitions=(replace(catalog.definitions[0], description="Updated policy."),)
    )
    resolver = RecordingResolver()
    with pytest.raises(ValueError, match="different action catalog"):
        _run(_step(), changed_catalog, resolver, _bindings(catalog))
    assert resolver.requests == []


def test_mcp_bound_preflight_rejects_missing_tool_binding() -> None:
    catalog = _catalog()
    resolver = RecordingResolver()
    with pytest.raises(McpActionBindingNotFoundError):
        _run(_step(), catalog, resolver, _bindings(catalog, mapped=False))
    assert resolver.requests == []


def test_mcp_bound_preflight_rejects_read_only_action() -> None:
    catalog = _catalog(effect=ActionEffect.READ_ONLY)
    resolver = RecordingResolver()
    with pytest.raises(McpActionNotMutatingError):
        _run(_step(), catalog, resolver, _bindings(catalog, mapped=False))
    assert resolver.requests == []


@pytest.mark.parametrize(
    ("step_change", "expected_error"),
    [
        ({"action_name": "not_in_catalog"}, UnknownActionError),
        ({"risk_level": RemediationRiskLevel.LOW}, ActionRiskMismatchError),
        ({"environment": "production"}, ActionEnvironmentNotAllowedError),
    ],
)
def test_mcp_bound_preflight_rejects_invalid_step_before_resolving(
    step_change: dict[str, object], expected_error: type[Exception]
) -> None:
    catalog = _catalog()
    resolver = RecordingResolver()
    with pytest.raises(expected_error):
        _run(replace(_step(), **step_change), catalog, resolver, _bindings(catalog))
    assert resolver.requests == []


def test_mcp_bound_preflight_rejects_mismatched_resolved_target() -> None:
    catalog = _catalog()
    resolver = RecordingResolver(
        target=ResolvedTarget(
            target="other-api",
            resource_id="service-123",
            environment="incident-lab",
            source="service-inventory",
        )
    )
    with pytest.raises(TargetIdentityMismatchError):
        _run(_step(), catalog, resolver, _bindings(catalog))
    assert resolver.requests == [("payments-api", "incident-lab")]


def test_mcp_bound_preflight_propagates_resolver_failures() -> None:
    catalog = _catalog()
    error = RuntimeError("inventory unavailable")
    resolver = RecordingResolver(error=error)
    with pytest.raises(RuntimeError) as caught:
        _run(_step(), catalog, resolver, _bindings(catalog))
    assert caught.value is error
    assert resolver.requests == [("payments-api", "incident-lab")]
