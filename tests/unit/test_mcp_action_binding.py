"""Unit tests for fail-closed, immutable MCP action-to-tool configuration."""

from dataclasses import FrozenInstanceError, replace
from uuid import uuid4

import pytest

from ai_incident_commander.domain.action_catalog import (
    ActionCatalog,
    ActionDefinition,
    ActionEffect,
    ActionEnvironmentNotAllowedError,
    ActionParameterValidationError,
    ActionRiskMismatchError,
    UnknownActionError,
)
from ai_incident_commander.domain.mcp_action_binding import (
    McpActionBindingConfigurationError,
    McpActionBindingNotFoundError,
    McpActionNotMutatingError,
    TrustedMcpActionBindings,
    TrustedMcpToolBinding,
)
from ai_incident_commander.domain.remediation import (
    RemediationRiskLevel,
    RemediationStep,
)


def _catalog() -> ActionCatalog:
    return ActionCatalog(
        definitions=(
            ActionDefinition(
                action_name="restart_service",
                description="Restart a service.",
                effect=ActionEffect.MUTATING,
                risk_level=RemediationRiskLevel.HIGH,
                allowed_environments=("incident-lab",),
            ),
            ActionDefinition(
                action_name="roll_back",
                description="Roll back a deployment.",
                effect=ActionEffect.MUTATING,
                risk_level=RemediationRiskLevel.HIGH,
                allowed_environments=("incident-lab",),
            ),
            ActionDefinition(
                action_name="inspect_service",
                description="Inspect a service.",
                effect=ActionEffect.READ_ONLY,
                risk_level=RemediationRiskLevel.LOW,
                allowed_environments=("incident-lab",),
            ),
        )
    )


def _binding(
    action_name: str = "restart_service",
    server_id: str = "deployment-mcp",
    tool_name: str = "restart_service",
) -> TrustedMcpToolBinding:
    return TrustedMcpToolBinding(action_name=action_name, server_id=server_id, tool_name=tool_name)


def _step(
    action_name: str = "restart_service",
    risk_level: RemediationRiskLevel = RemediationRiskLevel.HIGH,
    environment: str = "incident-lab",
    parameters: dict[str, str] | None = None,
) -> RemediationStep:
    return RemediationStep(
        plan_id=uuid4(),
        position=1,
        action_name=action_name,
        target="payments-api",
        environment=environment,
        risk_level=risk_level,
        parameters=parameters or {},
    )


def test_resolves_only_trusted_mapping_for_valid_mutation() -> None:
    binding = _binding(server_id="deployment-mcp", tool_name="restart_service")
    registry = TrustedMcpActionBindings(catalog=_catalog(), bindings=(binding,))
    assert registry.resolve_for_step(step=_step()) is binding
    assert not hasattr(binding, "resource_id")  # Target identity is not a config input.


def test_binding_and_registry_are_immutable() -> None:
    binding = _binding()
    registry = TrustedMcpActionBindings(catalog=_catalog(), bindings=(binding,))
    with pytest.raises(FrozenInstanceError):
        binding.server_id = "other-mcp"  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        registry.binding_version = "tampered"  # type: ignore[misc]


@pytest.mark.parametrize(
    "field_name,bad_value",
    [
        ("action_name", "restart-service"),
        ("server_id", "https://attacker.invalid"),
        ("tool_name", "../../../shell"),
        ("tool_name", ""),
    ],
)
def test_rejects_invalid_binding_identifiers(field_name: str, bad_value: str) -> None:
    with pytest.raises(McpActionBindingConfigurationError):
        replace(_binding(), **{field_name: bad_value})


def test_rejects_duplicate_action_mapping() -> None:
    with pytest.raises(McpActionBindingConfigurationError, match="Duplicate"):
        TrustedMcpActionBindings(catalog=_catalog(), bindings=(_binding(), _binding()))


def test_rejects_binding_for_missing_catalog_action() -> None:
    with pytest.raises(McpActionBindingConfigurationError, match="missing"):
        TrustedMcpActionBindings(catalog=_catalog(), bindings=(_binding("delete_database"),))


def test_rejects_binding_for_read_only_catalog_action() -> None:
    with pytest.raises(McpActionBindingConfigurationError, match="Read-only"):
        TrustedMcpActionBindings(catalog=_catalog(), bindings=(_binding("inspect_service"),))


def test_unbound_mutating_action_is_denied() -> None:
    registry = TrustedMcpActionBindings(catalog=_catalog(), bindings=())
    with pytest.raises(McpActionBindingNotFoundError):
        registry.resolve_for_step(step=_step())


def test_other_mutating_action_cannot_reuse_another_binding() -> None:
    registry = TrustedMcpActionBindings(catalog=_catalog(), bindings=(_binding(),))
    with pytest.raises(McpActionBindingNotFoundError):
        registry.resolve_for_step(step=_step(action_name="roll_back"))


def test_read_only_step_is_not_executable_even_if_valid_in_catalog() -> None:
    registry = TrustedMcpActionBindings(catalog=_catalog(), bindings=(_binding(),))
    with pytest.raises(McpActionNotMutatingError):
        registry.resolve_for_step(
            step=_step(action_name="inspect_service", risk_level=RemediationRiskLevel.LOW)
        )


@pytest.mark.parametrize(
    "step,expected",
    [
        (_step(risk_level=RemediationRiskLevel.LOW), ActionRiskMismatchError),
        (_step(environment="production"), ActionEnvironmentNotAllowedError),
        (
            _step(parameters={"shell_command": "forbidden"}),
            ActionParameterValidationError,
        ),
        (_step(action_name="unknown_action"), UnknownActionError),
    ],
)
def test_step_must_pass_trusted_catalog_validation(
    step: RemediationStep, expected: type[Exception]
) -> None:
    registry = TrustedMcpActionBindings(catalog=_catalog(), bindings=(_binding(),))
    with pytest.raises(expected):
        registry.resolve_for_step(step=step)


def test_binding_version_ignores_configuration_order() -> None:
    first = _binding()
    second = _binding("roll_back", "deployment-mcp", "roll_back")
    a = TrustedMcpActionBindings(catalog=_catalog(), bindings=(first, second))
    b = TrustedMcpActionBindings(catalog=_catalog(), bindings=(second, first))
    assert a.binding_version == b.binding_version
    assert a.binding_version.startswith("mcp-bind:v1:")


@pytest.mark.parametrize(
    "changed",
    [
        _binding(server_id="other-deployment-mcp"),
        _binding(tool_name="restart_service_v2"),
    ],
)
def test_binding_version_changes_when_tool_or_server_changes(
    changed: TrustedMcpToolBinding,
) -> None:
    original = TrustedMcpActionBindings(catalog=_catalog(), bindings=(_binding(),))
    updated = TrustedMcpActionBindings(catalog=_catalog(), bindings=(changed,))
    assert original.binding_version != updated.binding_version
