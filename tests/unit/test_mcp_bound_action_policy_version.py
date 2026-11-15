"""Contract tests for proposed MCP-bound approval policy version v2.

These tests do not enable v2 approvals or MCP execution; the existing approval
and claim schemas still accept apv:v1 only.
"""

from dataclasses import replace
from re import fullmatch

import pytest

from ai_incident_commander.application.action_policy_version import (
    create_action_policy_version,
    create_mcp_bound_action_policy_version,
)
from ai_incident_commander.domain.action_catalog import (
    ActionCatalog,
    ActionDefinition,
    ActionEffect,
)
from ai_incident_commander.domain.mcp_action_binding import (
    TrustedMcpActionBindings,
    TrustedMcpToolBinding,
)
from ai_incident_commander.domain.remediation import RemediationRiskLevel


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
                action_name="scale_service",
                description="Scale a service.",
                effect=ActionEffect.MUTATING,
                risk_level=RemediationRiskLevel.HIGH,
                allowed_environments=("incident-lab",),
            ),
        )
    )


def _binding(
    action_name: str, *, server_id: str = "deployment-mcp", tool_name: str | None = None
) -> TrustedMcpToolBinding:
    return TrustedMcpToolBinding(
        action_name=action_name,
        server_id=server_id,
        tool_name=action_name if tool_name is None else tool_name,
    )


def _version(catalog: ActionCatalog, *bindings: TrustedMcpToolBinding) -> str:
    registry = TrustedMcpActionBindings(catalog=catalog, bindings=tuple(bindings))
    return create_mcp_bound_action_policy_version(catalog=catalog, bindings=registry)


def test_mcp_bound_policy_uses_distinct_versioned_hash() -> None:
    catalog = _catalog()
    version = _version(catalog, _binding("restart_service"))
    assert fullmatch(r"apv:v2:[0-9a-f]{64}", version) is not None
    assert create_action_policy_version(catalog).startswith("apv:v1:")


def test_mcp_bound_policy_is_deterministic() -> None:
    catalog = _catalog()
    assert _version(catalog, _binding("restart_service")) == _version(
        catalog, _binding("restart_service")
    )


def test_mcp_bound_policy_changes_when_server_changes() -> None:
    catalog = _catalog()
    first = _version(catalog, _binding("restart_service"))
    changed = _version(catalog, _binding("restart_service", server_id="new-deployment-mcp"))
    assert first != changed


def test_mcp_bound_policy_changes_when_tool_changes() -> None:
    catalog = _catalog()
    first = _version(catalog, _binding("restart_service"))
    changed = _version(catalog, _binding("restart_service", tool_name="restart_deployment"))
    assert first != changed


def test_mcp_bound_policy_changes_when_mapping_is_added() -> None:
    catalog = _catalog()
    first = _version(catalog, _binding("restart_service"))
    changed = _version(catalog, _binding("restart_service"), _binding("scale_service"))
    assert first != changed


def test_mcp_bound_policy_changes_when_catalog_changes() -> None:
    catalog = _catalog()
    altered = ActionCatalog(
        definitions=(
            replace(catalog.definitions[0], description="Safer restart."),
            catalog.definitions[1],
        )
    )
    assert _version(catalog, _binding("restart_service")) != _version(
        altered, _binding("restart_service")
    )


def test_mcp_bound_policy_ignores_registry_order() -> None:
    catalog = _catalog()
    first = _version(catalog, _binding("restart_service"), _binding("scale_service"))
    reversed_order = _version(catalog, _binding("scale_service"), _binding("restart_service"))
    assert first == reversed_order


def test_mcp_bound_policy_rejects_mismatched_catalog() -> None:
    catalog = _catalog()
    altered = ActionCatalog(
        definitions=(
            replace(catalog.definitions[0], description="Different."),
            catalog.definitions[1],
        )
    )
    registry = TrustedMcpActionBindings(catalog=catalog, bindings=(_binding("restart_service"),))
    with pytest.raises(ValueError, match="different action catalog"):
        create_mcp_bound_action_policy_version(catalog=altered, bindings=registry)


def test_mcp_bound_policy_rejects_missing_bindings() -> None:
    with pytest.raises(TypeError, match="requires trusted MCP action bindings"):
        create_mcp_bound_action_policy_version(  # type: ignore[arg-type]
            catalog=_catalog(), bindings=None
        )
