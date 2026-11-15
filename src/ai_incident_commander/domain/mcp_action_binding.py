"""Trusted configuration mapping approved remediation actions to MCP tools.

A binding is configuration data, not proof of approval or permission to call MCP.
The execution boundary must obtain actions from the trusted catalog, use a fresh
Guard, verify the durable dispatch and separately enforce resource preconditions.
"""

from collections.abc import Mapping
from dataclasses import dataclass, field
from hashlib import sha256
from json import dumps
from re import fullmatch
from types import MappingProxyType

from ai_incident_commander.domain.action_catalog import (
    ActionCatalog,
    ActionEffect,
    UnknownActionError,
    validate_remediation_step,
)
from ai_incident_commander.domain.remediation import RemediationStep


class McpActionBindingError(ValueError):
    """Base error for rejected MCP action-binding configuration or lookup."""


class McpActionBindingConfigurationError(McpActionBindingError):
    """The trusted MCP allowlist is invalid or inconsistent with the catalog."""


class McpActionBindingNotFoundError(McpActionBindingError):
    """The approved action has no configured mutating MCP tool binding."""


class McpActionNotMutatingError(McpActionBindingError):
    """Only mutating catalog actions may use this execution binding."""


@dataclass(frozen=True, slots=True, kw_only=True)
class TrustedMcpToolBinding:
    """One allowlisted action-to-tool mapping, created by trusted configuration.

    server_id is a configured alias, never a caller-supplied URL or credential.
    The binding must never be accepted from the request as authorization.
    """

    action_name: str
    server_id: str
    tool_name: str

    def __post_init__(self) -> None:
        if (
            type(self.action_name) is not str
            or fullmatch(r"[a-z][a-z0-9_]*", self.action_name) is None
        ):
            raise McpActionBindingConfigurationError("Invalid action name in MCP binding.")
        if (
            type(self.server_id) is not str
            or fullmatch(r"[a-z][a-z0-9_-]*", self.server_id) is None
        ):
            raise McpActionBindingConfigurationError("Invalid MCP server alias.")
        if type(self.tool_name) is not str or fullmatch(r"[a-z][a-z0-9_]*", self.tool_name) is None:
            raise McpActionBindingConfigurationError("Invalid MCP tool name.")


@dataclass(frozen=True, slots=True, kw_only=True)
class TrustedMcpActionBindings:
    """Immutable, fail-closed allowlist aligned with the trusted action catalog.

    binding_version changes when an action-to-server/tool mapping changes.
    It is NOT yet incorporated into approval policy versions or fingerprints;
    that integration is mandatory before an MCP executor can be enabled.
    """

    catalog: ActionCatalog
    bindings: tuple[TrustedMcpToolBinding, ...]
    _by_action: Mapping[str, TrustedMcpToolBinding] = field(
        init=False, repr=False, compare=False, hash=False
    )
    binding_version: str = field(init=False)

    def __post_init__(self) -> None:
        if not isinstance(self.catalog, ActionCatalog):
            raise McpActionBindingConfigurationError(
                "MCP bindings require a trusted action catalog."
            )
        if not isinstance(self.bindings, tuple):
            raise McpActionBindingConfigurationError("MCP bindings must be a tuple.")

        by_action: dict[str, TrustedMcpToolBinding] = {}
        for binding in self.bindings:
            if not isinstance(binding, TrustedMcpToolBinding):
                raise McpActionBindingConfigurationError("Invalid MCP binding entry.")
            if binding.action_name in by_action:
                raise McpActionBindingConfigurationError("Duplicate MCP binding for action.")
            try:
                action = self.catalog.get(binding.action_name)
            except UnknownActionError as exc:
                raise McpActionBindingConfigurationError(
                    "MCP binding refers to an action missing from the trusted catalog."
                ) from exc
            if action.effect is not ActionEffect.MUTATING:
                raise McpActionBindingConfigurationError(
                    "Read-only actions cannot be registered for mutating MCP execution."
                )
            by_action[binding.action_name] = binding

        canonical = sorted(
            (binding.action_name, binding.server_id, binding.tool_name)
            for binding in by_action.values()
        )
        payload = dumps(canonical, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        version = "mcp-bind:v1:" + sha256(payload).hexdigest()
        object.__setattr__(self, "_by_action", MappingProxyType(by_action))
        object.__setattr__(self, "binding_version", version)

    def resolve_for_step(self, *, step: RemediationStep) -> TrustedMcpToolBinding:
        """Validate against catalog and reject unmapped or nonmutating actions.

        Does not run preflight, resolve a target, reserve dispatch or invoke MCP.
        """
        definition = validate_remediation_step(step, self.catalog)
        if definition.effect is not ActionEffect.MUTATING:
            raise McpActionNotMutatingError("Not a mutating remediation action.")
        try:
            return self._by_action[definition.action_name]
        except KeyError as exc:
            raise McpActionBindingNotFoundError("No trusted MCP tool binding for action.") from exc
