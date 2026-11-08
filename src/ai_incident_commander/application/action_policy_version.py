"""Deterministic versions of trusted remediation action policies."""

from hashlib import sha256
from json import dumps

from ai_incident_commander.domain.action_catalog import (
    ActionCatalog,
    ActionParameterDefinition,
)

_POLICY_VERSION_DOMAIN = b"ai-incident-commander:action-policy:v1\x00"


def _serialize_allowed_values(
    parameter: ActionParameterDefinition,
) -> list[str | int | float | bool] | None:
    """Return allowed values in a stable, type-aware order."""
    if parameter.allowed_values is None:
        return None

    return sorted(
        parameter.allowed_values,
        key=lambda value: (
            type(value).__name__,
            dumps(value, ensure_ascii=False, allow_nan=False),
        ),
    )


def create_action_policy_version(catalog: ActionCatalog) -> str:
    """Create a content-based version of the complete trusted catalog."""
    payload = {
        "version": 1,
        "actions": [
            {
                "name": definition.action_name,
                "description": definition.description,
                "effect": definition.effect.value,
                "risk_level": definition.risk_level.value,
                "allowed_environments": sorted(definition.allowed_environments),
                "parameters": [
                    {
                        "name": parameter.name,
                        "value_type": parameter.value_type.value,
                        "required": parameter.required,
                        "nullable": parameter.nullable,
                        "non_blank": parameter.non_blank,
                        "minimum": parameter.minimum,
                        "maximum": parameter.maximum,
                        "allowed_values": _serialize_allowed_values(parameter),
                    }
                    for parameter in sorted(
                        definition.parameters,
                        key=lambda item: item.name,
                    )
                ],
            }
            for definition in sorted(
                catalog.definitions,
                key=lambda item: item.action_name,
            )
        ],
    }

    canonical_bytes = dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")

    digest = sha256(_POLICY_VERSION_DOMAIN + canonical_bytes).hexdigest()

    return f"apv:v1:{digest}"
