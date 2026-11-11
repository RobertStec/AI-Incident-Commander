"""Unit tests for deterministic trusted action catalog policy versions."""

from dataclasses import replace
from re import fullmatch

import pytest

from ai_incident_commander.application.action_policy_version import (
    create_action_policy_version,
)
from ai_incident_commander.domain.action_catalog import (
    ActionCatalog,
    ActionDefinition,
    ActionEffect,
    ActionParameterDefinition,
    ActionParameterType,
)
from ai_incident_commander.domain.remediation import RemediationRiskLevel


def _numeric_parameter() -> ActionParameterDefinition:
    return ActionParameterDefinition(
        name="timeout_seconds",
        value_type=ActionParameterType.NUMBER,
        minimum=1,
        maximum=300,
        allowed_values=(30, 60),
    )


def _strategy_parameter() -> ActionParameterDefinition:
    return ActionParameterDefinition(
        name="strategy",
        value_type=ActionParameterType.STRING,
        required=False,
        non_blank=True,
        allowed_values=("rolling", "immediate"),
    )


def _definition() -> ActionDefinition:
    return ActionDefinition(
        action_name="restart_service",
        description="Restart an affected service.",
        effect=ActionEffect.MUTATING,
        risk_level=RemediationRiskLevel.HIGH,
        allowed_environments=("incident-lab", "staging"),
        parameters=(_numeric_parameter(), _strategy_parameter()),
    )


def _version(definition: ActionDefinition) -> str:
    return create_action_policy_version(ActionCatalog(definitions=(definition,)))


def test_policy_version_has_versioned_sha256_format() -> None:
    assert fullmatch(r"apv:v1:[0-9a-f]{64}", _version(_definition())) is not None


def test_policy_version_is_deterministic() -> None:
    catalog = ActionCatalog(definitions=(_definition(),))
    assert create_action_policy_version(catalog) == create_action_policy_version(catalog)


def test_policy_version_supports_empty_catalog() -> None:
    result = create_action_policy_version(ActionCatalog(definitions=()))
    assert fullmatch(r"apv:v1:[0-9a-f]{64}", result) is not None
    assert result == create_action_policy_version(ActionCatalog(definitions=()))


def test_policy_version_ignores_action_registration_order() -> None:
    first = _definition()
    second = replace(first, action_name="inspect_service", effect=ActionEffect.READ_ONLY)
    assert create_action_policy_version(
        ActionCatalog(definitions=(first, second))
    ) == create_action_policy_version(ActionCatalog(definitions=(second, first)))


def test_policy_version_ignores_parameter_definition_order() -> None:
    original = _definition()
    changed = replace(original, parameters=tuple(reversed(original.parameters)))
    assert _version(original) == _version(changed)


def test_policy_version_ignores_allowed_environment_order() -> None:
    original = _definition()
    changed = replace(original, allowed_environments=("staging", "incident-lab"))
    assert _version(original) == _version(changed)


def test_policy_version_ignores_allowed_value_order() -> None:
    original = _definition()
    changed = replace(
        original,
        parameters=(
            replace(_numeric_parameter(), allowed_values=(60, 30)),
            replace(_strategy_parameter(), allowed_values=("immediate", "rolling")),
        ),
    )
    assert _version(original) == _version(changed)


def test_policy_version_distinguishes_integer_and_float_allowed_values() -> None:
    original = _definition()
    integer = replace(
        original,
        parameters=(replace(_numeric_parameter(), allowed_values=(1,)), _strategy_parameter()),
    )
    floating = replace(
        original,
        parameters=(replace(_numeric_parameter(), allowed_values=(1.0,)), _strategy_parameter()),
    )
    assert _version(integer) != _version(floating)


def test_policy_version_changes_with_action_name() -> None:
    original = _definition()
    assert _version(original) != _version(replace(original, action_name="stop_service"))


def test_policy_version_changes_with_description() -> None:
    original = _definition()
    assert _version(original) != _version(replace(original, description="Restart service safely."))


def test_policy_version_changes_with_effect() -> None:
    original = _definition()
    assert _version(original) != _version(replace(original, effect=ActionEffect.READ_ONLY))


def test_policy_version_changes_with_risk_level() -> None:
    original = _definition()
    assert _version(original) != _version(replace(original, risk_level=RemediationRiskLevel.MEDIUM))


def test_policy_version_changes_with_allowed_environment_membership() -> None:
    original = _definition()
    assert _version(original) != _version(replace(original, allowed_environments=("incident-lab",)))


def test_policy_version_changes_when_an_action_is_added() -> None:
    original = _definition()
    changed = replace(original, action_name="inspect_service")
    assert _version(original) != create_action_policy_version(
        ActionCatalog(definitions=(original, changed))
    )


def test_policy_version_changes_with_parameter_name() -> None:
    original = _definition()
    changed = replace(
        original,
        parameters=(replace(_numeric_parameter(), name="delay_seconds"), _strategy_parameter()),
    )
    assert _version(original) != _version(changed)


def test_policy_version_changes_with_parameter_type() -> None:
    original = _definition()
    changed = replace(
        original,
        parameters=(
            replace(_numeric_parameter(), value_type=ActionParameterType.INTEGER),
            _strategy_parameter(),
        ),
    )
    assert _version(original) != _version(changed)


def test_policy_version_changes_with_required() -> None:
    original = _definition()
    changed = replace(
        original,
        parameters=(replace(_numeric_parameter(), required=False), _strategy_parameter()),
    )
    assert _version(original) != _version(changed)


def test_policy_version_changes_with_nullable() -> None:
    original = _definition()
    changed = replace(
        original,
        parameters=(replace(_numeric_parameter(), nullable=True), _strategy_parameter()),
    )
    assert _version(original) != _version(changed)


def test_policy_version_changes_with_non_blank() -> None:
    original = _definition()
    changed = replace(
        original,
        parameters=(_numeric_parameter(), replace(_strategy_parameter(), non_blank=False)),
    )
    assert _version(original) != _version(changed)


@pytest.mark.parametrize(
    ("minimum", "maximum"),
    [(2, 300), (1, 200)],
)
def test_policy_version_changes_with_numeric_bounds(minimum: int, maximum: int) -> None:
    original = _definition()
    changed = replace(
        original,
        parameters=(
            replace(_numeric_parameter(), minimum=minimum, maximum=maximum),
            _strategy_parameter(),
        ),
    )
    assert _version(original) != _version(changed)


def test_policy_version_changes_with_allowed_value_membership() -> None:
    original = _definition()
    changed = replace(
        original,
        parameters=(replace(_numeric_parameter(), allowed_values=(30,)), _strategy_parameter()),
    )
    assert _version(original) != _version(changed)


def test_policy_version_distinguishes_absent_and_present_allowed_values() -> None:
    original = _definition()
    changed = replace(
        original,
        parameters=(replace(_numeric_parameter(), allowed_values=None), _strategy_parameter()),
    )
    assert _version(original) != _version(changed)


def test_policy_version_supports_unicode_description() -> None:
    original = replace(_definition(), description="Bezpieczny restart usługi Żółć.")
    assert _version(original) != _version(_definition())
    assert _version(original) == _version(original)


def test_policy_version_does_not_modify_catalog() -> None:
    original = _definition()
    catalog = ActionCatalog(definitions=(original,))
    parameters = original.parameters
    environments = original.allowed_environments
    allowed_values = parameters[0].allowed_values
    create_action_policy_version(catalog)
    assert catalog.definitions == (original,)
    assert original.parameters is parameters
    assert original.allowed_environments is environments
    assert original.parameters[0].allowed_values is allowed_values
