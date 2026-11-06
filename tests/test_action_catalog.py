"""Unit tests for trusted remediation action definitions."""

from collections.abc import MutableMapping, MutableSequence
from dataclasses import FrozenInstanceError
from typing import cast
from uuid import uuid4

import pytest

from ai_incident_commander.domain.action_catalog import (
    ActionCatalog,
    ActionDefinition,
    ActionEffect,
    ActionParameterDefinition,
    ActionParameterType,
    ActionParameterValidationError,
    ActionRiskMismatchError,
    UnknownActionError,
    validate_remediation_step,
)
from ai_incident_commander.domain.remediation import (
    RemediationParameterValue,
    RemediationRiskLevel,
    RemediationStep,
)


def test_action_effect_values_match_domain_contract() -> None:
    assert {effect.value for effect in ActionEffect} == {
        "read_only",
        "mutating",
    }


@pytest.mark.parametrize(
    ("effect", "risk_level"),
    [
        (ActionEffect.READ_ONLY, RemediationRiskLevel.LOW),
        (ActionEffect.MUTATING, RemediationRiskLevel.LOW),
        (ActionEffect.MUTATING, RemediationRiskLevel.HIGH),
    ],
)
def test_action_definition_accepts_valid_classifications(
    effect: ActionEffect,
    risk_level: RemediationRiskLevel,
) -> None:
    definition = ActionDefinition(
        action_name="restart_service",
        description="Restart a service in an authorized environment.",
        effect=effect,
        risk_level=risk_level,
    )

    assert definition.action_name == "restart_service"
    assert definition.description == ("Restart a service in an authorized environment.")
    assert definition.effect is effect
    assert definition.risk_level is risk_level


@pytest.mark.parametrize(
    "action_name",
    ["a", "inspect_service", "rollback_release2"],
)
def test_action_definition_accepts_valid_names(
    action_name: str,
) -> None:
    definition = ActionDefinition(
        action_name=action_name,
        description="Test action.",
        effect=ActionEffect.READ_ONLY,
        risk_level=RemediationRiskLevel.LOW,
    )

    assert definition.action_name == action_name


@pytest.mark.parametrize(
    "action_name",
    [
        "",
        " ",
        "Restart_service",
        "restart-service",
        "1restart",
        "restart service",
    ],
)
def test_action_definition_rejects_invalid_names(
    action_name: str,
) -> None:
    with pytest.raises(
        ValueError,
        match="name must use lowercase snake_case",
    ):
        ActionDefinition(
            action_name=action_name,
            description="Test action.",
            effect=ActionEffect.READ_ONLY,
            risk_level=RemediationRiskLevel.LOW,
        )


def test_action_definition_rejects_non_string_name() -> None:
    with pytest.raises(
        ValueError,
        match="name must use lowercase snake_case",
    ):
        ActionDefinition(
            action_name=cast(str, 123),
            description="Test action.",
            effect=ActionEffect.READ_ONLY,
            risk_level=RemediationRiskLevel.LOW,
        )


@pytest.mark.parametrize("description", ["", " ", "\t\n"])
def test_action_definition_rejects_empty_description(
    description: str,
) -> None:
    with pytest.raises(
        ValueError,
        match="description must not be empty",
    ):
        ActionDefinition(
            action_name="inspect_service",
            description=description,
            effect=ActionEffect.READ_ONLY,
            risk_level=RemediationRiskLevel.LOW,
        )


def test_action_definition_rejects_invalid_effect() -> None:
    with pytest.raises(
        ValueError,
        match="effect must be a valid ActionEffect",
    ):
        ActionDefinition(
            action_name="restart_service",
            description="Restart the affected service.",
            effect=cast(ActionEffect, "mutating"),
            risk_level=RemediationRiskLevel.MEDIUM,
        )


def test_action_definition_rejects_invalid_risk_level() -> None:
    with pytest.raises(
        ValueError,
        match="risk_level must be a valid RemediationRiskLevel",
    ):
        ActionDefinition(
            action_name="rollback_release",
            description="Rollback a deployment.",
            effect=ActionEffect.MUTATING,
            risk_level=cast(RemediationRiskLevel, "high"),
        )


def test_action_definition_cannot_be_modified_directly() -> None:
    definition = ActionDefinition(
        action_name="inspect_service",
        description="Inspect service health.",
        effect=ActionEffect.READ_ONLY,
        risk_level=RemediationRiskLevel.LOW,
    )

    field_name = "effect"

    with pytest.raises(FrozenInstanceError):
        setattr(
            definition,
            field_name,
            ActionEffect.MUTATING,
        )

    assert definition.effect is ActionEffect.READ_ONLY


def _make_action_definition(
    action_name: str,
    *,
    effect: ActionEffect = ActionEffect.READ_ONLY,
    risk_level: RemediationRiskLevel = RemediationRiskLevel.LOW,
) -> ActionDefinition:
    """Create a valid trusted action definition for catalog tests."""
    return ActionDefinition(
        action_name=action_name,
        description=f"Trusted definition for {action_name}.",
        effect=effect,
        risk_level=risk_level,
    )


def test_action_catalog_returns_registered_definition() -> None:
    definition = _make_action_definition(
        "rollback_release",
        effect=ActionEffect.MUTATING,
        risk_level=RemediationRiskLevel.HIGH,
    )

    catalog = ActionCatalog(definitions=(definition,))

    retrieved = catalog.get("rollback_release")

    assert retrieved is definition
    assert retrieved.effect is ActionEffect.MUTATING
    assert retrieved.risk_level is RemediationRiskLevel.HIGH


def test_action_catalog_supports_multiple_definitions() -> None:
    inspect = _make_action_definition("inspect_service")
    restart = _make_action_definition(
        "restart_service",
        effect=ActionEffect.MUTATING,
        risk_level=RemediationRiskLevel.MEDIUM,
    )
    rollback = _make_action_definition(
        "rollback_release",
        effect=ActionEffect.MUTATING,
        risk_level=RemediationRiskLevel.HIGH,
    )

    catalog = ActionCatalog(
        definitions=(inspect, restart, rollback),
    )

    assert catalog.get("inspect_service") is inspect
    assert catalog.get("restart_service") is restart
    assert catalog.get("rollback_release") is rollback
    assert len(catalog.definitions) == 3


@pytest.mark.parametrize(
    "unknown_name",
    ["restart_service", "execute_arbitrary_command"],
)
def test_action_catalog_rejects_unknown_actions(
    unknown_name: str,
) -> None:
    definition = _make_action_definition("inspect_service")
    catalog = ActionCatalog(definitions=(definition,))

    with pytest.raises(
        UnknownActionError,
        match="is not in the trusted catalog",
    ):
        catalog.get(unknown_name)


def test_empty_action_catalog_denies_all_actions() -> None:
    catalog = ActionCatalog(definitions=())

    assert catalog.definitions == ()

    with pytest.raises(UnknownActionError):
        catalog.get("inspect_service")


def test_action_catalog_rejects_duplicate_action_names() -> None:
    first = _make_action_definition("restart_service")
    second = _make_action_definition(
        "restart_service",
        effect=ActionEffect.MUTATING,
        risk_level=RemediationRiskLevel.HIGH,
    )

    with pytest.raises(
        ValueError,
        match="Duplicate remediation action",
    ):
        ActionCatalog(definitions=(first, second))


def test_action_catalog_rejects_non_tuple_definitions() -> None:
    definition = _make_action_definition("inspect_service")

    invalid_definitions = cast(
        tuple[ActionDefinition, ...],
        [definition],
    )

    with pytest.raises(
        ValueError,
        match="definitions must be a tuple",
    ):
        ActionCatalog(definitions=invalid_definitions)


def test_action_catalog_rejects_invalid_definition_entry() -> None:
    invalid_definitions = cast(
        tuple[ActionDefinition, ...],
        ("not-an-action-definition",),
    )

    with pytest.raises(
        ValueError,
        match="entries must be ActionDefinition instances",
    ):
        ActionCatalog(definitions=invalid_definitions)


def test_action_catalog_lookup_index_is_read_only() -> None:
    definition = _make_action_definition("inspect_service")
    catalog = ActionCatalog(definitions=(definition,))

    mutable_index = cast(
        MutableMapping[str, ActionDefinition],
        catalog._by_name,
    )

    with pytest.raises(TypeError):
        mutable_index["restart_service"] = _make_action_definition(
            "restart_service",
        )

    assert catalog.get("inspect_service") is definition

    with pytest.raises(UnknownActionError):
        catalog.get("restart_service")


def test_action_catalog_definitions_cannot_be_reassigned() -> None:
    definition = _make_action_definition("inspect_service")
    catalog = ActionCatalog(definitions=(definition,))

    field_name = "definitions"

    with pytest.raises(FrozenInstanceError):
        setattr(catalog, field_name, ())

    assert catalog.definitions == (definition,)
    assert catalog.get("inspect_service") is definition


def _make_remediation_step(
    action_name: str,
    risk_level: RemediationRiskLevel,
) -> RemediationStep:
    """Create a proposed remediation step for catalog validation tests."""
    return RemediationStep(
        plan_id=uuid4(),
        position=1,
        action_name=action_name,
        target="payments-api",
        environment="incident-lab",
        risk_level=risk_level,
    )


@pytest.mark.parametrize(
    ("effect", "risk_level"),
    [
        (ActionEffect.READ_ONLY, RemediationRiskLevel.LOW),
        (ActionEffect.MUTATING, RemediationRiskLevel.LOW),
        (ActionEffect.MUTATING, RemediationRiskLevel.HIGH),
    ],
)
def test_validate_remediation_step_returns_trusted_definition(
    effect: ActionEffect,
    risk_level: RemediationRiskLevel,
) -> None:
    definition = _make_action_definition(
        "restart_service",
        effect=effect,
        risk_level=risk_level,
    )
    catalog = ActionCatalog(definitions=(definition,))
    step = _make_remediation_step("restart_service", risk_level)

    validated = validate_remediation_step(step, catalog)

    assert validated is definition
    assert validated.effect is effect
    assert validated.risk_level is risk_level


@pytest.mark.parametrize(
    ("trusted_risk", "declared_risk"),
    [
        (RemediationRiskLevel.HIGH, RemediationRiskLevel.LOW),
        (RemediationRiskLevel.LOW, RemediationRiskLevel.HIGH),
    ],
)
def test_validate_remediation_step_rejects_risk_mismatch(
    trusted_risk: RemediationRiskLevel,
    declared_risk: RemediationRiskLevel,
) -> None:
    definition = _make_action_definition(
        "rollback_release",
        effect=ActionEffect.MUTATING,
        risk_level=trusted_risk,
    )
    catalog = ActionCatalog(definitions=(definition,))
    step = _make_remediation_step("rollback_release", declared_risk)

    with pytest.raises(
        ActionRiskMismatchError,
        match="does not match the trusted action definition",
    ):
        validate_remediation_step(step, catalog)

    assert step.risk_level is declared_risk
    assert definition.risk_level is trusted_risk


def test_validate_remediation_step_rejects_unknown_action() -> None:
    definition = _make_action_definition("inspect_service")
    catalog = ActionCatalog(definitions=(definition,))

    step = _make_remediation_step(
        "execute_arbitrary_command",
        RemediationRiskLevel.LOW,
    )

    with pytest.raises(
        UnknownActionError,
        match="is not in the trusted catalog",
    ):
        validate_remediation_step(step, catalog)


def test_validate_remediation_step_rejects_empty_catalog() -> None:
    catalog = ActionCatalog(definitions=())

    step = _make_remediation_step(
        "inspect_service",
        RemediationRiskLevel.LOW,
    )

    with pytest.raises(UnknownActionError):
        validate_remediation_step(step, catalog)


def test_validate_remediation_step_does_not_modify_step() -> None:
    definition = _make_action_definition(
        "restart_service",
        effect=ActionEffect.MUTATING,
        risk_level=RemediationRiskLevel.MEDIUM,
    )
    catalog = ActionCatalog(definitions=(definition,))

    step = _make_remediation_step(
        "restart_service",
        RemediationRiskLevel.MEDIUM,
    )

    original_step_id = step.step_id
    original_plan_id = step.plan_id
    original_risk = step.risk_level

    validate_remediation_step(step, catalog)

    assert step.step_id == original_step_id
    assert step.plan_id == original_plan_id
    assert step.action_name == "restart_service"
    assert step.risk_level is original_risk


def test_action_parameter_types_match_domain_contract() -> None:
    assert {value_type.value for value_type in ActionParameterType} == {
        "string",
        "integer",
        "number",
        "boolean",
    }


@pytest.mark.parametrize("value_type", list(ActionParameterType))
def test_action_parameter_definition_accepts_supported_types(
    value_type: ActionParameterType,
) -> None:
    parameter = ActionParameterDefinition(
        name="test_parameter",
        value_type=value_type,
    )

    assert parameter.name == "test_parameter"
    assert parameter.value_type is value_type


def test_action_parameter_definition_has_expected_defaults() -> None:
    parameter = ActionParameterDefinition(
        name="release_id",
        value_type=ActionParameterType.STRING,
    )

    assert parameter.name == "release_id"
    assert parameter.value_type is ActionParameterType.STRING
    assert parameter.required is True
    assert parameter.nullable is False


@pytest.mark.parametrize(
    ("required", "nullable"),
    [
        (True, True),
        (True, False),
        (False, True),
        (False, False),
    ],
)
def test_action_parameter_required_and_nullable_are_independent(
    required: bool,
    nullable: bool,
) -> None:
    parameter = ActionParameterDefinition(
        name="release_id",
        value_type=ActionParameterType.STRING,
        required=required,
        nullable=nullable,
    )

    assert parameter.required is required
    assert parameter.nullable is nullable


@pytest.mark.parametrize(
    "name",
    ["x", "release_id", "timeout_seconds2"],
)
def test_action_parameter_definition_accepts_valid_names(
    name: str,
) -> None:
    parameter = ActionParameterDefinition(
        name=name,
        value_type=ActionParameterType.STRING,
    )

    assert parameter.name == name


@pytest.mark.parametrize(
    "name",
    [
        "",
        " ",
        "Release_id",
        "release-id",
        "1release",
        "release id",
    ],
)
def test_action_parameter_definition_rejects_invalid_names(
    name: str,
) -> None:
    with pytest.raises(
        ValueError,
        match="name must use lowercase snake_case",
    ):
        ActionParameterDefinition(
            name=name,
            value_type=ActionParameterType.STRING,
        )


def test_action_parameter_definition_rejects_non_string_name() -> None:
    with pytest.raises(
        ValueError,
        match="name must use lowercase snake_case",
    ):
        ActionParameterDefinition(
            name=cast(str, 123),
            value_type=ActionParameterType.STRING,
        )


def test_action_parameter_definition_rejects_invalid_value_type() -> None:
    with pytest.raises(
        ValueError,
        match="value_type must be a valid ActionParameterType",
    ):
        ActionParameterDefinition(
            name="release_id",
            value_type=cast(ActionParameterType, "string"),
        )


@pytest.mark.parametrize("invalid_value", [0, 1])
def test_action_parameter_definition_rejects_non_boolean_required(
    invalid_value: int,
) -> None:
    with pytest.raises(
        ValueError,
        match="required must be a boolean",
    ):
        ActionParameterDefinition(
            name="release_id",
            value_type=ActionParameterType.STRING,
            required=cast(bool, invalid_value),
        )


@pytest.mark.parametrize("invalid_value", [0, 1])
def test_action_parameter_definition_rejects_non_boolean_nullable(
    invalid_value: int,
) -> None:
    with pytest.raises(
        ValueError,
        match="nullable must be a boolean",
    ):
        ActionParameterDefinition(
            name="release_id",
            value_type=ActionParameterType.STRING,
            nullable=cast(bool, invalid_value),
        )


def test_action_parameter_definition_cannot_be_modified_directly() -> None:
    parameter = ActionParameterDefinition(
        name="release_id",
        value_type=ActionParameterType.STRING,
        required=True,
        nullable=False,
    )

    field_name = "required"

    with pytest.raises(FrozenInstanceError):
        setattr(parameter, field_name, False)

    assert parameter.required is True
    assert parameter.nullable is False


def test_action_definition_has_empty_parameter_schema_by_default() -> None:
    definition = ActionDefinition(
        action_name="inspect_service",
        description="Inspect service health.",
        effect=ActionEffect.READ_ONLY,
        risk_level=RemediationRiskLevel.LOW,
    )

    assert definition.parameters == ()


def test_action_definition_accepts_single_parameter() -> None:
    parameter = ActionParameterDefinition(
        name="release_id",
        value_type=ActionParameterType.STRING,
        required=True,
        nullable=False,
    )

    definition = ActionDefinition(
        action_name="rollback_release",
        description="Rollback a deployment.",
        effect=ActionEffect.MUTATING,
        risk_level=RemediationRiskLevel.HIGH,
        parameters=(parameter,),
    )

    assert definition.parameters == (parameter,)
    assert definition.parameters[0] is parameter


def test_action_definition_preserves_parameter_order() -> None:
    release_id = ActionParameterDefinition(
        name="release_id",
        value_type=ActionParameterType.STRING,
    )
    dry_run = ActionParameterDefinition(
        name="dry_run",
        value_type=ActionParameterType.BOOLEAN,
        required=False,
    )

    definition = ActionDefinition(
        action_name="rollback_release",
        description="Rollback a deployment.",
        effect=ActionEffect.MUTATING,
        risk_level=RemediationRiskLevel.HIGH,
        parameters=(release_id, dry_run),
    )

    assert definition.parameters == (release_id, dry_run)
    assert [parameter.name for parameter in definition.parameters] == [
        "release_id",
        "dry_run",
    ]


def test_action_definition_rejects_duplicate_parameter_names() -> None:
    first = ActionParameterDefinition(
        name="release_id",
        value_type=ActionParameterType.STRING,
    )
    second = ActionParameterDefinition(
        name="release_id",
        value_type=ActionParameterType.INTEGER,
    )

    with pytest.raises(
        ValueError,
        match="Duplicate action parameter: release_id",
    ):
        ActionDefinition(
            action_name="rollback_release",
            description="Rollback a deployment.",
            effect=ActionEffect.MUTATING,
            risk_level=RemediationRiskLevel.HIGH,
            parameters=(first, second),
        )


def test_action_definition_rejects_non_tuple_parameters() -> None:
    parameter = ActionParameterDefinition(
        name="release_id",
        value_type=ActionParameterType.STRING,
    )

    invalid_parameters = cast(
        tuple[ActionParameterDefinition, ...],
        [parameter],
    )

    with pytest.raises(
        ValueError,
        match="parameters must be a tuple",
    ):
        ActionDefinition(
            action_name="rollback_release",
            description="Rollback a deployment.",
            effect=ActionEffect.MUTATING,
            risk_level=RemediationRiskLevel.HIGH,
            parameters=invalid_parameters,
        )


def test_action_definition_rejects_invalid_parameter_entry() -> None:
    invalid_parameters = cast(
        tuple[ActionParameterDefinition, ...],
        ("not-a-parameter-definition",),
    )

    with pytest.raises(
        ValueError,
        match="parameters must be ActionParameterDefinition instances",
    ):
        ActionDefinition(
            action_name="rollback_release",
            description="Rollback a deployment.",
            effect=ActionEffect.MUTATING,
            risk_level=RemediationRiskLevel.HIGH,
            parameters=invalid_parameters,
        )


def test_action_definition_parameters_cannot_be_reassigned() -> None:
    parameter = ActionParameterDefinition(
        name="release_id",
        value_type=ActionParameterType.STRING,
    )

    definition = ActionDefinition(
        action_name="rollback_release",
        description="Rollback a deployment.",
        effect=ActionEffect.MUTATING,
        risk_level=RemediationRiskLevel.HIGH,
        parameters=(parameter,),
    )

    field_name = "parameters"

    with pytest.raises(FrozenInstanceError):
        setattr(definition, field_name, ())

    assert definition.parameters == (parameter,)


def test_action_definition_parameter_collection_is_immutable() -> None:
    parameter = ActionParameterDefinition(
        name="release_id",
        value_type=ActionParameterType.STRING,
    )

    definition = ActionDefinition(
        action_name="rollback_release",
        description="Rollback a deployment.",
        effect=ActionEffect.MUTATING,
        risk_level=RemediationRiskLevel.HIGH,
        parameters=(parameter,),
    )

    mutable_view = cast(
        MutableSequence[ActionParameterDefinition],
        definition.parameters,
    )

    replacement = ActionParameterDefinition(
        name="different_parameter",
        value_type=ActionParameterType.INTEGER,
    )

    with pytest.raises(TypeError):
        mutable_view[0] = replacement

    assert definition.parameters == (parameter,)


def _make_parameter_schema_catalog(
    *parameters: ActionParameterDefinition,
) -> tuple[ActionCatalog, ActionDefinition]:
    """Create a trusted catalog with a parameterized action."""
    definition = ActionDefinition(
        action_name="rollback_release",
        description="Rollback a deployment.",
        effect=ActionEffect.MUTATING,
        risk_level=RemediationRiskLevel.HIGH,
        parameters=parameters,
    )
    return ActionCatalog(definitions=(definition,)), definition


def _make_parameterized_step(
    parameters: dict[str, RemediationParameterValue],
) -> RemediationStep:
    """Create a remediation step with proposed action parameters."""
    return RemediationStep(
        plan_id=uuid4(),
        position=1,
        action_name="rollback_release",
        target="payments-api",
        environment="incident-lab",
        risk_level=RemediationRiskLevel.HIGH,
        parameters=parameters,
    )


@pytest.mark.parametrize(
    "supplied_parameters",
    [
        {"release_id": "release-123"},
        {"release_id": "release-123", "dry_run": True},
    ],
)
def test_action_parameter_names_accept_valid_arguments(
    supplied_parameters: dict[str, RemediationParameterValue],
) -> None:
    catalog, definition = _make_parameter_schema_catalog(
        ActionParameterDefinition(
            name="release_id",
            value_type=ActionParameterType.STRING,
        ),
        ActionParameterDefinition(
            name="dry_run",
            value_type=ActionParameterType.BOOLEAN,
            required=False,
        ),
    )
    step = _make_parameterized_step(supplied_parameters)

    assert validate_remediation_step(step, catalog) is definition
    assert dict(step.parameters) == supplied_parameters


def test_action_parameter_names_reject_missing_required_parameter() -> None:
    catalog, _ = _make_parameter_schema_catalog(
        ActionParameterDefinition(
            name="release_id",
            value_type=ActionParameterType.STRING,
        ),
    )
    step = _make_parameterized_step({})

    with pytest.raises(
        ActionParameterValidationError,
        match="is missing required parameters: release_id",
    ):
        validate_remediation_step(step, catalog)


def test_action_parameter_names_sort_missing_parameters() -> None:
    catalog, _ = _make_parameter_schema_catalog(
        ActionParameterDefinition(
            name="zeta_id",
            value_type=ActionParameterType.STRING,
        ),
        ActionParameterDefinition(
            name="alpha_id",
            value_type=ActionParameterType.STRING,
        ),
    )
    step = _make_parameterized_step({})

    with pytest.raises(
        ActionParameterValidationError,
        match="is missing required parameters: alpha_id, zeta_id",
    ):
        validate_remediation_step(step, catalog)


def test_action_parameter_names_reject_unknown_parameter() -> None:
    catalog, _ = _make_parameter_schema_catalog(
        ActionParameterDefinition(
            name="release_id",
            value_type=ActionParameterType.STRING,
        ),
    )
    step = _make_parameterized_step(
        {
            "release_id": "release-123",
            "force": True,
        }
    )

    with pytest.raises(
        ActionParameterValidationError,
        match="contains unknown parameters: force",
    ):
        validate_remediation_step(step, catalog)


def test_action_parameter_names_sort_unknown_parameters() -> None:
    catalog, _ = _make_parameter_schema_catalog(
        ActionParameterDefinition(
            name="release_id",
            value_type=ActionParameterType.STRING,
        ),
    )
    step = _make_parameterized_step(
        {
            "release_id": "release-123",
            "z_extra": True,
            "a_extra": False,
        }
    )

    with pytest.raises(
        ActionParameterValidationError,
        match="contains unknown parameters: a_extra, z_extra",
    ):
        validate_remediation_step(step, catalog)


def test_action_parameter_names_accept_empty_schema_and_arguments() -> None:
    catalog, definition = _make_parameter_schema_catalog()
    step = _make_parameterized_step({})

    assert validate_remediation_step(step, catalog) is definition


def test_action_parameter_names_reject_arguments_for_empty_schema() -> None:
    catalog, _ = _make_parameter_schema_catalog()
    step = _make_parameterized_step({"force": True})

    with pytest.raises(
        ActionParameterValidationError,
        match="contains unknown parameters: force",
    ):
        validate_remediation_step(step, catalog)


def test_action_parameter_names_allow_all_optional_parameters_to_be_absent() -> None:
    catalog, definition = _make_parameter_schema_catalog(
        ActionParameterDefinition(
            name="dry_run",
            value_type=ActionParameterType.BOOLEAN,
            required=False,
        ),
    )
    step = _make_parameterized_step({})

    assert validate_remediation_step(step, catalog) is definition


def test_action_parameter_names_reject_unknown_before_missing_required() -> None:
    catalog, _ = _make_parameter_schema_catalog(
        ActionParameterDefinition(
            name="release_id",
            value_type=ActionParameterType.STRING,
        ),
    )
    step = _make_parameterized_step({"force": True})

    with pytest.raises(
        ActionParameterValidationError,
        match="contains unknown parameters: force",
    ):
        validate_remediation_step(step, catalog)


@pytest.mark.parametrize(
    ("value_type", "value"),
    [
        (ActionParameterType.STRING, "release-123"),
        (ActionParameterType.INTEGER, 15),
        (ActionParameterType.NUMBER, 15),
        (ActionParameterType.NUMBER, 15.5),
        (ActionParameterType.BOOLEAN, True),
        (ActionParameterType.BOOLEAN, False),
    ],
)
def test_action_parameter_values_accept_exact_types(
    value_type: ActionParameterType,
    value: RemediationParameterValue,
) -> None:
    catalog, definition = _make_parameter_schema_catalog(
        ActionParameterDefinition(
            name="argument",
            value_type=value_type,
        ),
    )
    step = _make_parameterized_step({"argument": value})

    assert validate_remediation_step(step, catalog) is definition
    assert step.parameters["argument"] == value


@pytest.mark.parametrize(
    ("value_type", "invalid_value"),
    [
        (ActionParameterType.STRING, 123),
        (ActionParameterType.STRING, True),
        (ActionParameterType.INTEGER, True),
        (ActionParameterType.INTEGER, 15.5),
        (ActionParameterType.INTEGER, "15"),
        (ActionParameterType.NUMBER, False),
        (ActionParameterType.NUMBER, "15"),
        (ActionParameterType.BOOLEAN, 1),
        (ActionParameterType.BOOLEAN, "true"),
    ],
)
def test_action_parameter_values_reject_wrong_types(
    value_type: ActionParameterType,
    invalid_value: RemediationParameterValue,
) -> None:
    catalog, _ = _make_parameter_schema_catalog(
        ActionParameterDefinition(
            name="argument",
            value_type=value_type,
        ),
    )
    step = _make_parameterized_step({"argument": invalid_value})

    with pytest.raises(
        ActionParameterValidationError,
        match=f"parameter 'argument' must have type {value_type.value}",
    ):
        validate_remediation_step(step, catalog)


@pytest.mark.parametrize("value_type", list(ActionParameterType))
def test_action_parameter_values_accept_nullable_none(
    value_type: ActionParameterType,
) -> None:
    catalog, definition = _make_parameter_schema_catalog(
        ActionParameterDefinition(
            name="argument",
            value_type=value_type,
            nullable=True,
        ),
    )
    step = _make_parameterized_step({"argument": None})

    assert validate_remediation_step(step, catalog) is definition
    assert step.parameters["argument"] is None


def test_optional_nullable_parameter_accepts_explicit_none() -> None:
    catalog, definition = _make_parameter_schema_catalog(
        ActionParameterDefinition(
            name="dry_run",
            value_type=ActionParameterType.BOOLEAN,
            required=False,
            nullable=True,
        ),
    )
    step = _make_parameterized_step({"dry_run": None})

    assert validate_remediation_step(step, catalog) is definition


@pytest.mark.parametrize("required", [True, False])
def test_action_parameter_values_reject_non_nullable_none(
    required: bool,
) -> None:
    catalog, _ = _make_parameter_schema_catalog(
        ActionParameterDefinition(
            name="argument",
            value_type=ActionParameterType.STRING,
            required=required,
            nullable=False,
        ),
    )
    step = _make_parameterized_step({"argument": None})

    with pytest.raises(
        ActionParameterValidationError,
        match="parameter 'argument' must not be null",
    ):
        validate_remediation_step(step, catalog)


def test_optional_non_nullable_parameter_may_be_omitted() -> None:
    catalog, definition = _make_parameter_schema_catalog(
        ActionParameterDefinition(
            name="timeout_seconds",
            value_type=ActionParameterType.INTEGER,
            required=False,
            nullable=False,
        ),
    )
    step = _make_parameterized_step({})

    assert validate_remediation_step(step, catalog) is definition


def test_optional_parameter_still_rejects_incorrect_type() -> None:
    catalog, _ = _make_parameter_schema_catalog(
        ActionParameterDefinition(
            name="timeout_seconds",
            value_type=ActionParameterType.INTEGER,
            required=False,
        ),
    )
    step = _make_parameterized_step({"timeout_seconds": "15"})

    with pytest.raises(
        ActionParameterValidationError,
        match="parameter 'timeout_seconds' must have type integer",
    ):
        validate_remediation_step(step, catalog)


def test_action_parameter_values_accept_multiple_valid_arguments() -> None:
    catalog, definition = _make_parameter_schema_catalog(
        ActionParameterDefinition(
            name="release_id",
            value_type=ActionParameterType.STRING,
        ),
        ActionParameterDefinition(
            name="dry_run",
            value_type=ActionParameterType.BOOLEAN,
            required=False,
        ),
        ActionParameterDefinition(
            name="timeout_seconds",
            value_type=ActionParameterType.NUMBER,
            required=False,
        ),
    )
    supplied: dict[str, RemediationParameterValue] = {
        "release_id": "release-123",
        "dry_run": False,
        "timeout_seconds": 15.5,
    }
    step = _make_parameterized_step(supplied)

    assert validate_remediation_step(step, catalog) is definition
    assert dict(step.parameters) == supplied


def test_action_parameter_validation_does_not_modify_step() -> None:
    catalog, _ = _make_parameter_schema_catalog(
        ActionParameterDefinition(
            name="release_id",
            value_type=ActionParameterType.STRING,
        ),
    )
    step = _make_parameterized_step({"release_id": "release-123"})
    original_parameters = dict(step.parameters)
    original_step_id = step.step_id

    validate_remediation_step(step, catalog)

    assert dict(step.parameters) == original_parameters
    assert step.step_id == original_step_id


def test_action_parameter_non_blank_defaults_to_false() -> None:
    parameter = ActionParameterDefinition(
        name="release_id",
        value_type=ActionParameterType.STRING,
    )

    assert parameter.non_blank is False


@pytest.mark.parametrize(
    "value",
    ["release-123", " release-123 "],
)
def test_action_parameter_non_blank_accepts_valid_text(
    value: str,
) -> None:
    catalog, definition = _make_parameter_schema_catalog(
        ActionParameterDefinition(
            name="release_id",
            value_type=ActionParameterType.STRING,
            non_blank=True,
        ),
    )
    step = _make_parameterized_step({"release_id": value})

    assert validate_remediation_step(step, catalog) is definition
    assert step.parameters["release_id"] == value


@pytest.mark.parametrize(
    "blank_value",
    ["", "   ", "\t\n"],
)
def test_action_parameter_non_blank_rejects_blank_text(
    blank_value: str,
) -> None:
    catalog, _ = _make_parameter_schema_catalog(
        ActionParameterDefinition(
            name="release_id",
            value_type=ActionParameterType.STRING,
            non_blank=True,
        ),
    )
    step = _make_parameterized_step({"release_id": blank_value})

    with pytest.raises(
        ActionParameterValidationError,
        match="parameter 'release_id' must not be blank",
    ):
        validate_remediation_step(step, catalog)


@pytest.mark.parametrize(
    "blank_value",
    ["", " \t "],
)
def test_action_parameter_allows_blank_text_when_disabled(
    blank_value: str,
) -> None:
    catalog, definition = _make_parameter_schema_catalog(
        ActionParameterDefinition(
            name="release_id",
            value_type=ActionParameterType.STRING,
            non_blank=False,
        ),
    )
    step = _make_parameterized_step({"release_id": blank_value})

    assert validate_remediation_step(step, catalog) is definition
    assert step.parameters["release_id"] == blank_value


@pytest.mark.parametrize(
    "value_type",
    [
        ActionParameterType.INTEGER,
        ActionParameterType.NUMBER,
        ActionParameterType.BOOLEAN,
    ],
)
def test_action_parameter_non_blank_requires_string_type(
    value_type: ActionParameterType,
) -> None:
    with pytest.raises(
        ValueError,
        match="non_blank requires string value_type",
    ):
        ActionParameterDefinition(
            name="argument",
            value_type=value_type,
            non_blank=True,
        )


@pytest.mark.parametrize("invalid_value", [0, 1])
def test_action_parameter_non_blank_rejects_non_boolean_flag(
    invalid_value: int,
) -> None:
    with pytest.raises(
        ValueError,
        match="non_blank must be a boolean",
    ):
        ActionParameterDefinition(
            name="release_id",
            value_type=ActionParameterType.STRING,
            non_blank=cast(bool, invalid_value),
        )


def test_action_parameter_non_blank_accepts_nullable_none() -> None:
    catalog, definition = _make_parameter_schema_catalog(
        ActionParameterDefinition(
            name="release_id",
            value_type=ActionParameterType.STRING,
            nullable=True,
            non_blank=True,
        ),
    )
    step = _make_parameterized_step({"release_id": None})

    assert validate_remediation_step(step, catalog) is definition
    assert step.parameters["release_id"] is None


def test_action_parameter_non_blank_rejects_blank_when_nullable() -> None:
    catalog, _ = _make_parameter_schema_catalog(
        ActionParameterDefinition(
            name="release_id",
            value_type=ActionParameterType.STRING,
            nullable=True,
            non_blank=True,
        ),
    )
    step = _make_parameterized_step({"release_id": "   "})

    with pytest.raises(
        ActionParameterValidationError,
        match="parameter 'release_id' must not be blank",
    ):
        validate_remediation_step(step, catalog)


def test_action_parameter_non_blank_preserves_original_text() -> None:
    catalog, definition = _make_parameter_schema_catalog(
        ActionParameterDefinition(
            name="release_id",
            value_type=ActionParameterType.STRING,
            non_blank=True,
        ),
    )
    original_value = "  release-123  "
    step = _make_parameterized_step(
        {"release_id": original_value},
    )

    assert validate_remediation_step(step, catalog) is definition
    assert step.parameters["release_id"] == original_value


def test_action_parameter_non_blank_rejects_non_nullable_none() -> None:
    catalog, _ = _make_parameter_schema_catalog(
        ActionParameterDefinition(
            name="release_id",
            value_type=ActionParameterType.STRING,
            nullable=False,
            non_blank=True,
        ),
    )
    step = _make_parameterized_step({"release_id": None})

    with pytest.raises(
        ActionParameterValidationError,
        match="parameter 'release_id' must not be null",
    ):
        validate_remediation_step(step, catalog)


def test_action_parameter_numeric_bounds_default_to_none() -> None:
    parameter = ActionParameterDefinition(
        name="timeout_seconds",
        value_type=ActionParameterType.INTEGER,
    )

    assert parameter.minimum is None
    assert parameter.maximum is None


@pytest.mark.parametrize(
    ("value_type", "minimum", "maximum"),
    [
        (ActionParameterType.INTEGER, 1, 300),
        (ActionParameterType.NUMBER, 0.5, 10.5),
        (ActionParameterType.INTEGER, 1, None),
        (ActionParameterType.INTEGER, None, 300),
        (ActionParameterType.NUMBER, 0.5, None),
        (ActionParameterType.NUMBER, None, 10.5),
        (ActionParameterType.INTEGER, 5, 5),
        (ActionParameterType.NUMBER, 1.5, 1.5),
        (ActionParameterType.NUMBER, 0, 2.5),
    ],
)
def test_action_parameter_accepts_valid_numeric_bounds(
    value_type: ActionParameterType,
    minimum: int | float | None,
    maximum: int | float | None,
) -> None:
    parameter = ActionParameterDefinition(
        name="timeout_seconds",
        value_type=value_type,
        minimum=minimum,
        maximum=maximum,
    )

    assert parameter.minimum == minimum
    assert parameter.maximum == maximum
    assert parameter.value_type is value_type


@pytest.mark.parametrize(
    "value_type",
    [
        ActionParameterType.STRING,
        ActionParameterType.BOOLEAN,
    ],
)
@pytest.mark.parametrize("bound_name", ["minimum", "maximum"])
def test_action_parameter_rejects_bounds_for_non_numeric_types(
    value_type: ActionParameterType,
    bound_name: str,
) -> None:
    with pytest.raises(
        ValueError,
        match="numeric bounds require integer or number value_type",
    ):
        ActionParameterDefinition(
            name="argument",
            value_type=value_type,
            minimum=1 if bound_name == "minimum" else None,
            maximum=1 if bound_name == "maximum" else None,
        )


@pytest.mark.parametrize("bound_name", ["minimum", "maximum"])
def test_integer_parameter_rejects_fractional_bounds(
    bound_name: str,
) -> None:
    with pytest.raises(
        ValueError,
        match=f"{bound_name} must be an integer",
    ):
        ActionParameterDefinition(
            name="timeout_seconds",
            value_type=ActionParameterType.INTEGER,
            minimum=1.5 if bound_name == "minimum" else None,
            maximum=1.5 if bound_name == "maximum" else None,
        )


@pytest.mark.parametrize(
    ("bound_name", "invalid_value"),
    [
        ("minimum", True),
        ("maximum", False),
        ("minimum", "1"),
        ("maximum", "300"),
    ],
)
def test_action_parameter_rejects_non_numeric_bounds(
    bound_name: str,
    invalid_value: object,
) -> None:
    bound = cast(int | float, invalid_value)

    with pytest.raises(
        ValueError,
        match=f"{bound_name} must be numeric",
    ):
        ActionParameterDefinition(
            name="timeout_seconds",
            value_type=ActionParameterType.NUMBER,
            minimum=bound if bound_name == "minimum" else None,
            maximum=bound if bound_name == "maximum" else None,
        )


@pytest.mark.parametrize("bound_name", ["minimum", "maximum"])
@pytest.mark.parametrize(
    "invalid_value",
    [float("nan"), float("inf"), float("-inf")],
)
def test_action_parameter_rejects_non_finite_bounds(
    bound_name: str,
    invalid_value: float,
) -> None:
    with pytest.raises(
        ValueError,
        match=f"{bound_name} must be finite",
    ):
        ActionParameterDefinition(
            name="timeout_seconds",
            value_type=ActionParameterType.NUMBER,
            minimum=invalid_value if bound_name == "minimum" else None,
            maximum=invalid_value if bound_name == "maximum" else None,
        )


@pytest.mark.parametrize(
    ("minimum", "maximum"),
    [
        (300, 1),
        (10.5, 0.5),
    ],
)
def test_action_parameter_rejects_reversed_numeric_bounds(
    minimum: int | float,
    maximum: int | float,
) -> None:
    with pytest.raises(
        ValueError,
        match="minimum must not exceed maximum",
    ):
        ActionParameterDefinition(
            name="timeout_seconds",
            value_type=ActionParameterType.NUMBER,
            minimum=minimum,
            maximum=maximum,
        )


def _make_bounded_timeout_catalog(
    *,
    value_type: ActionParameterType = ActionParameterType.INTEGER,
    minimum: int | float | None = None,
    maximum: int | float | None = None,
    required: bool = True,
    nullable: bool = False,
) -> tuple[ActionCatalog, ActionDefinition]:
    """Create a trusted action with a bounded numeric parameter."""
    return _make_parameter_schema_catalog(
        ActionParameterDefinition(
            name="timeout_seconds",
            value_type=value_type,
            minimum=minimum,
            maximum=maximum,
            required=required,
            nullable=nullable,
        ),
    )


@pytest.mark.parametrize(
    ("value_type", "minimum", "maximum", "value"),
    [
        (ActionParameterType.INTEGER, 1, 300, 1),
        (ActionParameterType.INTEGER, 1, 300, 150),
        (ActionParameterType.INTEGER, 1, 300, 300),
        (ActionParameterType.NUMBER, 0.5, 10.5, 0.5),
        (ActionParameterType.NUMBER, 0.5, 10.5, 5),
        (ActionParameterType.NUMBER, 0.5, 10.5, 5.5),
        (ActionParameterType.NUMBER, 0.5, 10.5, 10.5),
        (ActionParameterType.NUMBER, 0, 2.5, 2.5),
    ],
)
def test_action_parameter_bounds_accept_values_in_closed_range(
    value_type: ActionParameterType,
    minimum: int | float,
    maximum: int | float,
    value: int | float,
) -> None:
    catalog, definition = _make_bounded_timeout_catalog(
        value_type=value_type,
        minimum=minimum,
        maximum=maximum,
    )
    step = _make_parameterized_step({"timeout_seconds": value})

    assert validate_remediation_step(step, catalog) is definition
    assert step.parameters["timeout_seconds"] == value


@pytest.mark.parametrize(
    ("value_type", "minimum", "maximum", "value", "message"),
    [
        (ActionParameterType.INTEGER, 1, 300, 0, "must not be below minimum"),
        (ActionParameterType.INTEGER, 1, 300, 301, "must not exceed maximum"),
        (ActionParameterType.NUMBER, 0.5, 10.5, 0.49, "must not be below minimum"),
        (ActionParameterType.NUMBER, 0.5, 10.5, 10.51, "must not exceed maximum"),
    ],
)
def test_action_parameter_bounds_reject_out_of_range_values(
    value_type: ActionParameterType,
    minimum: int | float,
    maximum: int | float,
    value: int | float,
    message: str,
) -> None:
    catalog, _ = _make_bounded_timeout_catalog(
        value_type=value_type,
        minimum=minimum,
        maximum=maximum,
    )
    step = _make_parameterized_step({"timeout_seconds": value})

    with pytest.raises(ActionParameterValidationError, match=message):
        validate_remediation_step(step, catalog)


@pytest.mark.parametrize(
    ("minimum", "maximum", "value", "error_message"),
    [
        (1, None, 1, None),
        (1, None, 10_000, None),
        (1, None, 0, "must not be below minimum"),
        (None, 300, 300, None),
        (None, 300, -100, None),
        (None, 300, 301, "must not exceed maximum"),
    ],
)
def test_action_parameter_bounds_support_one_sided_ranges(
    minimum: int | None,
    maximum: int | None,
    value: int,
    error_message: str | None,
) -> None:
    catalog, definition = _make_bounded_timeout_catalog(
        minimum=minimum,
        maximum=maximum,
    )
    step = _make_parameterized_step({"timeout_seconds": value})

    if error_message is None:
        assert validate_remediation_step(step, catalog) is definition
    else:
        with pytest.raises(ActionParameterValidationError, match=error_message):
            validate_remediation_step(step, catalog)


@pytest.mark.parametrize(
    ("value", "error_message"),
    [
        (5, None),
        (4, "must not be below minimum"),
        (6, "must not exceed maximum"),
    ],
)
def test_action_parameter_bounds_support_single_point_range(
    value: int,
    error_message: str | None,
) -> None:
    catalog, definition = _make_bounded_timeout_catalog(
        minimum=5,
        maximum=5,
    )
    step = _make_parameterized_step({"timeout_seconds": value})

    if error_message is None:
        assert validate_remediation_step(step, catalog) is definition
    else:
        with pytest.raises(ActionParameterValidationError, match=error_message):
            validate_remediation_step(step, catalog)


def test_action_parameter_bounds_allow_nullable_none() -> None:
    catalog, definition = _make_bounded_timeout_catalog(
        minimum=1,
        maximum=300,
        nullable=True,
    )
    step = _make_parameterized_step({"timeout_seconds": None})

    assert validate_remediation_step(step, catalog) is definition


def test_action_parameter_bounds_allow_omitted_optional_parameter() -> None:
    catalog, definition = _make_bounded_timeout_catalog(
        minimum=1,
        maximum=300,
        required=False,
    )
    step = _make_parameterized_step({})

    assert validate_remediation_step(step, catalog) is definition


@pytest.mark.parametrize("value", [-1000, 100_000])
def test_action_parameter_bounds_allow_unbounded_numbers(
    value: int,
) -> None:
    catalog, definition = _make_bounded_timeout_catalog()
    step = _make_parameterized_step({"timeout_seconds": value})

    assert validate_remediation_step(step, catalog) is definition


def test_action_parameter_bounds_preserve_original_value() -> None:
    catalog, definition = _make_bounded_timeout_catalog(
        value_type=ActionParameterType.NUMBER,
        minimum=0.5,
        maximum=10.5,
    )
    step = _make_parameterized_step({"timeout_seconds": 5.75})
    original_parameters = dict(step.parameters)

    assert validate_remediation_step(step, catalog) is definition
    assert dict(step.parameters) == original_parameters
    assert step.parameters["timeout_seconds"] == 5.75


@pytest.mark.parametrize(
    ("value_type", "invalid_value", "expected_type"),
    [
        (ActionParameterType.INTEGER, True, "integer"),
        (ActionParameterType.NUMBER, False, "number"),
    ],
)
def test_action_parameter_bounds_do_not_bypass_type_validation(
    value_type: ActionParameterType,
    invalid_value: bool,
    expected_type: str,
) -> None:
    catalog, _ = _make_bounded_timeout_catalog(
        value_type=value_type,
        minimum=1,
        maximum=300,
    )
    step = _make_parameterized_step(
        {"timeout_seconds": invalid_value},
    )

    with pytest.raises(
        ActionParameterValidationError,
        match=f"parameter 'timeout_seconds' must have type {expected_type}",
    ):
        validate_remediation_step(step, catalog)


def test_action_parameter_allowed_values_defaults_to_none() -> None:
    parameter = ActionParameterDefinition(
        name="strategy",
        value_type=ActionParameterType.STRING,
    )

    assert parameter.allowed_values is None


@pytest.mark.parametrize(
    ("value_type", "allowed_values"),
    [
        (ActionParameterType.STRING, ("rolling", "immediate")),
        (ActionParameterType.INTEGER, (1, 2, 3)),
        (ActionParameterType.NUMBER, (1, 2.5, 3.5)),
        (ActionParameterType.BOOLEAN, (True, False)),
    ],
)
def test_action_parameter_accepts_valid_allowed_values(
    value_type: ActionParameterType,
    allowed_values: tuple[str | int | float | bool, ...],
) -> None:
    parameter = ActionParameterDefinition(
        name="strategy",
        value_type=value_type,
        allowed_values=allowed_values,
    )

    assert parameter.allowed_values == allowed_values
    assert parameter.value_type is value_type


def test_action_parameter_accepts_single_allowed_value() -> None:
    parameter = ActionParameterDefinition(
        name="strategy",
        value_type=ActionParameterType.STRING,
        allowed_values=("rolling",),
    )

    assert parameter.allowed_values == ("rolling",)


def test_action_parameter_allowed_values_support_nullable_definition() -> None:
    parameter = ActionParameterDefinition(
        name="strategy",
        value_type=ActionParameterType.STRING,
        nullable=True,
        allowed_values=("rolling", "immediate"),
    )

    assert parameter.nullable is True
    assert parameter.allowed_values == ("rolling", "immediate")


@pytest.mark.parametrize(
    "invalid_values",
    [
        (),
        ["rolling"],
        {"rolling"},
    ],
)
def test_action_parameter_rejects_invalid_allowed_values_collection(
    invalid_values: object,
) -> None:
    with pytest.raises(
        ValueError,
        match="allowed_values must be a non-empty tuple",
    ):
        ActionParameterDefinition(
            name="strategy",
            value_type=ActionParameterType.STRING,
            allowed_values=cast(
                tuple[str | int | float | bool, ...],
                invalid_values,
            ),
        )


@pytest.mark.parametrize(
    ("value_type", "invalid_values"),
    [
        (ActionParameterType.STRING, (1,)),
        (ActionParameterType.INTEGER, (True,)),
        (ActionParameterType.INTEGER, (1.0,)),
        (ActionParameterType.NUMBER, (False,)),
        (ActionParameterType.NUMBER, ("1",)),
        (ActionParameterType.BOOLEAN, (1,)),
    ],
)
def test_action_parameter_rejects_allowed_values_with_wrong_types(
    value_type: ActionParameterType,
    invalid_values: tuple[str | int | float | bool, ...],
) -> None:
    with pytest.raises(
        ValueError,
        match="allowed_values must match value_type",
    ):
        ActionParameterDefinition(
            name="argument",
            value_type=value_type,
            allowed_values=invalid_values,
        )


@pytest.mark.parametrize(
    ("value_type", "duplicate_values"),
    [
        (ActionParameterType.STRING, ("rolling", "rolling")),
        (ActionParameterType.INTEGER, (1, 1)),
        (ActionParameterType.NUMBER, (1, 1.0)),
        (ActionParameterType.BOOLEAN, (True, True)),
    ],
)
def test_action_parameter_rejects_duplicate_allowed_values(
    value_type: ActionParameterType,
    duplicate_values: tuple[str | int | float | bool, ...],
) -> None:
    with pytest.raises(
        ValueError,
        match="allowed_values must be unique",
    ):
        ActionParameterDefinition(
            name="argument",
            value_type=value_type,
            allowed_values=duplicate_values,
        )


@pytest.mark.parametrize(
    "invalid_value",
    [
        float("nan"),
        float("inf"),
        float("-inf"),
    ],
)
def test_action_parameter_rejects_non_finite_allowed_values(
    invalid_value: float,
) -> None:
    with pytest.raises(
        ValueError,
        match="allowed_values must be finite",
    ):
        ActionParameterDefinition(
            name="threshold",
            value_type=ActionParameterType.NUMBER,
            allowed_values=(1.5, invalid_value),
        )


@pytest.mark.parametrize(
    "blank_value",
    ["", "   ", "\t\n"],
)
def test_action_parameter_rejects_blank_allowed_values_when_non_blank(
    blank_value: str,
) -> None:
    with pytest.raises(
        ValueError,
        match="allowed_values must not contain blank text",
    ):
        ActionParameterDefinition(
            name="strategy",
            value_type=ActionParameterType.STRING,
            non_blank=True,
            allowed_values=("rolling", blank_value),
        )


@pytest.mark.parametrize(
    ("allowed_values", "expected_error"),
    [
        ((0, 2), "allowed_values must respect minimum"),
        ((2, 6), "allowed_values must respect maximum"),
    ],
)
def test_action_parameter_rejects_allowed_values_outside_bounds(
    allowed_values: tuple[int, ...],
    expected_error: str,
) -> None:
    with pytest.raises(ValueError, match=expected_error):
        ActionParameterDefinition(
            name="timeout_seconds",
            value_type=ActionParameterType.INTEGER,
            minimum=1,
            maximum=5,
            allowed_values=allowed_values,
        )


def test_action_parameter_accepts_allowed_values_within_bounds() -> None:
    parameter = ActionParameterDefinition(
        name="timeout_seconds",
        value_type=ActionParameterType.NUMBER,
        minimum=1,
        maximum=5,
        allowed_values=(1, 2.5, 5),
    )

    assert parameter.allowed_values == (1, 2.5, 5)


def test_action_parameter_rejects_none_inside_allowed_values() -> None:
    invalid_values = cast(
        tuple[str | int | float | bool, ...],
        ("rolling", None),
    )

    with pytest.raises(
        ValueError,
        match="allowed_values must match value_type",
    ):
        ActionParameterDefinition(
            name="strategy",
            value_type=ActionParameterType.STRING,
            nullable=True,
            allowed_values=invalid_values,
        )


def test_action_parameter_allowed_values_cannot_be_reassigned() -> None:
    parameter = ActionParameterDefinition(
        name="strategy",
        value_type=ActionParameterType.STRING,
        allowed_values=("rolling", "immediate"),
    )

    field_name = "allowed_values"

    with pytest.raises(FrozenInstanceError):
        setattr(parameter, field_name, ("unsafe",))

    assert parameter.allowed_values == ("rolling", "immediate")


def test_action_parameter_allowed_values_collection_is_immutable() -> None:
    parameter = ActionParameterDefinition(
        name="strategy",
        value_type=ActionParameterType.STRING,
        allowed_values=("rolling", "immediate"),
    )

    mutable_view = cast(
        MutableSequence[str | int | float | bool],
        parameter.allowed_values,
    )

    with pytest.raises(TypeError):
        mutable_view[0] = "unsafe"

    assert parameter.allowed_values == ("rolling", "immediate")


def _make_allowed_values_catalog(
    value_type: ActionParameterType,
    allowed_values: tuple[str | int | float | bool, ...] | None,
    *,
    required: bool = True,
    nullable: bool = False,
) -> tuple[ActionCatalog, ActionDefinition]:
    """Build a trusted action with a single restricted parameter."""
    return _make_parameter_schema_catalog(
        ActionParameterDefinition(
            name="argument",
            value_type=value_type,
            allowed_values=allowed_values,
            required=required,
            nullable=nullable,
        ),
    )


@pytest.mark.parametrize(
    ("value_type", "allowed_values", "value"),
    [
        (ActionParameterType.STRING, ("rolling", "immediate"), "rolling"),
        (ActionParameterType.STRING, ("rolling", "immediate"), "immediate"),
        (ActionParameterType.INTEGER, (1, 2), 2),
        (ActionParameterType.NUMBER, (1, 2.5), 1),
        (ActionParameterType.NUMBER, (1, 2.5), 2.5),
        (ActionParameterType.BOOLEAN, (True, False), True),
        (ActionParameterType.BOOLEAN, (True, False), False),
    ],
)
def test_action_allowed_values_accept_registered_values(
    value_type: ActionParameterType,
    allowed_values: tuple[str | int | float | bool, ...],
    value: RemediationParameterValue,
) -> None:
    catalog, definition = _make_allowed_values_catalog(value_type, allowed_values)
    step = _make_parameterized_step({"argument": value})

    assert validate_remediation_step(step, catalog) is definition
    assert step.parameters["argument"] == value


@pytest.mark.parametrize(
    ("value_type", "allowed_values", "value"),
    [
        (ActionParameterType.STRING, ("rolling", "immediate"), "unsupported"),
        (ActionParameterType.STRING, ("rolling", "immediate"), "ROLLING"),
        (ActionParameterType.INTEGER, (1, 2), 3),
        (ActionParameterType.NUMBER, (1, 2.5), 7),
        (ActionParameterType.BOOLEAN, (True,), False),
    ],
)
def test_action_allowed_values_reject_unregistered_values(
    value_type: ActionParameterType,
    allowed_values: tuple[str | int | float | bool, ...],
    value: RemediationParameterValue,
) -> None:
    catalog, _ = _make_allowed_values_catalog(value_type, allowed_values)
    step = _make_parameterized_step({"argument": value})

    with pytest.raises(
        ActionParameterValidationError,
        match="parameter 'argument' must match one of the allowed values",
    ):
        validate_remediation_step(step, catalog)


@pytest.mark.parametrize(
    ("allowed_values", "value"),
    [
        ((1,), 1.0),
        ((2.0,), 2),
    ],
)
def test_action_allowed_values_accept_equivalent_number_forms(
    allowed_values: tuple[str | int | float | bool, ...],
    value: int | float,
) -> None:
    catalog, definition = _make_allowed_values_catalog(
        ActionParameterType.NUMBER,
        allowed_values,
    )
    step = _make_parameterized_step({"argument": value})

    assert validate_remediation_step(step, catalog) is definition
    assert type(step.parameters["argument"]) is type(value)


@pytest.mark.parametrize(
    ("value_type", "value"),
    [
        (ActionParameterType.STRING, "any_strategy"),
        (ActionParameterType.NUMBER, 999.5),
    ],
)
def test_action_allowed_values_none_does_not_restrict_values(
    value_type: ActionParameterType,
    value: RemediationParameterValue,
) -> None:
    catalog, definition = _make_allowed_values_catalog(
        value_type,
        None,
    )
    step = _make_parameterized_step({"argument": value})

    assert validate_remediation_step(step, catalog) is definition


def test_action_allowed_values_accept_nullable_none() -> None:
    catalog, definition = _make_allowed_values_catalog(
        ActionParameterType.STRING,
        ("rolling",),
        nullable=True,
    )
    step = _make_parameterized_step({"argument": None})

    assert validate_remediation_step(step, catalog) is definition


def test_action_allowed_values_reject_non_nullable_none() -> None:
    catalog, _ = _make_allowed_values_catalog(
        ActionParameterType.STRING,
        ("rolling",),
        nullable=False,
    )
    step = _make_parameterized_step({"argument": None})

    with pytest.raises(
        ActionParameterValidationError,
        match="parameter 'argument' must not be null",
    ):
        validate_remediation_step(step, catalog)


def test_action_allowed_values_allow_absent_optional_argument() -> None:
    catalog, definition = _make_allowed_values_catalog(
        ActionParameterType.STRING,
        ("rolling",),
        required=False,
    )
    step = _make_parameterized_step({})

    assert validate_remediation_step(step, catalog) is definition


@pytest.mark.parametrize(
    ("value_type", "allowed_values", "wrong_value"),
    [
        (ActionParameterType.STRING, ("rolling",), 123),
        (ActionParameterType.INTEGER, (1,), True),
        (ActionParameterType.NUMBER, (1,), False),
        (ActionParameterType.BOOLEAN, (True,), 1),
    ],
)
def test_action_allowed_values_checks_type_before_membership(
    value_type: ActionParameterType,
    allowed_values: tuple[str | int | float | bool, ...],
    wrong_value: RemediationParameterValue,
) -> None:
    catalog, _ = _make_allowed_values_catalog(
        value_type,
        allowed_values,
    )
    step = _make_parameterized_step({"argument": wrong_value})

    with pytest.raises(
        ActionParameterValidationError,
        match=f"parameter 'argument' must have type {value_type.value}",
    ):
        validate_remediation_step(step, catalog)


def test_action_allowed_values_checks_non_blank_before_membership() -> None:
    catalog, _ = _make_parameter_schema_catalog(
        ActionParameterDefinition(
            name="argument",
            value_type=ActionParameterType.STRING,
            non_blank=True,
            allowed_values=("rolling",),
        ),
    )
    step = _make_parameterized_step({"argument": "   "})

    with pytest.raises(
        ActionParameterValidationError,
        match="parameter 'argument' must not be blank",
    ):
        validate_remediation_step(step, catalog)


def test_action_allowed_values_checks_bounds_before_membership() -> None:
    catalog, _ = _make_parameter_schema_catalog(
        ActionParameterDefinition(
            name="argument",
            value_type=ActionParameterType.INTEGER,
            minimum=1,
            maximum=5,
            allowed_values=(2, 3),
        ),
    )
    step = _make_parameterized_step({"argument": 0})

    with pytest.raises(
        ActionParameterValidationError,
        match="parameter 'argument' must not be below minimum",
    ):
        validate_remediation_step(step, catalog)


def test_action_allowed_values_do_not_normalize_accepted_values() -> None:
    original_value = " rolling "
    catalog, definition = _make_allowed_values_catalog(
        ActionParameterType.STRING,
        (original_value,),
    )
    step = _make_parameterized_step({"argument": original_value})
    original_parameters = dict(step.parameters)

    assert validate_remediation_step(step, catalog) is definition
    assert dict(step.parameters) == original_parameters
    assert step.parameters["argument"] == original_value


def test_action_allowed_values_rejection_preserves_arguments_and_hides_value() -> None:
    original_value = "secret_unsupported_strategy"
    catalog, _ = _make_allowed_values_catalog(
        ActionParameterType.STRING,
        ("rolling",),
    )
    step = _make_parameterized_step({"argument": original_value})
    original_parameters = dict(step.parameters)

    with pytest.raises(ActionParameterValidationError) as error:
        validate_remediation_step(step, catalog)

    assert "must match one of the allowed values" in str(error.value)
    assert original_value not in str(error.value)
    assert dict(step.parameters) == original_parameters
