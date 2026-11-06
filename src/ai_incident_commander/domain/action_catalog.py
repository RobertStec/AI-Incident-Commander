"""Trusted remediation action definitions and catalog types."""

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from math import isfinite
from re import fullmatch
from types import MappingProxyType

from ai_incident_commander.domain.remediation import (
    RemediationRiskLevel,
    RemediationStep,
)


class ActionEffect(StrEnum):
    """Operational effect of a remediation action."""

    READ_ONLY = "read_only"
    MUTATING = "mutating"


class ActionParameterType(StrEnum):
    """Supported types of trusted remediation action parameters."""

    STRING = "string"
    INTEGER = "integer"
    NUMBER = "number"
    BOOLEAN = "boolean"


@dataclass(frozen=True, slots=True, kw_only=True)
class ActionParameterDefinition:
    """Trusted schema definition for a single action parameter."""

    name: str
    value_type: ActionParameterType
    required: bool = True
    nullable: bool = False
    non_blank: bool = False
    minimum: int | float | None = None
    maximum: int | float | None = None
    allowed_values: tuple[str | int | float | bool, ...] | None = None

    def __post_init__(self) -> None:
        """Validate parameter definition invariants."""
        if not isinstance(self.name, str) or fullmatch(r"[a-z][a-z0-9_]*", self.name) is None:
            raise ValueError("Action parameter name must use lowercase snake_case.")

        if not isinstance(self.value_type, ActionParameterType):
            raise ValueError("Action parameter value_type must be a valid ActionParameterType.")

        if type(self.required) is not bool:
            raise ValueError("Action parameter required must be a boolean.")

        if type(self.nullable) is not bool:
            raise ValueError("Action parameter nullable must be a boolean.")

        if type(self.non_blank) is not bool:
            raise ValueError("Action parameter non_blank must be a boolean.")

        if self.non_blank and self.value_type is not ActionParameterType.STRING:
            raise ValueError("Action parameter non_blank requires string value_type.")

        if self.minimum is not None or self.maximum is not None:
            if self.value_type not in (
                ActionParameterType.INTEGER,
                ActionParameterType.NUMBER,
            ):
                raise ValueError(
                    "Action parameter numeric bounds require integer or number value_type."
                )

        for bound_name, bound_value in (
            ("minimum", self.minimum),
            ("maximum", self.maximum),
        ):
            if bound_value is None:
                continue

            if type(bound_value) not in (int, float):
                raise ValueError(f"Action parameter {bound_name} must be numeric.")

            if self.value_type is ActionParameterType.INTEGER and type(bound_value) is not int:
                raise ValueError(
                    f"Action parameter {bound_name} must be an integer for integer value_type."
                )

            if isinstance(bound_value, float) and not isfinite(bound_value):
                raise ValueError(f"Action parameter {bound_name} must be finite.")

        if self.minimum is not None and self.maximum is not None and self.minimum > self.maximum:
            raise ValueError("Action parameter minimum must not exceed maximum.")

        if self.allowed_values is not None:
            if not isinstance(self.allowed_values, tuple) or not self.allowed_values:
                raise ValueError("Action parameter allowed_values must be a non-empty tuple.")

            seen_values: set[str | int | float | bool] = set()

            for allowed_value in self.allowed_values:
                if self.value_type is ActionParameterType.STRING:
                    valid_type = type(allowed_value) is str
                elif self.value_type is ActionParameterType.INTEGER:
                    valid_type = type(allowed_value) is int
                elif self.value_type is ActionParameterType.NUMBER:
                    valid_type = type(allowed_value) in (int, float)
                elif self.value_type is ActionParameterType.BOOLEAN:
                    valid_type = type(allowed_value) is bool
                else:
                    valid_type = False

                if not valid_type:
                    raise ValueError("Action parameter allowed_values must match value_type.")

                if isinstance(allowed_value, float) and not isfinite(allowed_value):
                    raise ValueError("Action parameter allowed_values must be finite.")

                if self.non_blank and isinstance(allowed_value, str) and not allowed_value.strip():
                    raise ValueError("Action parameter allowed_values must not contain blank text.")

                if isinstance(allowed_value, (int, float)) and not isinstance(allowed_value, bool):
                    if self.minimum is not None and allowed_value < self.minimum:
                        raise ValueError("Action parameter allowed_values must respect minimum.")

                    if self.maximum is not None and allowed_value > self.maximum:
                        raise ValueError("Action parameter allowed_values must respect maximum.")

                if allowed_value in seen_values:
                    raise ValueError("Action parameter allowed_values must be unique.")

                seen_values.add(allowed_value)


@dataclass(frozen=True, slots=True, kw_only=True)
class ActionDefinition:
    """Trusted definition of an allowed remediation action."""

    action_name: str
    description: str
    effect: ActionEffect
    risk_level: RemediationRiskLevel
    parameters: tuple[ActionParameterDefinition, ...] = ()

    def __post_init__(self) -> None:
        """Validate the action definition invariants."""
        if (
            not isinstance(self.action_name, str)
            or fullmatch(r"[a-z][a-z0-9_]*", self.action_name) is None
        ):
            raise ValueError("Action definition name must use lowercase snake_case.")

        if not isinstance(self.description, str) or not self.description.strip():
            raise ValueError("Action definition description must not be empty.")

        if not isinstance(self.effect, ActionEffect):
            raise ValueError("Action definition effect must be a valid ActionEffect.")

        if not isinstance(self.risk_level, RemediationRiskLevel):
            raise ValueError("Action definition risk_level must be a valid RemediationRiskLevel.")

        if not isinstance(self.parameters, tuple):
            raise ValueError("Action definition parameters must be a tuple.")

        parameter_names: set[str] = set()

        for parameter in self.parameters:
            if not isinstance(parameter, ActionParameterDefinition):
                raise ValueError(
                    "Action definition parameters must be ActionParameterDefinition instances."
                )

            if parameter.name in parameter_names:
                raise ValueError(f"Duplicate action parameter: {parameter.name}.")

            parameter_names.add(parameter.name)


class UnknownActionError(LookupError):
    """Raised when an action is absent from the trusted catalog."""


class ActionRiskMismatchError(ValueError):
    """Raised when a step risk differs from its trusted action definition."""


class ActionParameterValidationError(ValueError):
    """Raised when action parameters violate the trusted schema."""


@dataclass(frozen=True, slots=True, kw_only=True)
class ActionCatalog:
    """Immutable registry of allowed remediation action definitions."""

    definitions: tuple[ActionDefinition, ...]

    _by_name: Mapping[str, ActionDefinition] = field(
        init=False,
        repr=False,
        compare=False,
        hash=False,
    )

    def __post_init__(self) -> None:
        """Validate definitions and build the immutable lookup index."""
        if not isinstance(self.definitions, tuple):
            raise ValueError("Action catalog definitions must be a tuple.")

        by_name: dict[str, ActionDefinition] = {}

        for definition in self.definitions:
            if not isinstance(definition, ActionDefinition):
                raise ValueError("Action catalog entries must be ActionDefinition instances.")

            if definition.action_name in by_name:
                raise ValueError(f"Duplicate remediation action: {definition.action_name}.")

            by_name[definition.action_name] = definition

        object.__setattr__(
            self,
            "_by_name",
            MappingProxyType(by_name),
        )

    def get(self, action_name: str) -> ActionDefinition:
        """Return an allowed action or reject an unknown action."""
        try:
            return self._by_name[action_name]
        except KeyError as exc:
            raise UnknownActionError(
                f"Remediation action {action_name!r} is not in the trusted catalog."
            ) from exc


def _validate_action_parameter_names(
    step: RemediationStep,
    definition: ActionDefinition,
) -> None:
    """Reject unknown and missing required action parameters."""
    provided_names = set(step.parameters)

    allowed_names = {parameter.name for parameter in definition.parameters}

    unknown_names = provided_names - allowed_names

    if unknown_names:
        raise ActionParameterValidationError(
            f"Remediation action {definition.action_name!r} "
            "contains unknown parameters: "
            f"{', '.join(sorted(unknown_names))}."
        )

    missing_names = {
        parameter.name
        for parameter in definition.parameters
        if parameter.required and parameter.name not in provided_names
    }

    if missing_names:
        raise ActionParameterValidationError(
            f"Remediation action {definition.action_name!r} "
            "is missing required parameters: "
            f"{', '.join(sorted(missing_names))}."
        )


def _validate_action_parameter_values(
    step: RemediationStep,
    definition: ActionDefinition,
) -> None:
    """Validate supplied parameter values against trusted types."""
    for parameter in definition.parameters:
        if parameter.name not in step.parameters:
            continue

        value = step.parameters[parameter.name]

        if value is None:
            if parameter.nullable:
                continue

            raise ActionParameterValidationError(
                f"Remediation action {definition.action_name!r} "
                f"parameter {parameter.name!r} must not be null."
            )

        if parameter.value_type is ActionParameterType.STRING:
            valid = type(value) is str
        elif parameter.value_type is ActionParameterType.INTEGER:
            valid = type(value) is int
        elif parameter.value_type is ActionParameterType.NUMBER:
            valid = type(value) in (int, float)
        elif parameter.value_type is ActionParameterType.BOOLEAN:
            valid = type(value) is bool
        else:
            valid = False

        if not valid:
            raise ActionParameterValidationError(
                f"Remediation action {definition.action_name!r} "
                f"parameter {parameter.name!r} must have type "
                f"{parameter.value_type.value}."
            )

        if parameter.non_blank and isinstance(value, str) and not value.strip():
            raise ActionParameterValidationError(
                f"Remediation action {definition.action_name!r} "
                f"parameter {parameter.name!r} must not be blank."
            )

        if isinstance(value, (int, float)) and not isinstance(value, bool):
            if parameter.minimum is not None and value < parameter.minimum:
                raise ActionParameterValidationError(
                    f"Remediation action {definition.action_name!r} "
                    f"parameter {parameter.name!r} must not be below minimum."
                )

            if parameter.maximum is not None and value > parameter.maximum:
                raise ActionParameterValidationError(
                    f"Remediation action {definition.action_name!r} "
                    f"parameter {parameter.name!r} must not exceed maximum."
                )

        if parameter.allowed_values is not None and value not in parameter.allowed_values:
            raise ActionParameterValidationError(
                f"Remediation action {definition.action_name!r} "
                f"parameter {parameter.name!r} "
                "must match one of the allowed values."
            )


def validate_remediation_step(
    step: RemediationStep,
    catalog: ActionCatalog,
) -> ActionDefinition:
    """Validate a proposed step against the trusted action catalog."""
    definition = catalog.get(step.action_name)

    if step.risk_level is not definition.risk_level:
        raise ActionRiskMismatchError(
            f"Remediation step {step.action_name!r} risk_level "
            "does not match the trusted action definition."
        )

    _validate_action_parameter_names(step, definition)
    _validate_action_parameter_values(step, definition)

    return definition
