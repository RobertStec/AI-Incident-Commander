"""Remediation domain models and risk classification."""

from __future__ import annotations

from collections.abc import Mapping
from copy import copy
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from math import isfinite
from types import MappingProxyType
from uuid import UUID, uuid4


class RemediationRiskLevel(StrEnum):
    """Risk classification of a remediation action."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class RemediationPlanStatus(StrEnum):
    """Lifecycle states of an incident remediation plan."""

    DRAFT = "draft"
    READY = "ready"
    IN_PROGRESS = "in_progress"
    VERIFYING = "verifying"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


type RemediationParameterValue = str | int | float | bool | None

_ALLOWED_REMEDIATION_PLAN_TRANSITIONS: dict[
    RemediationPlanStatus, frozenset[RemediationPlanStatus]
] = {
    RemediationPlanStatus.DRAFT: frozenset(
        {
            RemediationPlanStatus.READY,
            RemediationPlanStatus.CANCELLED,
        }
    ),
    RemediationPlanStatus.READY: frozenset(
        {
            RemediationPlanStatus.DRAFT,
            RemediationPlanStatus.IN_PROGRESS,
            RemediationPlanStatus.CANCELLED,
        }
    ),
    RemediationPlanStatus.IN_PROGRESS: frozenset(
        {
            RemediationPlanStatus.VERIFYING,
            RemediationPlanStatus.FAILED,
        }
    ),
    RemediationPlanStatus.VERIFYING: frozenset(
        {
            RemediationPlanStatus.COMPLETED,
            RemediationPlanStatus.FAILED,
        }
    ),
    RemediationPlanStatus.COMPLETED: frozenset(),
    RemediationPlanStatus.FAILED: frozenset(),
    RemediationPlanStatus.CANCELLED: frozenset(),
}


class RemediationPlanTransitionError(ValueError):
    """Raised when a remediation plan transition is not permitted."""


class RemediationPlanStepError(ValueError):
    """Raised when modifying remediation plan steps is not permitted."""


def can_transition_remediation_plan_status(
    current: RemediationPlanStatus,
    target: RemediationPlanStatus,
) -> bool:
    """Check whether a remediation plan transition is structurally allowed."""
    return target in _ALLOWED_REMEDIATION_PLAN_TRANSITIONS[current]


@dataclass(frozen=True, slots=True, kw_only=True)
class RemediationPlan:
    """Proposed remediation strategy for an incident."""

    incident_id: UUID
    description: str
    risk_level: RemediationRiskLevel

    plan_id: UUID = field(default_factory=uuid4)
    hypothesis_id: UUID | None = None

    steps: tuple[RemediationStep, ...] = ()

    status: RemediationPlanStatus = field(
        default=RemediationPlanStatus.DRAFT,
        init=False,
    )

    created_at: datetime = field(
        default_factory=lambda: datetime.now(UTC),
    )
    updated_at: datetime = field(
        default_factory=lambda: datetime.now(UTC),
    )

    def __post_init__(self) -> None:
        """Validate initial remediation plan invariants."""
        if not self.description.strip():
            raise ValueError("Remediation plan description must not be empty.")

        for timestamp in (self.created_at, self.updated_at):
            if timestamp.utcoffset() != timedelta(0):
                raise ValueError("Remediation plan timestamps must use UTC.")

        if self.updated_at < self.created_at:
            raise ValueError("updated_at must not precede created_at.")

        self._validate_steps()

    def _validate_steps(self) -> None:
        """Validate and normalize remediation plan steps."""
        if not isinstance(self.steps, tuple):
            raise ValueError("Remediation plan steps must be a tuple.")

        positions: set[int] = set()
        step_ids: set[UUID] = set()

        for step in self.steps:
            if not isinstance(step, RemediationStep):
                raise ValueError("Remediation plan steps must be RemediationStep instances.")

            if step.plan_id != self.plan_id:
                raise ValueError("Remediation step belongs to a different plan.")

            if step.position in positions:
                raise ValueError("Remediation step positions must be unique.")

            if step.step_id in step_ids:
                raise ValueError("Remediation step identifiers must be unique.")

            positions.add(step.position)
            step_ids.add(step.step_id)

        object.__setattr__(
            self,
            "steps",
            tuple(sorted(self.steps, key=lambda step: step.position)),
        )

    def validate_structural_readiness(self) -> None:
        """Validate basic structural requirements for plan readiness."""
        if not self.steps:
            raise RemediationPlanTransitionError(
                "Remediation plan requires at least one step before it can become ready."
            )

    def validate_risk_consistency(self) -> None:
        """Ensure plan risk is not lower than any step's risk."""
        risk_ranks = {
            RemediationRiskLevel.LOW: 1,
            RemediationRiskLevel.MEDIUM: 2,
            RemediationRiskLevel.HIGH: 3,
        }

        for step in self.steps:
            if risk_ranks[step.risk_level] > risk_ranks[self.risk_level]:
                raise RemediationPlanTransitionError(
                    "Remediation plan risk level must not be lower than any step risk level."
                )

    def transition_to(
        self,
        target: RemediationPlanStatus,
    ) -> RemediationPlan:
        """Return a new plan after a safe lifecycle transition."""
        if not can_transition_remediation_plan_status(
            self.status,
            target,
        ):
            raise RemediationPlanTransitionError(
                f"Transition from {self.status.value} to {target.value} is not allowed."
            )

        if (
            self.status is not RemediationPlanStatus.DRAFT
            or target is not RemediationPlanStatus.CANCELLED
        ):
            raise RemediationPlanTransitionError(
                f"Transition from {self.status.value} "
                f"to {target.value} requires validated remediation context."
            )

        transitioned_at = datetime.now(UTC)

        if transitioned_at < self.updated_at:
            raise RemediationPlanTransitionError("Transition time must not precede updated_at.")

        updated_plan = copy(self)
        object.__setattr__(updated_plan, "status", target)
        object.__setattr__(
            updated_plan,
            "updated_at",
            transitioned_at,
        )

        return updated_plan

    def add_step(self, step: RemediationStep) -> RemediationPlan:
        """Return a new draft plan with an additional validated step."""
        if self.status is not RemediationPlanStatus.DRAFT:
            raise RemediationPlanStepError("Steps can only be added to a draft remediation plan.")

        added_at = datetime.now(UTC)

        if added_at < self.updated_at:
            raise RemediationPlanStepError("Step addition time must not precede updated_at.")

        updated_plan = copy(self)

        object.__setattr__(
            updated_plan,
            "steps",
            (*self.steps, step),
        )
        object.__setattr__(
            updated_plan,
            "updated_at",
            added_at,
        )

        updated_plan._validate_steps()

        return updated_plan


@dataclass(frozen=True, slots=True, kw_only=True)
class RemediationStep:
    """Declarative remediation action belonging to a plan."""

    plan_id: UUID
    position: int
    action_name: str
    target: str
    environment: str
    risk_level: RemediationRiskLevel
    parameters: Mapping[str, RemediationParameterValue] = field(
        default_factory=dict,
        hash=False,
    )

    step_id: UUID = field(default_factory=uuid4)
    created_at: datetime = field(
        default_factory=lambda: datetime.now(UTC),
    )

    def __post_init__(self) -> None:
        """Validate basic remediation step invariants."""
        if type(self.position) is not int or self.position < 1:
            raise ValueError("Remediation step position must be a positive integer.")

        required_fields = {
            "action_name": self.action_name,
            "target": self.target,
            "environment": self.environment,
        }

        for field_name, value in required_fields.items():
            if not value.strip():
                raise ValueError(f"Remediation step {field_name} must not be empty.")

        if self.created_at.utcoffset() != timedelta(0):
            raise ValueError("Remediation step timestamps must use UTC.")

        for key, parameter_value in self.parameters.items():
            if not isinstance(key, str) or not key.strip():
                raise ValueError("Remediation step parameter names must be non-empty strings.")

            if parameter_value is not None and not isinstance(
                parameter_value, (str, int, float, bool)
            ):
                raise ValueError("Remediation step parameters must be JSON scalars.")

            if isinstance(parameter_value, float) and not isfinite(parameter_value):
                raise ValueError("Remediation step numeric parameters must be finite.")

        object.__setattr__(
            self,
            "parameters",
            MappingProxyType(dict(self.parameters)),
        )
