"""Hypothesis domain model and evaluation types."""

from __future__ import annotations

from copy import copy
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from uuid import UUID, uuid4


class HypothesisStatus(StrEnum):
    """Lifecycle states of an incident root-cause hypothesis."""

    PROPOSED = "proposed"
    UNDER_EVALUATION = "under_evaluation"
    SUPPORTED = "supported"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"


class HypothesisConfidenceLevel(StrEnum):
    """Qualitative strength of evidence supporting a hypothesis."""

    INSUFFICIENT_EVIDENCE = "insufficient_evidence"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


_ALLOWED_HYPOTHESIS_TRANSITIONS: dict[HypothesisStatus, frozenset[HypothesisStatus]] = {
    HypothesisStatus.PROPOSED: frozenset(
        {
            HypothesisStatus.UNDER_EVALUATION,
        }
    ),
    HypothesisStatus.UNDER_EVALUATION: frozenset(
        {
            HypothesisStatus.SUPPORTED,
            HypothesisStatus.REJECTED,
        }
    ),
    HypothesisStatus.SUPPORTED: frozenset(
        {
            HypothesisStatus.UNDER_EVALUATION,
            HypothesisStatus.CONFIRMED,
        }
    ),
    HypothesisStatus.CONFIRMED: frozenset(),
    HypothesisStatus.REJECTED: frozenset(),
}


class HypothesisTransitionError(ValueError):
    """Raised when a hypothesis lifecycle transition is not permitted."""


def can_transition_hypothesis_status(
    current: HypothesisStatus,
    target: HypothesisStatus,
) -> bool:
    """Check whether a hypothesis status transition is structurally allowed."""
    return target in _ALLOWED_HYPOTHESIS_TRANSITIONS[current]


@dataclass(frozen=True, slots=True, kw_only=True)
class Hypothesis:
    """A possible root cause of an incident awaiting evaluation."""

    incident_id: UUID
    statement: str
    reasoning: str

    hypothesis_id: UUID = field(default_factory=uuid4)
    status: HypothesisStatus = field(
        default=HypothesisStatus.PROPOSED,
        init=False,
    )
    confidence_level: HypothesisConfidenceLevel = field(
        default=HypothesisConfidenceLevel.INSUFFICIENT_EVIDENCE,
        init=False,
    )

    created_at: datetime = field(
        default_factory=lambda: datetime.now(UTC),
    )
    updated_at: datetime = field(
        default_factory=lambda: datetime.now(UTC),
    )

    def __post_init__(self) -> None:
        """Validate initial hypothesis invariants."""
        if not self.statement.strip():
            raise ValueError("Hypothesis statement must not be empty.")

        if not self.reasoning.strip():
            raise ValueError("Hypothesis reasoning must not be empty.")

        for timestamp in (self.created_at, self.updated_at):
            if timestamp.utcoffset() != timedelta(0):
                raise ValueError("Hypothesis timestamps must use UTC.")

        if self.updated_at < self.created_at:
            raise ValueError("updated_at must not precede created_at.")

    def transition_to(self, target: HypothesisStatus) -> Hypothesis:
        """Return a new hypothesis after an authorized status transition."""
        if not can_transition_hypothesis_status(self.status, target):
            raise HypothesisTransitionError(
                f"Transition from {self.status.value} to {target.value} is not allowed."
            )

        evidence_required_statuses = frozenset(
            {
                HypothesisStatus.SUPPORTED,
                HypothesisStatus.REJECTED,
                HypothesisStatus.CONFIRMED,
            }
        )

        if target in evidence_required_statuses:
            raise HypothesisTransitionError(
                f"Transition to {target.value} requires "
                "evidence assessment or verified diagnostic basis."
            )

        transitioned_at = datetime.now(UTC)

        if transitioned_at < self.updated_at:
            raise HypothesisTransitionError("Transition time must not precede updated_at.")

        updated_hypothesis = copy(self)
        object.__setattr__(updated_hypothesis, "status", target)
        object.__setattr__(updated_hypothesis, "updated_at", transitioned_at)

        return updated_hypothesis
