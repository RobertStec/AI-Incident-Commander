"""Incident domain model and lifecycle types."""

from __future__ import annotations

from copy import copy
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from uuid import UUID, uuid4


class IncidentStatus(StrEnum):
    """Business lifecycle states of an incident."""

    REPORTED = "reported"
    INVESTIGATING = "investigating"
    MITIGATING = "mitigating"
    VERIFYING = "verifying"
    RESOLVED = "resolved"
    CLOSED = "closed"


class IncidentSeverity(StrEnum):
    """Business impact classification of an incident."""

    UNCLASSIFIED = "unclassified"
    SEV1 = "sev1"
    SEV2 = "sev2"
    SEV3 = "sev3"
    SEV4 = "sev4"


_ALLOWED_STATUS_TRANSITIONS: dict[IncidentStatus, frozenset[IncidentStatus]] = {
    IncidentStatus.REPORTED: frozenset(
        {
            IncidentStatus.INVESTIGATING,
        }
    ),
    IncidentStatus.INVESTIGATING: frozenset(
        {
            IncidentStatus.MITIGATING,
            IncidentStatus.VERIFYING,
        }
    ),
    IncidentStatus.MITIGATING: frozenset(
        {
            IncidentStatus.INVESTIGATING,
            IncidentStatus.VERIFYING,
        }
    ),
    IncidentStatus.VERIFYING: frozenset(
        {
            IncidentStatus.INVESTIGATING,
            IncidentStatus.RESOLVED,
        }
    ),
    IncidentStatus.RESOLVED: frozenset(
        {
            IncidentStatus.INVESTIGATING,
            IncidentStatus.CLOSED,
        }
    ),
    IncidentStatus.CLOSED: frozenset(),
}


class IncidentTransitionError(ValueError):
    """Raised when an incident lifecycle transition is not permitted."""


def can_transition_incident_status(
    current: IncidentStatus,
    target: IncidentStatus,
) -> bool:
    """Check whether a lifecycle transition is structurally allowed."""
    return target in _ALLOWED_STATUS_TRANSITIONS[current]


@dataclass(frozen=True, slots=True, kw_only=True)
class Incident:
    """Domain representation of a newly reported incident."""

    title: str
    description: str

    incident_id: UUID = field(default_factory=uuid4)
    status: IncidentStatus = field(
        default=IncidentStatus.REPORTED,
        init=False,
    )
    severity: IncidentSeverity = IncidentSeverity.UNCLASSIFIED
    affected_services: tuple[str, ...] = ()

    detected_at: datetime | None = None
    created_at: datetime = field(
        default_factory=lambda: datetime.now(UTC),
    )
    updated_at: datetime = field(
        default_factory=lambda: datetime.now(UTC),
    )
    resolved_at: datetime | None = field(
        default=None,
        init=False,
    )

    def __post_init__(self) -> None:
        """Validate initial incident invariants."""
        if not self.title.strip():
            raise ValueError("Incident title must not be empty.")

        if any(not service.strip() for service in self.affected_services):
            raise ValueError("Affected services must not contain empty names.")

        timestamps = (
            self.detected_at,
            self.created_at,
            self.updated_at,
        )

        for timestamp in timestamps:
            if timestamp is None:
                continue

            if timestamp.utcoffset() != timedelta(0):
                raise ValueError("Incident timestamps must use UTC.")

        if self.updated_at < self.created_at:
            raise ValueError("updated_at must not precede created_at.")

    def transition_to(self, target: IncidentStatus) -> Incident:
        """Return a new incident after an allowed status transition."""
        if not can_transition_incident_status(self.status, target):
            raise IncidentTransitionError(
                f"Transition from {self.status.value} to {target.value} is not allowed."
            )

        if target is IncidentStatus.RESOLVED:
            raise IncidentTransitionError(
                "Resolving an incident requires verified outcome or an authorized human decision."
            )

        transitioned_at = datetime.now(UTC)

        if transitioned_at < self.updated_at:
            raise IncidentTransitionError("Transition time must not precede updated_at.")

        updated_incident = copy(self)
        object.__setattr__(updated_incident, "status", target)
        object.__setattr__(updated_incident, "updated_at", transitioned_at)

        return updated_incident
