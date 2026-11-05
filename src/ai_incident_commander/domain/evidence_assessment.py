"""Evidence assessment domain model and relationship types."""

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from uuid import UUID, uuid4


class EvidenceRelation(StrEnum):
    """Relationship between evidence and an incident hypothesis."""

    SUPPORTS = "supports"
    REFUTES = "refutes"
    NEUTRAL = "neutral"


@dataclass(frozen=True, slots=True, kw_only=True)
class EvidenceAssessment:
    """Immutable assessment of evidence against a hypothesis."""

    hypothesis_id: UUID
    evidence_id: UUID
    relation: EvidenceRelation
    reasoning: str
    assessor: str

    assessment_id: UUID = field(default_factory=uuid4)
    assessed_at: datetime = field(
        default_factory=lambda: datetime.now(UTC),
    )

    def __post_init__(self) -> None:
        """Validate evidence assessment invariants."""
        if not self.reasoning.strip():
            raise ValueError("Evidence assessment reasoning must not be empty.")

        if not self.assessor.strip():
            raise ValueError("Evidence assessment assessor must not be empty.")

        if self.assessed_at.utcoffset() != timedelta(0):
            raise ValueError("Evidence assessment timestamps must use UTC.")
