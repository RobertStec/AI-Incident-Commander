"""Evidence domain models and provenance types."""

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from math import isfinite
from re import fullmatch
from types import MappingProxyType
from uuid import UUID, uuid4


class EvidenceType(StrEnum):
    """Categories of evidence collected during incident investigation."""

    METRIC = "metric"
    LOG = "log"
    TRACE = "trace"
    DEPLOYMENT = "deployment"
    CODE_CHANGE = "code_change"
    INCIDENT_RECORD = "incident_record"
    MANUAL_OBSERVATION = "manual_observation"


type EvidenceMetadataValue = str | int | float | bool | None


@dataclass(frozen=True, slots=True, kw_only=True)
class Evidence:
    """Immutable evidence collected during incident investigation."""

    incident_id: UUID
    evidence_type: EvidenceType
    source: str
    source_reference: str
    summary: str

    evidence_id: UUID = field(default_factory=uuid4)
    service_name: str | None = None
    observed_at: datetime | None = None
    collected_at: datetime = field(
        default_factory=lambda: datetime.now(UTC),
    )
    artifact_reference: str | None = None
    content_hash: str | None = None
    metadata: Mapping[str, EvidenceMetadataValue] = field(
        default_factory=dict,
        hash=False,
    )

    def __post_init__(self) -> None:
        """Validate evidence identity and provenance invariants."""
        required_fields = {
            "source": self.source,
            "source_reference": self.source_reference,
            "summary": self.summary,
        }

        for field_name, value in required_fields.items():
            if not value.strip():
                raise ValueError(f"Evidence {field_name} must not be empty.")

        if self.service_name is not None:
            if not self.service_name.strip():
                raise ValueError("Evidence service_name must not be empty.")

        for timestamp in (self.observed_at, self.collected_at):
            if timestamp is None:
                continue

            if timestamp.utcoffset() != timedelta(0):
                raise ValueError("Evidence timestamps must use UTC.")

        if self.artifact_reference is not None:
            if not self.artifact_reference.strip():
                raise ValueError("Evidence artifact_reference must not be empty.")

        if self.content_hash is not None:
            if fullmatch(r"[0-9a-f]{64}", self.content_hash) is None:
                raise ValueError(
                    "Evidence content_hash must be a lowercase SHA-256 hexadecimal digest."
                )

        for key, metadata_value in self.metadata.items():
            if not isinstance(key, str) or not key.strip():
                raise ValueError("Evidence metadata keys must be non-empty strings.")

            if metadata_value is not None and not isinstance(
                metadata_value, (str, int, float, bool)
            ):
                raise ValueError("Evidence metadata values must be JSON scalars.")

            if isinstance(metadata_value, float) and not isfinite(metadata_value):
                raise ValueError("Evidence metadata numbers must be finite.")

        object.__setattr__(
            self,
            "metadata",
            MappingProxyType(dict(self.metadata)),
        )
