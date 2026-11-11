"""Unit tests for the Evidence domain model."""

from collections.abc import Mapping, MutableMapping
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta, timezone
from typing import cast
from uuid import UUID, uuid4

import pytest

from ai_incident_commander.domain.evidence import (
    Evidence,
    EvidenceMetadataValue,
    EvidenceType,
)


def test_evidence_types_match_domain_contract() -> None:
    assert {evidence_type.value for evidence_type in EvidenceType} == {
        "metric",
        "log",
        "trace",
        "deployment",
        "code_change",
        "incident_record",
        "manual_observation",
    }


def test_new_evidence_has_expected_defaults() -> None:
    incident_id = uuid4()

    evidence = Evidence(
        incident_id=incident_id,
        evidence_type=EvidenceType.METRIC,
        source="observability-mcp",
        source_reference="query-001",
        summary="HTTP 500 error rate increased to 18%.",
    )

    assert isinstance(evidence.evidence_id, UUID)
    assert evidence.incident_id == incident_id
    assert evidence.evidence_type is EvidenceType.METRIC
    assert evidence.source == "observability-mcp"
    assert evidence.source_reference == "query-001"
    assert evidence.service_name is None
    assert evidence.observed_at is None
    assert evidence.collected_at.utcoffset() == timedelta(0)


def test_evidence_accepts_explicit_fields() -> None:
    evidence_id = uuid4()
    observed_at = datetime(2026, 11, 4, 8, 0, tzinfo=UTC)
    collected_at = datetime(2026, 11, 4, 8, 5, tzinfo=UTC)

    evidence = Evidence(
        evidence_id=evidence_id,
        incident_id=uuid4(),
        evidence_type=EvidenceType.LOG,
        source="logs-mcp",
        source_reference="log-entry-123",
        summary="Database connection timeout.",
        service_name="payments-api",
        observed_at=observed_at,
        collected_at=collected_at,
    )

    assert evidence.evidence_id == evidence_id
    assert evidence.service_name == "payments-api"
    assert evidence.observed_at == observed_at
    assert evidence.collected_at == collected_at


def test_evidence_generates_unique_identifiers() -> None:
    incident_id = uuid4()

    first = Evidence(
        incident_id=incident_id,
        evidence_type=EvidenceType.LOG,
        source="logs-mcp",
        source_reference="entry-1",
        summary="First log entry.",
    )

    second = Evidence(
        incident_id=incident_id,
        evidence_type=EvidenceType.LOG,
        source="logs-mcp",
        source_reference="entry-2",
        summary="Second log entry.",
    )

    assert first.evidence_id != second.evidence_id


@pytest.mark.parametrize(
    ("source", "source_reference", "summary"),
    [
        ("", "query-001", "Metric increased."),
        (" \t ", "query-001", "Metric increased."),
        ("observability-mcp", "", "Metric increased."),
        ("observability-mcp", " \t ", "Metric increased."),
        ("observability-mcp", "query-001", ""),
        ("observability-mcp", "query-001", " \n "),
    ],
)
def test_evidence_rejects_empty_required_fields(
    source: str,
    source_reference: str,
    summary: str,
) -> None:
    with pytest.raises(ValueError, match="must not be empty"):
        Evidence(
            incident_id=uuid4(),
            evidence_type=EvidenceType.METRIC,
            source=source,
            source_reference=source_reference,
            summary=summary,
        )


@pytest.mark.parametrize("service_name", ["", " \t "])
def test_evidence_rejects_empty_service_name(
    service_name: str,
) -> None:
    with pytest.raises(ValueError, match="service_name must not be empty"):
        Evidence(
            incident_id=uuid4(),
            evidence_type=EvidenceType.METRIC,
            source="observability-mcp",
            source_reference="query-001",
            summary="Metric increased.",
            service_name=service_name,
        )


@pytest.mark.parametrize(
    "timestamp",
    [
        datetime(2026, 11, 4, 8, 0),
        datetime(
            2026,
            11,
            4,
            9,
            0,
            tzinfo=timezone(timedelta(hours=1)),
        ),
    ],
)
@pytest.mark.parametrize("timestamp_field", ["observed_at", "collected_at"])
def test_evidence_rejects_non_utc_timestamps(
    timestamp: datetime,
    timestamp_field: str,
) -> None:
    incident_id = uuid4()

    with pytest.raises(ValueError, match="timestamps must use UTC"):
        if timestamp_field == "observed_at":
            Evidence(
                incident_id=incident_id,
                evidence_type=EvidenceType.METRIC,
                source="observability-mcp",
                source_reference="query-001",
                summary="Metric increased.",
                observed_at=timestamp,
            )
        else:
            Evidence(
                incident_id=incident_id,
                evidence_type=EvidenceType.METRIC,
                source="observability-mcp",
                source_reference="query-001",
                summary="Metric increased.",
                collected_at=timestamp,
            )


def test_evidence_cannot_be_modified_directly() -> None:
    evidence = Evidence(
        incident_id=uuid4(),
        evidence_type=EvidenceType.METRIC,
        source="observability-mcp",
        source_reference="query-001",
        summary="Original observation.",
    )

    field_name = "summary"

    with pytest.raises(FrozenInstanceError):
        setattr(evidence, field_name, "Modified observation.")

    assert evidence.summary == "Original observation."


def test_evidence_accepts_provenance_fields() -> None:
    evidence = Evidence(
        incident_id=uuid4(),
        evidence_type=EvidenceType.METRIC,
        source="observability-mcp",
        source_reference="query-001",
        summary="Elevated error rate.",
        artifact_reference="artifacts/query-001.json",
        content_hash="a" * 64,
        metadata={
            "environment": "incident-lab",
            "sample_count": 1500,
            "error_rate": 18.0,
            "verified": True,
            "optional": None,
        },
    )

    assert evidence.artifact_reference == "artifacts/query-001.json"
    assert evidence.content_hash == "a" * 64
    assert dict(evidence.metadata) == {
        "environment": "incident-lab",
        "sample_count": 1500,
        "error_rate": 18.0,
        "verified": True,
        "optional": None,
    }


@pytest.mark.parametrize("artifact_reference", ["", " \t "])
def test_evidence_rejects_empty_artifact_reference(
    artifact_reference: str,
) -> None:
    with pytest.raises(
        ValueError,
        match="artifact_reference must not be empty",
    ):
        Evidence(
            incident_id=uuid4(),
            evidence_type=EvidenceType.LOG,
            source="logs-mcp",
            source_reference="log-001",
            summary="Error logged.",
            artifact_reference=artifact_reference,
        )


@pytest.mark.parametrize(
    "content_hash",
    ["", "a" * 63, "A" * 64, "g" * 64],
)
def test_evidence_rejects_invalid_content_hash(
    content_hash: str,
) -> None:
    with pytest.raises(
        ValueError,
        match="content_hash must be a lowercase SHA-256",
    ):
        Evidence(
            incident_id=uuid4(),
            evidence_type=EvidenceType.METRIC,
            source="observability-mcp",
            source_reference="query-001",
            summary="Elevated error rate.",
            content_hash=content_hash,
        )


@pytest.mark.parametrize("metadata_key", ["", " \t "])
def test_evidence_rejects_empty_metadata_key(
    metadata_key: str,
) -> None:
    with pytest.raises(
        ValueError,
        match="metadata keys must be non-empty strings",
    ):
        Evidence(
            incident_id=uuid4(),
            evidence_type=EvidenceType.LOG,
            source="logs-mcp",
            source_reference="log-001",
            summary="Error logged.",
            metadata={metadata_key: "production"},
        )


def test_evidence_rejects_non_string_metadata_key() -> None:
    invalid_metadata = cast(
        Mapping[str, EvidenceMetadataValue],
        {123: "production"},
    )

    with pytest.raises(
        ValueError,
        match="metadata keys must be non-empty strings",
    ):
        Evidence(
            incident_id=uuid4(),
            evidence_type=EvidenceType.LOG,
            source="logs-mcp",
            source_reference="log-001",
            summary="Error logged.",
            metadata=invalid_metadata,
        )


@pytest.mark.parametrize(
    "invalid_value",
    [["nested"], {"nested": "value"}],
)
def test_evidence_rejects_nested_metadata(
    invalid_value: object,
) -> None:
    with pytest.raises(
        ValueError,
        match="metadata values must be JSON scalars",
    ):
        Evidence(
            incident_id=uuid4(),
            evidence_type=EvidenceType.METRIC,
            source="observability-mcp",
            source_reference="query-001",
            summary="Elevated error rate.",
            metadata={
                "invalid": cast(EvidenceMetadataValue, invalid_value),
            },
        )


@pytest.mark.parametrize(
    "invalid_value",
    [float("nan"), float("inf"), float("-inf")],
)
def test_evidence_rejects_non_finite_metadata_numbers(
    invalid_value: float,
) -> None:
    with pytest.raises(
        ValueError,
        match="metadata numbers must be finite",
    ):
        Evidence(
            incident_id=uuid4(),
            evidence_type=EvidenceType.METRIC,
            source="observability-mcp",
            source_reference="query-001",
            summary="Elevated error rate.",
            metadata={"error_rate": invalid_value},
        )


def test_evidence_metadata_is_read_only() -> None:
    evidence = Evidence(
        incident_id=uuid4(),
        evidence_type=EvidenceType.METRIC,
        source="observability-mcp",
        source_reference="query-001",
        summary="Elevated error rate.",
        metadata={"environment": "production"},
    )

    mutable_view = cast(
        MutableMapping[str, EvidenceMetadataValue],
        evidence.metadata,
    )

    with pytest.raises(TypeError):
        mutable_view["environment"] = "staging"

    assert evidence.metadata["environment"] == "production"


def test_evidence_copies_input_metadata() -> None:
    supplied_metadata = {"environment": "production"}

    evidence = Evidence(
        incident_id=uuid4(),
        evidence_type=EvidenceType.METRIC,
        source="observability-mcp",
        source_reference="query-001",
        summary="Elevated error rate.",
        metadata=supplied_metadata,
    )

    supplied_metadata["environment"] = "staging"
    supplied_metadata["new_field"] = "untrusted"

    assert dict(evidence.metadata) == {
        "environment": "production",
    }
