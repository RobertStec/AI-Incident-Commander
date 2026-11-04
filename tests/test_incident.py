"""Unit tests for the Incident domain model."""

from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta, timezone
from uuid import UUID

import pytest

from ai_incident_commander.domain.incident import (
    Incident,
    IncidentSeverity,
    IncidentStatus,
    IncidentTransitionError,
    can_transition_incident_status,
)


def test_new_incident_has_expected_defaults() -> None:
    incident = Incident(
        title="Increased HTTP 500 errors",
        description="API errors increased after deployment.",
    )

    assert isinstance(incident.incident_id, UUID)
    assert incident.status is IncidentStatus.REPORTED
    assert incident.severity is IncidentSeverity.UNCLASSIFIED
    assert incident.affected_services == ()
    assert incident.detected_at is None
    assert incident.resolved_at is None
    assert incident.created_at.utcoffset() == timedelta(0)
    assert incident.updated_at >= incident.created_at


def test_incident_accepts_explicit_business_fields() -> None:
    detected_at = datetime(2026, 11, 4, 6, 0, tzinfo=UTC)

    incident = Incident(
        title="Payments API degradation",
        description="Elevated latency and HTTP 500 errors.",
        severity=IncidentSeverity.SEV2,
        affected_services=("payments-api", "postgresql"),
        detected_at=detected_at,
    )

    assert incident.severity is IncidentSeverity.SEV2
    assert incident.affected_services == ("payments-api", "postgresql")
    assert incident.detected_at == detected_at


@pytest.mark.parametrize("title", ["", " ", "\t\n"])
def test_incident_rejects_empty_title(title: str) -> None:
    with pytest.raises(ValueError, match="title must not be empty"):
        Incident(title=title, description="Test incident")


@pytest.mark.parametrize("service", ["", " \t "])
def test_incident_rejects_empty_service_name(service: str) -> None:
    with pytest.raises(ValueError, match="Affected services"):
        Incident(
            title="Test incident",
            description="Test description",
            affected_services=(service,),
        )


@pytest.mark.parametrize(
    "detected_at",
    [
        datetime(2026, 11, 4, 6, 0),
        datetime(
            2026,
            11,
            4,
            6,
            0,
            tzinfo=timezone(timedelta(hours=1)),
        ),
    ],
)
def test_incident_rejects_non_utc_timestamps(
    detected_at: datetime,
) -> None:
    with pytest.raises(ValueError, match="must use UTC"):
        Incident(
            title="Test incident",
            description="Test description",
            detected_at=detected_at,
        )


def test_incident_rejects_updated_at_before_created_at() -> None:
    created_at = datetime(2026, 11, 4, 10, 0, tzinfo=UTC)
    updated_at = created_at - timedelta(seconds=1)

    with pytest.raises(ValueError, match="updated_at must not precede"):
        Incident(
            title="Test incident",
            description="Test description",
            created_at=created_at,
            updated_at=updated_at,
        )


def test_incident_cannot_be_modified_directly() -> None:
    incident = Incident(
        title="Test incident",
        description="Test description",
    )

    field_name = "status"

    with pytest.raises(FrozenInstanceError):
        setattr(incident, field_name, IncidentStatus.RESOLVED)


@pytest.mark.parametrize(
    ("current", "allowed_targets"),
    [
        (
            IncidentStatus.REPORTED,
            frozenset({IncidentStatus.INVESTIGATING}),
        ),
        (
            IncidentStatus.INVESTIGATING,
            frozenset(
                {
                    IncidentStatus.MITIGATING,
                    IncidentStatus.VERIFYING,
                }
            ),
        ),
        (
            IncidentStatus.MITIGATING,
            frozenset(
                {
                    IncidentStatus.INVESTIGATING,
                    IncidentStatus.VERIFYING,
                }
            ),
        ),
        (
            IncidentStatus.VERIFYING,
            frozenset(
                {
                    IncidentStatus.INVESTIGATING,
                    IncidentStatus.RESOLVED,
                }
            ),
        ),
        (
            IncidentStatus.RESOLVED,
            frozenset(
                {
                    IncidentStatus.INVESTIGATING,
                    IncidentStatus.CLOSED,
                }
            ),
        ),
        (
            IncidentStatus.CLOSED,
            frozenset(),
        ),
    ],
)
@pytest.mark.parametrize("target", list(IncidentStatus))
def test_incident_status_transition_matrix(
    current: IncidentStatus,
    allowed_targets: frozenset[IncidentStatus],
    target: IncidentStatus,
) -> None:
    expected = target in allowed_targets

    assert can_transition_incident_status(current, target) is expected


def test_transition_creates_new_incident_without_modifying_original() -> None:
    incident = Incident(
        title="Payments API degradation",
        description="Elevated HTTP 500 errors.",
        severity=IncidentSeverity.SEV2,
        affected_services=("payments-api",),
    )

    transitioned = incident.transition_to(IncidentStatus.INVESTIGATING)

    assert transitioned is not incident
    assert transitioned.status is IncidentStatus.INVESTIGATING
    assert incident.status is IncidentStatus.REPORTED

    assert transitioned.incident_id == incident.incident_id
    assert transitioned.title == incident.title
    assert transitioned.description == incident.description
    assert transitioned.severity == incident.severity
    assert transitioned.affected_services == incident.affected_services
    assert transitioned.created_at == incident.created_at

    assert transitioned.updated_at >= incident.updated_at
    assert incident.resolved_at is None
    assert transitioned.resolved_at is None


def test_transition_supports_valid_workflow_progression() -> None:
    reported = Incident(
        title="API degradation",
        description="Increased latency.",
    )

    investigating = reported.transition_to(IncidentStatus.INVESTIGATING)
    mitigating = investigating.transition_to(IncidentStatus.MITIGATING)
    verifying = mitigating.transition_to(IncidentStatus.VERIFYING)

    assert reported.status is IncidentStatus.REPORTED
    assert investigating.status is IncidentStatus.INVESTIGATING
    assert mitigating.status is IncidentStatus.MITIGATING
    assert verifying.status is IncidentStatus.VERIFYING


@pytest.mark.parametrize(
    "target",
    [
        IncidentStatus.REPORTED,
        IncidentStatus.MITIGATING,
        IncidentStatus.RESOLVED,
        IncidentStatus.CLOSED,
    ],
)
def test_transition_rejects_invalid_status_change(
    target: IncidentStatus,
) -> None:
    incident = Incident(
        title="Test incident",
        description="Test description",
    )

    with pytest.raises(IncidentTransitionError, match="is not allowed"):
        incident.transition_to(target)

    assert incident.status is IncidentStatus.REPORTED


def test_transition_blocks_resolution_without_verification() -> None:
    incident = Incident(
        title="Test incident",
        description="Test description",
    )

    investigating = incident.transition_to(IncidentStatus.INVESTIGATING)
    verifying = investigating.transition_to(IncidentStatus.VERIFYING)

    with pytest.raises(
        IncidentTransitionError,
        match="requires verified outcome",
    ):
        verifying.transition_to(IncidentStatus.RESOLVED)

    assert verifying.status is IncidentStatus.VERIFYING
    assert verifying.resolved_at is None


def test_transition_rejects_timestamp_regression() -> None:
    future_updated_at = datetime.now(UTC) + timedelta(days=1)

    incident = Incident(
        title="Test incident",
        description="Test description",
        updated_at=future_updated_at,
    )

    with pytest.raises(
        IncidentTransitionError,
        match="Transition time must not precede updated_at",
    ):
        incident.transition_to(IncidentStatus.INVESTIGATING)

    assert incident.status is IncidentStatus.REPORTED
    assert incident.updated_at == future_updated_at
