"""Unit tests for checkpoint-safe incident state and parallel evidence reducer."""

import json
from copy import deepcopy
from datetime import UTC, datetime
from typing import Annotated, get_args, get_origin, get_type_hints
from uuid import UUID

import pytest

from ai_incident_commander.domain.evidence import Evidence, EvidenceType
from ai_incident_commander.domain.hypothesis import Hypothesis
from ai_incident_commander.domain.incident import Incident, IncidentSeverity
from ai_incident_commander.orchestration.incident_state import (
    EvidenceSnapshotConflictError,
    IncidentState,
    initial_incident_state,
    merge_evidence,
    snapshot_evidence,
    snapshot_hypothesis,
    snapshot_incident,
)

_INCIDENT_ID = UUID("00000000-0000-0000-0000-000000000010")
_COLLECTED_AT = datetime(2026, 11, 16, 9, 0, tzinfo=UTC)


def _incident() -> Incident:
    return Incident(
        incident_id=_INCIDENT_ID,
        title="API 500 errors",
        description="Error rate increased after deployment",
        severity=IncidentSeverity.SEV2,
        affected_services=("payments-api", "checkout-api"),
        detected_at=_COLLECTED_AT,
        created_at=_COLLECTED_AT,
        updated_at=_COLLECTED_AT,
    )


def _evidence(evidence_id: int = 1) -> Evidence:
    return Evidence(
        evidence_id=UUID(int=evidence_id),
        incident_id=_INCIDENT_ID,
        evidence_type=EvidenceType.METRIC,
        source="prometheus",
        source_reference=f"metric-{evidence_id}",
        summary="HTTP 500 rate increased",
        service_name="payments-api",
        observed_at=_COLLECTED_AT,
        collected_at=_COLLECTED_AT,
        artifact_reference="s3://example/artifact.json",
        content_hash="a" * 64,
        metadata={"error_rate": 0.15, "threshold_exceeded": True, "notes": None},
    )


def _hypothesis() -> Hypothesis:
    return Hypothesis(
        hypothesis_id=UUID(int=9),
        incident_id=_INCIDENT_ID,
        statement="Deployment introduced a regression",
        reasoning="Error rate rose after the latest release",
        created_at=_COLLECTED_AT,
        updated_at=_COLLECTED_AT,
    )


def test_initial_state_preserves_incident_and_starts_without_findings() -> None:
    incident = _incident()

    state = initial_incident_state(incident)

    assert state["workflow_phase"] == "intake"
    assert state["incident"]["incident_id"] == str(incident.incident_id)
    assert state["incident"]["status"] == "reported"
    assert state["incident"]["severity"] == "sev2"
    assert state["incident"]["affected_services"] == ["payments-api", "checkout-api"]
    assert state["evidence"] == []
    assert state["hypotheses"] == []


def test_incident_snapshot_preserves_timestamps_and_optional_fields() -> None:
    snapshot = snapshot_incident(_incident())

    assert snapshot["detected_at"] == "2026-11-16T09:00:00+00:00"
    assert snapshot["created_at"] == "2026-11-16T09:00:00+00:00"
    assert snapshot["resolved_at"] is None


def test_snapshot_incident_does_not_mutate_domain_incident() -> None:
    incident = _incident()
    snapshot = snapshot_incident(incident)
    snapshot["affected_services"].append("other-api")

    assert incident.affected_services == ("payments-api", "checkout-api")


def test_evidence_snapshot_preserves_provenance_and_json_scalars() -> None:
    snapshot = snapshot_evidence(_evidence())

    assert snapshot["evidence_id"] == str(UUID(int=1))
    assert snapshot["incident_id"] == str(_INCIDENT_ID)
    assert snapshot["evidence_type"] == "metric"
    assert snapshot["source"] == "prometheus"
    assert snapshot["source_reference"] == "metric-1"
    assert snapshot["content_hash"] == "a" * 64
    assert snapshot["observed_at"] == "2026-11-16T09:00:00+00:00"
    assert snapshot["metadata"] == {
        "error_rate": 0.15,
        "threshold_exceeded": True,
        "notes": None,
    }


def test_evidence_snapshot_metadata_is_independent_of_domain_object() -> None:
    evidence = _evidence()
    snapshot = snapshot_evidence(evidence)
    snapshot["metadata"]["error_rate"] = 1.0

    assert evidence.metadata["error_rate"] == 0.15


def test_hypothesis_snapshot_preserves_status_and_confidence() -> None:
    snapshot = snapshot_hypothesis(_hypothesis())

    assert snapshot["hypothesis_id"] == str(UUID(int=9))
    assert snapshot["incident_id"] == str(_INCIDENT_ID)
    assert snapshot["statement"] == "Deployment introduced a regression"
    assert snapshot["status"] == "proposed"
    assert snapshot["confidence_level"] == "insufficient_evidence"


def test_all_snapshots_are_json_serializable() -> None:
    state = initial_incident_state(_incident())
    state["evidence"] = [snapshot_evidence(_evidence())]
    state["hypotheses"] = [snapshot_hypothesis(_hypothesis())]

    serialized = json.dumps(state, allow_nan=False)
    restored = json.loads(serialized)

    assert restored == state


def test_parallel_evidence_merges_independent_of_completion_order() -> None:
    first = snapshot_evidence(_evidence(1))
    second = snapshot_evidence(_evidence(2))

    assert merge_evidence([first], [second]) == merge_evidence([second], [first])
    assert len(merge_evidence([first], [second])) == 2


def test_evidence_reducer_is_idempotent_for_replayed_observation() -> None:
    first = snapshot_evidence(_evidence())

    assert merge_evidence([first], [deepcopy(first)]) == [first]
    assert merge_evidence([], [first, first]) == [first]


def test_evidence_reducer_detects_conflicting_same_id() -> None:
    first = snapshot_evidence(_evidence())
    changed = deepcopy(first)
    changed["summary"] = "Different measurement"

    with pytest.raises(EvidenceSnapshotConflictError, match="Conflicting evidence snapshots"):
        merge_evidence([first], [changed])


def test_evidence_reducer_is_associative_for_nonconflicting_updates() -> None:
    first = snapshot_evidence(_evidence(1))
    second = snapshot_evidence(_evidence(2))
    third = snapshot_evidence(_evidence(3))

    left = merge_evidence(merge_evidence([first], [second]), [third])
    right = merge_evidence([first], merge_evidence([second], [third]))

    assert left == right


def test_evidence_reducer_does_not_mutate_inputs() -> None:
    first = snapshot_evidence(_evidence(1))
    second = snapshot_evidence(_evidence(2))
    before = deepcopy([first, second])

    output = merge_evidence([first], [second])
    output[0]["metadata"]["error_rate"] = 0.5

    assert [first, second] == before


def test_empty_reducer_returns_a_distinct_list() -> None:
    existing = []
    result = merge_evidence(existing, [])
    assert result == []
    assert result is not existing


def test_state_defines_evidence_reducer_but_not_hypothesis_reducer() -> None:
    hints = get_type_hints(IncidentState, include_extras=True)

    assert get_origin(hints["evidence"]) is Annotated
    assert get_args(hints["evidence"])[1] is merge_evidence
    assert get_origin(hints["hypotheses"]) is list
