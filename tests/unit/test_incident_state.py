"""Unit tests for checkpoint-safe incident state and parallel evidence reducer."""

import json
from copy import deepcopy
from datetime import UTC, datetime
from typing import Annotated, NotRequired, cast, get_args, get_origin, get_type_hints
from uuid import UUID

import pytest

from ai_incident_commander.domain.evidence import Evidence, EvidenceType
from ai_incident_commander.domain.hypothesis import Hypothesis
from ai_incident_commander.domain.incident import Incident, IncidentSeverity
from ai_incident_commander.orchestration.incident_state import (
    AnalysisReviewOutcome,
    EvidenceSnapshotConflictError,
    IncidentState,
    InvestigationSource,
    InvestigatorState,
    create_analysis_review,
    create_investigation_plan,
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
    assert state["investigation_plan"] is None
    assert state["incident"]["incident_id"] == str(incident.incident_id)
    assert state["incident"]["status"] == "reported"
    assert state["incident"]["severity"] == "sev2"
    assert state["incident"]["affected_services"] == ["payments-api", "checkout-api"]
    assert state["evidence"] == []
    assert state["hypotheses"] == []
    assert state["analysis_review"] is None


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
    state["investigation_plan"] = create_investigation_plan(
        sources=["logs", "metrics"], rationale="Investigate API error rate."
    )
    state["analysis_review"] = create_analysis_review(
        outcome="needs_follow_up", note="Investigate the latest deployment."
    )

    serialized = json.dumps(state, allow_nan=False)
    restored = json.loads(serialized)

    assert restored == state


def test_investigation_plan_keeps_source_order_and_copies_input() -> None:
    sources: list[InvestigationSource] = ["metrics", "logs"]
    plan = create_investigation_plan(sources=sources, rationale="Check latency first.")
    sources.clear()

    assert plan == {"sources": ["metrics", "logs"], "rationale": "Check latency first."}


def test_investigation_plan_rejects_empty_sources() -> None:
    with pytest.raises(ValueError, match="at least one source"):
        create_investigation_plan(sources=[], rationale="Investigate errors.")


def test_investigation_plan_rejects_duplicate_sources() -> None:
    with pytest.raises(ValueError, match="must be unique"):
        create_investigation_plan(sources=["logs", "logs"], rationale="Investigate errors.")


def test_investigation_plan_rejects_unknown_source_at_runtime() -> None:
    unknown = cast("InvestigationSource", "deployments")
    with pytest.raises(ValueError, match="unsupported source"):
        create_investigation_plan(sources=[unknown], rationale="Investigate errors.")


def test_investigation_plan_requires_nonblank_rationale() -> None:
    with pytest.raises(ValueError, match="must not be blank"):
        create_investigation_plan(sources=["logs"], rationale="  ")


def test_analysis_review_acknowledgement_does_not_require_a_note() -> None:
    review = create_analysis_review(outcome="acknowledged")

    assert review == {"outcome": "acknowledged", "note": None}
    assert "approved" not in review  # Review does not grant remediation authorization.


def test_analysis_review_follow_up_requires_a_note() -> None:
    with pytest.raises(ValueError, match="requires a note"):
        create_analysis_review(outcome="needs_follow_up")


def test_analysis_review_normalizes_notes_for_both_outcomes() -> None:
    for outcome in ("acknowledged", "needs_follow_up"):
        review = create_analysis_review(outcome=outcome, note="  Check deployment diff.  ")

        assert review == {"outcome": outcome, "note": "Check deployment diff."}


@pytest.mark.parametrize("outcome", ["approved", "rejected", "unknown"])
def test_analysis_review_rejects_unsupported_outcomes(outcome: str) -> None:
    invalid_outcome = cast("AnalysisReviewOutcome", outcome)

    with pytest.raises(ValueError, match="Unsupported analysis review outcome"):
        create_analysis_review(outcome=invalid_outcome)


@pytest.mark.parametrize("note", ["", "   ", "\t\n"])
def test_analysis_review_rejects_blank_notes(note: str) -> None:
    with pytest.raises(ValueError, match="must not be blank"):
        create_analysis_review(outcome="acknowledged", note=note)


def test_analysis_review_rejects_non_text_notes_at_runtime() -> None:
    invalid_note = cast("str | None", 42)

    with pytest.raises(ValueError, match="must be text or None"):
        create_analysis_review(outcome="acknowledged", note=invalid_note)


def test_analysis_review_enforces_note_length_boundary() -> None:
    within_limit = create_analysis_review(outcome="needs_follow_up", note="a" * 2000)
    assert len(within_limit["note"] or "") == 2000

    with pytest.raises(ValueError, match="must not exceed 2000 characters"):
        create_analysis_review(outcome="needs_follow_up", note="a" * 2001)


def test_analysis_review_snapshot_is_json_serializable() -> None:
    review = create_analysis_review(outcome="needs_follow_up", note="Collect further metrics.")

    assert json.loads(json.dumps(review, allow_nan=False)) == review


def test_legacy_incident_state_without_analysis_review_remains_readable() -> None:
    # Historical checkpoints may have been written before the new optional channel.
    legacy_state = dict(initial_incident_state(_incident()))
    del legacy_state["analysis_review"]

    assert legacy_state.get("analysis_review") is None
    assert json.loads(json.dumps(legacy_state, allow_nan=False)) == legacy_state


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
    assert get_origin(hints["investigation_plan"]) is not Annotated


def test_investigator_state_has_only_diagnostic_channels() -> None:
    hints = get_type_hints(InvestigatorState, include_extras=True)

    assert set(hints) == {
        "incident",
        "workflow_phase",
        "investigation_plan",
        "evidence",
    }
    assert InvestigatorState.__required_keys__ == frozenset(hints)
    assert "hypotheses" not in hints
    assert "analysis_review" not in hints


def test_incident_state_extends_investigator_channels_without_redefinition() -> None:
    investigator_hints = get_type_hints(InvestigatorState, include_extras=True)
    incident_hints = get_type_hints(IncidentState, include_extras=True)

    assert set(incident_hints) == {*investigator_hints, "hypotheses", "analysis_review"}
    assert IncidentState.__required_keys__ == frozenset({*investigator_hints, "hypotheses"})
    assert IncidentState.__optional_keys__ == frozenset({"analysis_review"})
    assert get_origin(incident_hints["analysis_review"]) is NotRequired
    assert get_origin(incident_hints["investigation_plan"]) is not Annotated
    for field, annotation in investigator_hints.items():
        assert incident_hints[field] == annotation


def test_investigator_state_inherits_the_evidence_reducer() -> None:
    hints = get_type_hints(InvestigatorState, include_extras=True)

    assert get_origin(hints["evidence"]) is Annotated
    assert get_args(hints["evidence"])[1] is merge_evidence
    assert get_origin(hints["investigation_plan"]) is not Annotated


def test_investigator_projection_is_json_safe_and_does_not_expose_hypotheses() -> None:
    parent = initial_incident_state(_incident())
    parent["investigation_plan"] = create_investigation_plan(
        sources=["logs"], rationale="Examine request failures."
    )
    parent["evidence"] = [snapshot_evidence(_evidence())]
    parent["hypotheses"] = [snapshot_hypothesis(_hypothesis())]
    parent["analysis_review"] = create_analysis_review(outcome="acknowledged")

    # The projection is explicit here; parent/subgraph wiring comes in 2.0.5.3.
    diagnostic = InvestigatorState(
        incident=deepcopy(parent["incident"]),
        workflow_phase=parent["workflow_phase"],
        investigation_plan=deepcopy(parent["investigation_plan"]),
        evidence=deepcopy(parent["evidence"]),
    )

    assert "hypotheses" not in diagnostic
    assert "analysis_review" not in diagnostic
    assert json.loads(json.dumps(diagnostic, allow_nan=False)) == diagnostic
    diagnostic["evidence"][0]["metadata"]["error_rate"] = 0.5
    assert parent["evidence"][0]["metadata"]["error_rate"] == 0.15
