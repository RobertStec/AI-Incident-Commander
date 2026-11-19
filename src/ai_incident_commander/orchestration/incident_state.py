"""Checkpoint-friendly state contract for the future LangGraph incident graph.

Domain objects own business invariants; this module only snapshots them into
JSON-compatible data and defines safe merging for parallel evidence branches.
"""

from copy import deepcopy
from datetime import datetime
from typing import Annotated, Literal, NotRequired, TypedDict

from ai_incident_commander.domain.evidence import Evidence, EvidenceMetadataValue
from ai_incident_commander.domain.hypothesis import Hypothesis
from ai_incident_commander.domain.incident import Incident

type WorkflowPhase = Literal[
    "intake",
    "planning",
    "collecting_evidence",
    "analyzing",
    "awaiting_approval",
    "verifying",
    "reporting",
    "complete",
]


type InvestigationSource = Literal["logs", "metrics"]


type AnalysisReviewOutcome = Literal["acknowledged", "needs_follow_up"]


class AnalysisReviewSnapshot(TypedDict):
    """Untrusted diagnostic feedback, never a remediation approval."""

    outcome: AnalysisReviewOutcome
    note: str | None


def create_analysis_review(
    *, outcome: AnalysisReviewOutcome, note: str | None = None
) -> AnalysisReviewSnapshot:
    """Validate checkpoint-safe human feedback before writing graph state.

    This is not an authorization decision. The authenticated operator identity
    and any remediation approval remain outside the orchestration state.
    """
    if outcome not in ("acknowledged", "needs_follow_up"):
        raise ValueError("Unsupported analysis review outcome.")
    if note is not None:
        if not isinstance(note, str):
            raise ValueError("Analysis review note must be text or None.")
        note = note.strip()
        if not note:
            raise ValueError("Analysis review note must not be blank.")
        if len(note) > 2000:
            raise ValueError("Analysis review note must not exceed 2000 characters.")
    if outcome == "needs_follow_up" and note is None:
        raise ValueError("Follow-up review requires a note.")
    return AnalysisReviewSnapshot(outcome=outcome, note=note)


class InvestigationPlanSnapshot(TypedDict):
    """Checkpoint-friendly, single-writer diagnostic plan."""

    sources: list[InvestigationSource]
    rationale: str


def create_investigation_plan(
    *, sources: list[InvestigationSource], rationale: str
) -> InvestigationPlanSnapshot:
    """Validate source selection before accepting a plan into graph state.

    Keep the caller's source order and explanation; copy the mutable list.
    """
    if not sources:
        raise ValueError("Investigation plan must include at least one source.")
    if any(source not in ("logs", "metrics") for source in sources):
        raise ValueError("Investigation plan contains an unsupported source.")
    if len(set(sources)) != len(sources):
        raise ValueError("Investigation plan sources must be unique.")
    if not rationale.strip():
        raise ValueError("Investigation plan rationale must not be blank.")
    return InvestigationPlanSnapshot(sources=list(sources), rationale=rationale)


class IncidentSnapshot(TypedDict):
    """Serialized incident information, not a mutable domain aggregate."""

    incident_id: str
    title: str
    description: str
    status: str
    severity: str
    affected_services: list[str]
    detected_at: str | None
    created_at: str
    updated_at: str
    resolved_at: str | None


class EvidenceSnapshot(TypedDict):
    """JSON-compatible evidence with its source and provenance preserved."""

    evidence_id: str
    incident_id: str
    evidence_type: str
    source: str
    source_reference: str
    summary: str
    service_name: str | None
    observed_at: str | None
    collected_at: str
    artifact_reference: str | None
    content_hash: str | None
    metadata: dict[str, EvidenceMetadataValue]


class HypothesisSnapshot(TypedDict):
    """Serialized hypothesis; transitions still belong to the domain layer."""

    hypothesis_id: str
    incident_id: str
    statement: str
    reasoning: str
    status: str
    confidence_level: str
    created_at: str
    updated_at: str


class EvidenceSnapshotConflictError(ValueError):
    """The same evidence ID was supplied with different contents."""


def merge_evidence(
    current: list[EvidenceSnapshot], updates: list[EvidenceSnapshot]
) -> list[EvidenceSnapshot]:
    """Idempotently union evidence by stable ID, rejecting conflicting versions.

    Sorted output ensures that parallel branch completion order does not alter
    checkpoint contents. Inputs and their nested metadata remain unmodified.
    Producers must retain the same evidence_id when replaying an observation.
    """
    indexed: dict[str, EvidenceSnapshot] = {}
    for item in (*current, *updates):
        evidence_id = item["evidence_id"]
        previous = indexed.get(evidence_id)
        if previous is not None and previous != item:
            raise EvidenceSnapshotConflictError(
                f"Conflicting evidence snapshots for evidence_id={evidence_id}."
            )
        indexed[evidence_id] = item

    return [deepcopy(indexed[evidence_id]) for evidence_id in sorted(indexed)]


class InvestigatorState(TypedDict):
    """Shared diagnostic channels for the coordinator and investigator subgraph.

    Evidence uses the same idempotent reducer on both sides of the graph boundary.
    Subgraph execution and cross-graph updates are verified separately.
    """

    incident: IncidentSnapshot
    workflow_phase: WorkflowPhase
    investigation_plan: InvestigationPlanSnapshot | None
    evidence: Annotated[list[EvidenceSnapshot], merge_evidence]


class IncidentState(InvestigatorState):
    """Coordinator state: diagnostic channels plus downstream hypotheses.

    Hypotheses remain single-writer until a domain-safe update policy is defined.
    """

    hypotheses: list[HypothesisSnapshot]
    # Older checkpoints may omit this key; consumers must use state.get().
    analysis_review: NotRequired[AnalysisReviewSnapshot | None]


def _optional_datetime(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


def snapshot_incident(incident: Incident) -> IncidentSnapshot:
    """Preserve the domain incident without placing a dataclass in checkpoints."""
    return IncidentSnapshot(
        incident_id=str(incident.incident_id),
        title=incident.title,
        description=incident.description,
        status=incident.status.value,
        severity=incident.severity.value,
        affected_services=list(incident.affected_services),
        detected_at=_optional_datetime(incident.detected_at),
        created_at=incident.created_at.isoformat(),
        updated_at=incident.updated_at.isoformat(),
        resolved_at=_optional_datetime(incident.resolved_at),
    )


def snapshot_evidence(evidence: Evidence) -> EvidenceSnapshot:
    """Copy provenance and plain JSON metadata from validated domain evidence."""
    return EvidenceSnapshot(
        evidence_id=str(evidence.evidence_id),
        incident_id=str(evidence.incident_id),
        evidence_type=evidence.evidence_type.value,
        source=evidence.source,
        source_reference=evidence.source_reference,
        summary=evidence.summary,
        service_name=evidence.service_name,
        observed_at=_optional_datetime(evidence.observed_at),
        collected_at=evidence.collected_at.isoformat(),
        artifact_reference=evidence.artifact_reference,
        content_hash=evidence.content_hash,
        metadata=dict(evidence.metadata),
    )


def snapshot_hypothesis(hypothesis: Hypothesis) -> HypothesisSnapshot:
    """Serialize a domain-validated hypothesis without changing its lifecycle."""
    return HypothesisSnapshot(
        hypothesis_id=str(hypothesis.hypothesis_id),
        incident_id=str(hypothesis.incident_id),
        statement=hypothesis.statement,
        reasoning=hypothesis.reasoning,
        status=hypothesis.status.value,
        confidence_level=hypothesis.confidence_level.value,
        created_at=hypothesis.created_at.isoformat(),
        updated_at=hypothesis.updated_at.isoformat(),
    )


def initial_incident_state(incident: Incident) -> IncidentState:
    """Initialize a new orchestration run from a trusted domain Incident."""
    return IncidentState(
        incident=snapshot_incident(incident),
        workflow_phase="intake",
        investigation_plan=None,
        evidence=[],
        hypotheses=[],
        analysis_review=None,
    )
