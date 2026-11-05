"""Unit tests for the EvidenceAssessment domain model."""

from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta, timezone
from uuid import UUID, uuid4

import pytest

from ai_incident_commander.domain.evidence_assessment import (
    EvidenceAssessment,
    EvidenceRelation,
)


def test_evidence_relations_match_domain_contract() -> None:
    assert {relation.value for relation in EvidenceRelation} == {
        "supports",
        "refutes",
        "neutral",
    }


@pytest.mark.parametrize("relation", list(EvidenceRelation))
def test_assessment_accepts_all_evidence_relations(
    relation: EvidenceRelation,
) -> None:
    hypothesis_id = uuid4()
    evidence_id = uuid4()

    assessment = EvidenceAssessment(
        hypothesis_id=hypothesis_id,
        evidence_id=evidence_id,
        relation=relation,
        reasoning="Assessment based on collected evidence.",
        assessor="investigator-agent",
    )

    assert isinstance(assessment.assessment_id, UUID)
    assert assessment.hypothesis_id == hypothesis_id
    assert assessment.evidence_id == evidence_id
    assert assessment.relation is relation
    assert assessment.reasoning == "Assessment based on collected evidence."
    assert assessment.assessor == "investigator-agent"
    assert assessment.assessed_at.utcoffset() == timedelta(0)


def test_assessment_accepts_explicit_identity_and_timestamp() -> None:
    assessment_id = uuid4()
    assessed_at = datetime(2026, 11, 5, 8, 0, tzinfo=UTC)

    assessment = EvidenceAssessment(
        assessment_id=assessment_id,
        hypothesis_id=uuid4(),
        evidence_id=uuid4(),
        relation=EvidenceRelation.NEUTRAL,
        reasoning="Evidence does not distinguish between hypotheses.",
        assessor="incident-operator",
        assessed_at=assessed_at,
    )

    assert assessment.assessment_id == assessment_id
    assert assessment.assessed_at == assessed_at
    assert assessment.relation is EvidenceRelation.NEUTRAL


def test_assessments_generate_distinct_identifiers() -> None:
    hypothesis_id = uuid4()
    evidence_id = uuid4()

    first = EvidenceAssessment(
        hypothesis_id=hypothesis_id,
        evidence_id=evidence_id,
        relation=EvidenceRelation.SUPPORTS,
        reasoning="Initial assessment.",
        assessor="investigator-agent",
    )

    second = EvidenceAssessment(
        hypothesis_id=hypothesis_id,
        evidence_id=evidence_id,
        relation=EvidenceRelation.REFUTES,
        reasoning="Reassessment after additional investigation.",
        assessor="incident-operator",
    )

    assert first.assessment_id != second.assessment_id
    assert first.hypothesis_id == second.hypothesis_id
    assert first.evidence_id == second.evidence_id


@pytest.mark.parametrize("reasoning", ["", " ", "\t\n"])
def test_assessment_rejects_empty_reasoning(reasoning: str) -> None:
    with pytest.raises(ValueError, match="reasoning must not be empty"):
        EvidenceAssessment(
            hypothesis_id=uuid4(),
            evidence_id=uuid4(),
            relation=EvidenceRelation.SUPPORTS,
            reasoning=reasoning,
            assessor="investigator-agent",
        )


@pytest.mark.parametrize("assessor", ["", " ", "\t\n"])
def test_assessment_rejects_empty_assessor(assessor: str) -> None:
    with pytest.raises(ValueError, match="assessor must not be empty"):
        EvidenceAssessment(
            hypothesis_id=uuid4(),
            evidence_id=uuid4(),
            relation=EvidenceRelation.SUPPORTS,
            reasoning="Evidence supports the hypothesis.",
            assessor=assessor,
        )


@pytest.mark.parametrize(
    "assessed_at",
    [
        datetime(2026, 11, 5, 8, 0),
        datetime(
            2026,
            11,
            5,
            9,
            0,
            tzinfo=timezone(timedelta(hours=1)),
        ),
    ],
)
def test_assessment_rejects_non_utc_timestamp(
    assessed_at: datetime,
) -> None:
    with pytest.raises(ValueError, match="timestamps must use UTC"):
        EvidenceAssessment(
            hypothesis_id=uuid4(),
            evidence_id=uuid4(),
            relation=EvidenceRelation.SUPPORTS,
            reasoning="Evidence supports the hypothesis.",
            assessor="investigator-agent",
            assessed_at=assessed_at,
        )


def test_assessment_cannot_be_modified_directly() -> None:
    assessment = EvidenceAssessment(
        hypothesis_id=uuid4(),
        evidence_id=uuid4(),
        relation=EvidenceRelation.SUPPORTS,
        reasoning="Initial assessment.",
        assessor="investigator-agent",
    )

    field_name = "relation"

    with pytest.raises(FrozenInstanceError):
        setattr(assessment, field_name, EvidenceRelation.REFUTES)

    assert assessment.relation is EvidenceRelation.SUPPORTS
