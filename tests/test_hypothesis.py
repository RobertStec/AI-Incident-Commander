"""Unit tests for the Hypothesis domain model."""

from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta, timezone
from uuid import UUID, uuid4

import pytest

from ai_incident_commander.domain.hypothesis import (
    Hypothesis,
    HypothesisConfidenceLevel,
    HypothesisStatus,
    HypothesisTransitionError,
    can_transition_hypothesis_status,
)


def test_hypothesis_enums_match_domain_contract() -> None:
    assert {status.value for status in HypothesisStatus} == {
        "proposed",
        "under_evaluation",
        "supported",
        "confirmed",
        "rejected",
    }

    assert {level.value for level in HypothesisConfidenceLevel} == {
        "insufficient_evidence",
        "low",
        "medium",
        "high",
    }


def test_new_hypothesis_has_expected_defaults() -> None:
    incident_id = uuid4()

    hypothesis = Hypothesis(
        incident_id=incident_id,
        statement="Connection pool exhaustion caused HTTP 500 errors.",
        reasoning="Timeouts increased after deployment.",
    )

    assert isinstance(hypothesis.hypothesis_id, UUID)
    assert hypothesis.incident_id == incident_id
    assert hypothesis.status is HypothesisStatus.PROPOSED
    assert hypothesis.confidence_level is HypothesisConfidenceLevel.INSUFFICIENT_EVIDENCE
    assert hypothesis.created_at.utcoffset() == timedelta(0)
    assert hypothesis.updated_at >= hypothesis.created_at


def test_hypothesis_accepts_explicit_identity_and_timestamps() -> None:
    hypothesis_id = uuid4()
    created_at = datetime(2026, 11, 4, 10, 0, tzinfo=UTC)
    updated_at = created_at + timedelta(minutes=5)

    hypothesis = Hypothesis(
        hypothesis_id=hypothesis_id,
        incident_id=uuid4(),
        statement="Database connection pool is exhausted.",
        reasoning="Active connections reached the configured limit.",
        created_at=created_at,
        updated_at=updated_at,
    )

    assert hypothesis.hypothesis_id == hypothesis_id
    assert hypothesis.created_at == created_at
    assert hypothesis.updated_at == updated_at


def test_hypotheses_generate_distinct_identifiers() -> None:
    incident_id = uuid4()

    first = Hypothesis(
        incident_id=incident_id,
        statement="Connection pool exhaustion.",
        reasoning="Database timeouts.",
    )

    second = Hypothesis(
        incident_id=incident_id,
        statement="Database overload.",
        reasoning="Elevated database latency.",
    )

    assert first.hypothesis_id != second.hypothesis_id
    assert first.incident_id == second.incident_id


@pytest.mark.parametrize("statement", ["", " ", "\t\n"])
def test_hypothesis_rejects_empty_statement(statement: str) -> None:
    with pytest.raises(ValueError, match="statement must not be empty"):
        Hypothesis(
            incident_id=uuid4(),
            statement=statement,
            reasoning="Test reasoning.",
        )


@pytest.mark.parametrize("reasoning", ["", " ", "\t\n"])
def test_hypothesis_rejects_empty_reasoning(reasoning: str) -> None:
    with pytest.raises(ValueError, match="reasoning must not be empty"):
        Hypothesis(
            incident_id=uuid4(),
            statement="Test hypothesis.",
            reasoning=reasoning,
        )


@pytest.mark.parametrize(
    "timestamp",
    [
        datetime(2026, 11, 4, 10, 0),
        datetime(
            2026,
            11,
            4,
            10,
            0,
            tzinfo=timezone(timedelta(hours=1)),
        ),
    ],
)
@pytest.mark.parametrize("timestamp_field", ["created_at", "updated_at"])
def test_hypothesis_rejects_non_utc_timestamps(
    timestamp: datetime,
    timestamp_field: str,
) -> None:
    with pytest.raises(ValueError, match="timestamps must use UTC"):
        if timestamp_field == "created_at":
            Hypothesis(
                incident_id=uuid4(),
                statement="Test hypothesis.",
                reasoning="Test reasoning.",
                created_at=timestamp,
            )
        else:
            Hypothesis(
                incident_id=uuid4(),
                statement="Test hypothesis.",
                reasoning="Test reasoning.",
                updated_at=timestamp,
            )


def test_hypothesis_rejects_timestamp_regression() -> None:
    created_at = datetime(2026, 11, 4, 10, 0, tzinfo=UTC)
    updated_at = created_at - timedelta(seconds=1)

    with pytest.raises(ValueError, match="updated_at must not precede"):
        Hypothesis(
            incident_id=uuid4(),
            statement="Test hypothesis.",
            reasoning="Test reasoning.",
            created_at=created_at,
            updated_at=updated_at,
        )


def test_hypothesis_cannot_be_modified_directly() -> None:
    hypothesis = Hypothesis(
        incident_id=uuid4(),
        statement="Original hypothesis.",
        reasoning="Original reasoning.",
    )

    field_name = "status"

    with pytest.raises(FrozenInstanceError):
        setattr(
            hypothesis,
            field_name,
            HypothesisStatus.CONFIRMED,
        )

    assert hypothesis.status is HypothesisStatus.PROPOSED


@pytest.mark.parametrize(
    ("current", "allowed_targets"),
    [
        (
            HypothesisStatus.PROPOSED,
            frozenset({HypothesisStatus.UNDER_EVALUATION}),
        ),
        (
            HypothesisStatus.UNDER_EVALUATION,
            frozenset(
                {
                    HypothesisStatus.SUPPORTED,
                    HypothesisStatus.REJECTED,
                }
            ),
        ),
        (
            HypothesisStatus.SUPPORTED,
            frozenset(
                {
                    HypothesisStatus.UNDER_EVALUATION,
                    HypothesisStatus.CONFIRMED,
                }
            ),
        ),
        (
            HypothesisStatus.CONFIRMED,
            frozenset(),
        ),
        (
            HypothesisStatus.REJECTED,
            frozenset(),
        ),
    ],
)
@pytest.mark.parametrize("target", list(HypothesisStatus))
def test_hypothesis_status_transition_matrix(
    current: HypothesisStatus,
    allowed_targets: frozenset[HypothesisStatus],
    target: HypothesisStatus,
) -> None:
    expected = target in allowed_targets

    assert can_transition_hypothesis_status(current, target) is expected


def test_transition_creates_new_hypothesis_without_modifying_original() -> None:
    hypothesis = Hypothesis(
        incident_id=uuid4(),
        statement="Connection pool exhaustion.",
        reasoning="Database timeouts increased after deployment.",
    )

    transitioned = hypothesis.transition_to(HypothesisStatus.UNDER_EVALUATION)

    assert transitioned is not hypothesis

    assert hypothesis.status is HypothesisStatus.PROPOSED
    assert transitioned.status is HypothesisStatus.UNDER_EVALUATION

    assert transitioned.hypothesis_id == hypothesis.hypothesis_id
    assert transitioned.incident_id == hypothesis.incident_id
    assert transitioned.statement == hypothesis.statement
    assert transitioned.reasoning == hypothesis.reasoning
    assert transitioned.created_at == hypothesis.created_at

    assert transitioned.updated_at >= hypothesis.updated_at
    assert hypothesis.status is HypothesisStatus.PROPOSED

    assert transitioned.confidence_level is HypothesisConfidenceLevel.INSUFFICIENT_EVIDENCE
    assert hypothesis.confidence_level is HypothesisConfidenceLevel.INSUFFICIENT_EVIDENCE


@pytest.mark.parametrize(
    "target",
    [
        HypothesisStatus.PROPOSED,
        HypothesisStatus.SUPPORTED,
        HypothesisStatus.CONFIRMED,
        HypothesisStatus.REJECTED,
    ],
)
def test_transition_rejects_invalid_status_change(
    target: HypothesisStatus,
) -> None:
    hypothesis = Hypothesis(
        incident_id=uuid4(),
        statement="Test hypothesis.",
        reasoning="Test reasoning.",
    )

    with pytest.raises(
        HypothesisTransitionError,
        match="is not allowed",
    ):
        hypothesis.transition_to(target)

    assert hypothesis.status is HypothesisStatus.PROPOSED


@pytest.mark.parametrize(
    "target",
    [
        HypothesisStatus.SUPPORTED,
        HypothesisStatus.REJECTED,
    ],
)
def test_transition_blocks_evidence_dependent_status(
    target: HypothesisStatus,
) -> None:
    hypothesis = Hypothesis(
        incident_id=uuid4(),
        statement="Connection pool exhaustion.",
        reasoning="Elevated database connection timeouts.",
    )

    evaluating = hypothesis.transition_to(HypothesisStatus.UNDER_EVALUATION)

    with pytest.raises(
        HypothesisTransitionError,
        match="requires evidence assessment",
    ):
        evaluating.transition_to(target)

    assert evaluating.status is HypothesisStatus.UNDER_EVALUATION
    assert evaluating.confidence_level is HypothesisConfidenceLevel.INSUFFICIENT_EVIDENCE


def test_transition_rejects_timestamp_regression() -> None:
    future_updated_at = datetime.now(UTC) + timedelta(days=1)

    hypothesis = Hypothesis(
        incident_id=uuid4(),
        statement="Test hypothesis.",
        reasoning="Test reasoning.",
        updated_at=future_updated_at,
    )

    with pytest.raises(
        HypothesisTransitionError,
        match="Transition time must not precede updated_at",
    ):
        hypothesis.transition_to(HypothesisStatus.UNDER_EVALUATION)

    assert hypothesis.status is HypothesisStatus.PROPOSED
    assert hypothesis.updated_at == future_updated_at
