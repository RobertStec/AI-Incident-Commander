"""Unit tests for remediation domain types and lifecycle policies."""

from collections.abc import Mapping, MutableMapping, MutableSequence
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta, timezone
from typing import cast
from uuid import UUID, uuid4

import pytest

from ai_incident_commander.domain.remediation import (
    RemediationParameterValue,
    RemediationPlan,
    RemediationPlanStatus,
    RemediationPlanStepError,
    RemediationPlanTransitionError,
    RemediationRiskLevel,
    RemediationStep,
    can_transition_remediation_plan_status,
)


def test_remediation_risk_levels_match_domain_contract() -> None:
    assert {level.value for level in RemediationRiskLevel} == {
        "low",
        "medium",
        "high",
    }


def test_remediation_plan_statuses_match_domain_contract() -> None:
    assert {status.value for status in RemediationPlanStatus} == {
        "draft",
        "ready",
        "in_progress",
        "verifying",
        "completed",
        "failed",
        "cancelled",
    }


@pytest.mark.parametrize(
    ("current", "allowed_targets"),
    [
        (
            RemediationPlanStatus.DRAFT,
            frozenset(
                {
                    RemediationPlanStatus.READY,
                    RemediationPlanStatus.CANCELLED,
                }
            ),
        ),
        (
            RemediationPlanStatus.READY,
            frozenset(
                {
                    RemediationPlanStatus.DRAFT,
                    RemediationPlanStatus.IN_PROGRESS,
                    RemediationPlanStatus.CANCELLED,
                }
            ),
        ),
        (
            RemediationPlanStatus.IN_PROGRESS,
            frozenset(
                {
                    RemediationPlanStatus.VERIFYING,
                    RemediationPlanStatus.FAILED,
                }
            ),
        ),
        (
            RemediationPlanStatus.VERIFYING,
            frozenset(
                {
                    RemediationPlanStatus.COMPLETED,
                    RemediationPlanStatus.FAILED,
                }
            ),
        ),
        (
            RemediationPlanStatus.COMPLETED,
            frozenset(),
        ),
        (
            RemediationPlanStatus.FAILED,
            frozenset(),
        ),
        (
            RemediationPlanStatus.CANCELLED,
            frozenset(),
        ),
    ],
)
@pytest.mark.parametrize("target", list(RemediationPlanStatus))
def test_remediation_plan_status_transition_matrix(
    current: RemediationPlanStatus,
    allowed_targets: frozenset[RemediationPlanStatus],
    target: RemediationPlanStatus,
) -> None:
    expected = target in allowed_targets

    assert can_transition_remediation_plan_status(current, target) is expected


def test_new_remediation_plan_has_expected_defaults() -> None:
    incident_id = uuid4()

    plan = RemediationPlan(
        incident_id=incident_id,
        description="Rollback the payments-api deployment.",
        risk_level=RemediationRiskLevel.HIGH,
    )

    assert isinstance(plan.plan_id, UUID)
    assert plan.incident_id == incident_id
    assert plan.hypothesis_id is None
    assert plan.description == "Rollback the payments-api deployment."
    assert plan.risk_level is RemediationRiskLevel.HIGH
    assert plan.status is RemediationPlanStatus.DRAFT
    assert plan.created_at.utcoffset() == timedelta(0)
    assert plan.updated_at >= plan.created_at


def test_remediation_plan_accepts_explicit_fields() -> None:
    plan_id = uuid4()
    incident_id = uuid4()
    hypothesis_id = uuid4()

    created_at = datetime(2026, 11, 5, 8, 0, tzinfo=UTC)
    updated_at = created_at + timedelta(minutes=5)

    plan = RemediationPlan(
        plan_id=plan_id,
        incident_id=incident_id,
        hypothesis_id=hypothesis_id,
        description="Restart the payments-api service in Incident Lab.",
        risk_level=RemediationRiskLevel.MEDIUM,
        created_at=created_at,
        updated_at=updated_at,
    )

    assert plan.plan_id == plan_id
    assert plan.incident_id == incident_id
    assert plan.hypothesis_id == hypothesis_id
    assert plan.risk_level is RemediationRiskLevel.MEDIUM
    assert plan.status is RemediationPlanStatus.DRAFT
    assert plan.created_at == created_at
    assert plan.updated_at == updated_at


def test_remediation_plans_generate_distinct_identifiers() -> None:
    incident_id = uuid4()

    first = RemediationPlan(
        incident_id=incident_id,
        description="Rollback the deployment.",
        risk_level=RemediationRiskLevel.HIGH,
    )

    second = RemediationPlan(
        incident_id=incident_id,
        description="Restart the affected service.",
        risk_level=RemediationRiskLevel.MEDIUM,
    )

    assert first.plan_id != second.plan_id
    assert first.incident_id == second.incident_id


@pytest.mark.parametrize("description", ["", " ", "\t\n"])
def test_remediation_plan_rejects_empty_description(
    description: str,
) -> None:
    with pytest.raises(
        ValueError,
        match="description must not be empty",
    ):
        RemediationPlan(
            incident_id=uuid4(),
            description=description,
            risk_level=RemediationRiskLevel.LOW,
        )


@pytest.mark.parametrize(
    "timestamp",
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
@pytest.mark.parametrize("timestamp_field", ["created_at", "updated_at"])
def test_remediation_plan_rejects_non_utc_timestamps(
    timestamp: datetime,
    timestamp_field: str,
) -> None:
    with pytest.raises(ValueError, match="timestamps must use UTC"):
        if timestamp_field == "created_at":
            RemediationPlan(
                incident_id=uuid4(),
                description="Test remediation plan.",
                risk_level=RemediationRiskLevel.LOW,
                created_at=timestamp,
            )
        else:
            RemediationPlan(
                incident_id=uuid4(),
                description="Test remediation plan.",
                risk_level=RemediationRiskLevel.LOW,
                updated_at=timestamp,
            )


def test_remediation_plan_rejects_timestamp_regression() -> None:
    created_at = datetime(2026, 11, 5, 10, 0, tzinfo=UTC)
    updated_at = created_at - timedelta(seconds=1)

    with pytest.raises(
        ValueError,
        match="updated_at must not precede created_at",
    ):
        RemediationPlan(
            incident_id=uuid4(),
            description="Test remediation plan.",
            risk_level=RemediationRiskLevel.MEDIUM,
            created_at=created_at,
            updated_at=updated_at,
        )


def test_remediation_plan_cannot_be_modified_directly() -> None:
    plan = RemediationPlan(
        incident_id=uuid4(),
        description="Rollback the deployment.",
        risk_level=RemediationRiskLevel.HIGH,
    )

    field_name = "status"

    with pytest.raises(FrozenInstanceError):
        setattr(plan, field_name, RemediationPlanStatus.IN_PROGRESS)

    assert plan.status is RemediationPlanStatus.DRAFT


def test_transition_cancels_draft_without_modifying_original() -> None:
    plan = RemediationPlan(
        incident_id=uuid4(),
        hypothesis_id=uuid4(),
        description="Rollback the payments-api deployment.",
        risk_level=RemediationRiskLevel.HIGH,
    )

    cancelled = plan.transition_to(RemediationPlanStatus.CANCELLED)

    assert cancelled is not plan

    assert plan.status is RemediationPlanStatus.DRAFT
    assert cancelled.status is RemediationPlanStatus.CANCELLED

    assert cancelled.plan_id == plan.plan_id
    assert cancelled.incident_id == plan.incident_id
    assert cancelled.hypothesis_id == plan.hypothesis_id
    assert cancelled.description == plan.description
    assert cancelled.risk_level is plan.risk_level
    assert cancelled.created_at == plan.created_at

    assert cancelled.updated_at >= plan.updated_at
    assert plan.status is RemediationPlanStatus.DRAFT


def test_transition_blocks_ready_without_validated_context() -> None:
    plan = RemediationPlan(
        incident_id=uuid4(),
        description="Restart the affected service in Incident Lab.",
        risk_level=RemediationRiskLevel.LOW,
    )

    assert can_transition_remediation_plan_status(
        RemediationPlanStatus.DRAFT,
        RemediationPlanStatus.READY,
    )

    with pytest.raises(
        RemediationPlanTransitionError,
        match="requires validated remediation context",
    ):
        plan.transition_to(RemediationPlanStatus.READY)

    assert plan.status is RemediationPlanStatus.DRAFT


@pytest.mark.parametrize(
    "target",
    [
        RemediationPlanStatus.DRAFT,
        RemediationPlanStatus.IN_PROGRESS,
        RemediationPlanStatus.VERIFYING,
        RemediationPlanStatus.COMPLETED,
        RemediationPlanStatus.FAILED,
    ],
)
def test_transition_rejects_invalid_status_change(
    target: RemediationPlanStatus,
) -> None:
    plan = RemediationPlan(
        incident_id=uuid4(),
        description="Test remediation plan.",
        risk_level=RemediationRiskLevel.MEDIUM,
    )

    with pytest.raises(
        RemediationPlanTransitionError,
        match="is not allowed",
    ):
        plan.transition_to(target)

    assert plan.status is RemediationPlanStatus.DRAFT


@pytest.mark.parametrize("target", list(RemediationPlanStatus))
def test_cancelled_plan_rejects_further_transitions(
    target: RemediationPlanStatus,
) -> None:
    plan = RemediationPlan(
        incident_id=uuid4(),
        description="Test remediation plan.",
        risk_level=RemediationRiskLevel.HIGH,
    )

    cancelled = plan.transition_to(RemediationPlanStatus.CANCELLED)

    with pytest.raises(
        RemediationPlanTransitionError,
        match="is not allowed",
    ):
        cancelled.transition_to(target)

    assert cancelled.status is RemediationPlanStatus.CANCELLED


def test_transition_rejects_timestamp_regression() -> None:
    future_updated_at = datetime.now(UTC) + timedelta(days=1)

    plan = RemediationPlan(
        incident_id=uuid4(),
        description="Test remediation plan.",
        risk_level=RemediationRiskLevel.MEDIUM,
        updated_at=future_updated_at,
    )

    with pytest.raises(
        RemediationPlanTransitionError,
        match="Transition time must not precede updated_at",
    ):
        plan.transition_to(RemediationPlanStatus.CANCELLED)

    assert plan.status is RemediationPlanStatus.DRAFT
    assert plan.updated_at == future_updated_at


def test_new_remediation_step_has_expected_defaults() -> None:
    plan_id = uuid4()

    step = RemediationStep(
        plan_id=plan_id,
        position=1,
        action_name="rollback_release",
        target="payments-api",
        environment="incident-lab",
        risk_level=RemediationRiskLevel.HIGH,
    )

    assert isinstance(step.step_id, UUID)
    assert step.plan_id == plan_id
    assert step.position == 1
    assert step.action_name == "rollback_release"
    assert step.target == "payments-api"
    assert step.environment == "incident-lab"
    assert step.risk_level is RemediationRiskLevel.HIGH
    assert step.created_at.utcoffset() == timedelta(0)


def test_remediation_step_accepts_explicit_fields() -> None:
    step_id = uuid4()
    plan_id = uuid4()
    created_at = datetime(2026, 11, 5, 10, 0, tzinfo=UTC)

    step = RemediationStep(
        step_id=step_id,
        plan_id=plan_id,
        position=2,
        action_name="restart_service",
        target="payments-api",
        environment="incident-lab",
        risk_level=RemediationRiskLevel.MEDIUM,
        created_at=created_at,
    )

    assert step.step_id == step_id
    assert step.plan_id == plan_id
    assert step.position == 2
    assert step.action_name == "restart_service"
    assert step.target == "payments-api"
    assert step.environment == "incident-lab"
    assert step.risk_level is RemediationRiskLevel.MEDIUM
    assert step.created_at == created_at


def test_remediation_steps_generate_distinct_identifiers() -> None:
    plan_id = uuid4()

    first = RemediationStep(
        plan_id=plan_id,
        position=1,
        action_name="inspect_service",
        target="payments-api",
        environment="incident-lab",
        risk_level=RemediationRiskLevel.LOW,
    )

    second = RemediationStep(
        plan_id=plan_id,
        position=2,
        action_name="restart_service",
        target="payments-api",
        environment="incident-lab",
        risk_level=RemediationRiskLevel.MEDIUM,
    )

    assert first.step_id != second.step_id
    assert first.plan_id == second.plan_id


@pytest.mark.parametrize("position", [0, -1, True])
def test_remediation_step_rejects_invalid_position(
    position: int,
) -> None:
    with pytest.raises(
        ValueError,
        match="position must be a positive integer",
    ):
        RemediationStep(
            plan_id=uuid4(),
            position=position,
            action_name="restart_service",
            target="payments-api",
            environment="incident-lab",
            risk_level=RemediationRiskLevel.MEDIUM,
        )


@pytest.mark.parametrize(
    ("field_name", "invalid_value"),
    [
        ("action_name", ""),
        ("action_name", " \t "),
        ("target", ""),
        ("target", " \t "),
        ("environment", ""),
        ("environment", " \t "),
    ],
)
def test_remediation_step_rejects_empty_required_fields(
    field_name: str,
    invalid_value: str,
) -> None:
    fields = {
        "action_name": "restart_service",
        "target": "payments-api",
        "environment": "incident-lab",
    }
    fields[field_name] = invalid_value

    with pytest.raises(
        ValueError,
        match=f"Remediation step {field_name} must not be empty",
    ):
        RemediationStep(
            plan_id=uuid4(),
            position=1,
            action_name=fields["action_name"],
            target=fields["target"],
            environment=fields["environment"],
            risk_level=RemediationRiskLevel.MEDIUM,
        )


@pytest.mark.parametrize(
    "created_at",
    [
        datetime(2026, 11, 5, 10, 0),
        datetime(
            2026,
            11,
            5,
            11,
            0,
            tzinfo=timezone(timedelta(hours=1)),
        ),
    ],
)
def test_remediation_step_rejects_non_utc_timestamp(
    created_at: datetime,
) -> None:
    with pytest.raises(
        ValueError,
        match="timestamps must use UTC",
    ):
        RemediationStep(
            plan_id=uuid4(),
            position=1,
            action_name="restart_service",
            target="payments-api",
            environment="incident-lab",
            risk_level=RemediationRiskLevel.MEDIUM,
            created_at=created_at,
        )


def test_remediation_step_cannot_be_modified_directly() -> None:
    step = RemediationStep(
        plan_id=uuid4(),
        position=1,
        action_name="rollback_release",
        target="payments-api",
        environment="incident-lab",
        risk_level=RemediationRiskLevel.HIGH,
    )

    field_name = "target"

    with pytest.raises(FrozenInstanceError):
        setattr(step, field_name, "another-service")

    assert step.target == "payments-api"


def test_new_remediation_step_has_empty_parameters() -> None:
    step = RemediationStep(
        plan_id=uuid4(),
        position=1,
        action_name="inspect_service",
        target="payments-api",
        environment="incident-lab",
        risk_level=RemediationRiskLevel.LOW,
    )

    assert dict(step.parameters) == {}


def test_remediation_step_accepts_json_scalar_parameters() -> None:
    parameters: dict[str, RemediationParameterValue] = {
        "release_id": "release-123",
        "attempt": 2,
        "timeout_seconds": 15.5,
        "dry_run": False,
        "optional": None,
    }

    step = RemediationStep(
        plan_id=uuid4(),
        position=1,
        action_name="rollback_release",
        target="payments-api",
        environment="incident-lab",
        risk_level=RemediationRiskLevel.HIGH,
        parameters=parameters,
    )

    assert dict(step.parameters) == parameters


@pytest.mark.parametrize("invalid_key", ["", " \t "])
def test_remediation_step_rejects_empty_parameter_names(
    invalid_key: str,
) -> None:
    with pytest.raises(
        ValueError,
        match="parameter names must be non-empty strings",
    ):
        RemediationStep(
            plan_id=uuid4(),
            position=1,
            action_name="rollback_release",
            target="payments-api",
            environment="incident-lab",
            risk_level=RemediationRiskLevel.HIGH,
            parameters={invalid_key: "release-123"},
        )


def test_remediation_step_rejects_non_string_parameter_name() -> None:
    invalid_parameters = cast(
        Mapping[str, RemediationParameterValue],
        {123: "release-123"},
    )

    with pytest.raises(
        ValueError,
        match="parameter names must be non-empty strings",
    ):
        RemediationStep(
            plan_id=uuid4(),
            position=1,
            action_name="rollback_release",
            target="payments-api",
            environment="incident-lab",
            risk_level=RemediationRiskLevel.HIGH,
            parameters=invalid_parameters,
        )


@pytest.mark.parametrize(
    "invalid_value",
    [["nested"], {"release": "123"}],
)
def test_remediation_step_rejects_non_scalar_parameters(
    invalid_value: object,
) -> None:
    with pytest.raises(
        ValueError,
        match="parameters must be JSON scalars",
    ):
        RemediationStep(
            plan_id=uuid4(),
            position=1,
            action_name="rollback_release",
            target="payments-api",
            environment="incident-lab",
            risk_level=RemediationRiskLevel.HIGH,
            parameters={
                "invalid": cast(RemediationParameterValue, invalid_value),
            },
        )


@pytest.mark.parametrize(
    "invalid_value",
    [float("nan"), float("inf"), float("-inf")],
)
def test_remediation_step_rejects_non_finite_numbers(
    invalid_value: float,
) -> None:
    with pytest.raises(
        ValueError,
        match="numeric parameters must be finite",
    ):
        RemediationStep(
            plan_id=uuid4(),
            position=1,
            action_name="rollback_release",
            target="payments-api",
            environment="incident-lab",
            risk_level=RemediationRiskLevel.HIGH,
            parameters={"timeout_seconds": invalid_value},
        )


def test_remediation_step_parameters_are_read_only() -> None:
    step = RemediationStep(
        plan_id=uuid4(),
        position=1,
        action_name="rollback_release",
        target="payments-api",
        environment="incident-lab",
        risk_level=RemediationRiskLevel.HIGH,
        parameters={"release_id": "release-123"},
    )

    mutable_view = cast(
        MutableMapping[str, RemediationParameterValue],
        step.parameters,
    )

    with pytest.raises(TypeError):
        mutable_view["release_id"] = "different-release"

    assert step.parameters["release_id"] == "release-123"


def test_remediation_step_copies_input_parameters() -> None:
    supplied_parameters = {"release_id": "release-123"}

    step = RemediationStep(
        plan_id=uuid4(),
        position=1,
        action_name="rollback_release",
        target="payments-api",
        environment="incident-lab",
        risk_level=RemediationRiskLevel.HIGH,
        parameters=supplied_parameters,
    )

    supplied_parameters["release_id"] = "different-release"
    supplied_parameters["unexpected"] = "value"

    assert dict(step.parameters) == {"release_id": "release-123"}


def _make_step(
    plan_id: UUID,
    position: int,
    *,
    step_id: UUID | None = None,
    risk_level: RemediationRiskLevel = RemediationRiskLevel.LOW,
) -> RemediationStep:
    """Create a valid step for aggregate consistency tests."""
    return RemediationStep(
        plan_id=plan_id,
        step_id=step_id if step_id is not None else uuid4(),
        position=position,
        action_name="inspect_service",
        target="payments-api",
        environment="incident-lab",
        risk_level=risk_level,
    )


def test_draft_remediation_plan_allows_empty_steps() -> None:
    plan = RemediationPlan(
        incident_id=uuid4(),
        description="Investigate payments-api degradation.",
        risk_level=RemediationRiskLevel.LOW,
    )

    assert plan.status is RemediationPlanStatus.DRAFT
    assert plan.steps == ()


def test_remediation_plan_sorts_steps_by_position() -> None:
    plan_id = uuid4()

    first = _make_step(plan_id, 1)
    second = _make_step(plan_id, 2)
    third = _make_step(plan_id, 3)

    plan = RemediationPlan(
        plan_id=plan_id,
        incident_id=uuid4(),
        description="Investigate and remediate the API.",
        risk_level=RemediationRiskLevel.HIGH,
        steps=(third, first, second),
    )

    assert plan.steps == (first, second, third)
    assert [step.position for step in plan.steps] == [1, 2, 3]
    assert all(step.plan_id == plan.plan_id for step in plan.steps)


def test_remediation_plan_rejects_step_from_different_plan() -> None:
    plan_id = uuid4()
    foreign_step = _make_step(uuid4(), 1)

    with pytest.raises(
        ValueError,
        match="belongs to a different plan",
    ):
        RemediationPlan(
            plan_id=plan_id,
            incident_id=uuid4(),
            description="Test remediation plan.",
            risk_level=RemediationRiskLevel.MEDIUM,
            steps=(foreign_step,),
        )


def test_remediation_plan_rejects_duplicate_step_positions() -> None:
    plan_id = uuid4()

    first = _make_step(plan_id, 1)
    second = _make_step(plan_id, 1)

    with pytest.raises(
        ValueError,
        match="step positions must be unique",
    ):
        RemediationPlan(
            plan_id=plan_id,
            incident_id=uuid4(),
            description="Test remediation plan.",
            risk_level=RemediationRiskLevel.MEDIUM,
            steps=(first, second),
        )


def test_remediation_plan_rejects_duplicate_step_ids() -> None:
    plan_id = uuid4()
    shared_step_id = uuid4()

    first = _make_step(plan_id, 1, step_id=shared_step_id)
    second = _make_step(plan_id, 2, step_id=shared_step_id)

    with pytest.raises(
        ValueError,
        match="step identifiers must be unique",
    ):
        RemediationPlan(
            plan_id=plan_id,
            incident_id=uuid4(),
            description="Test remediation plan.",
            risk_level=RemediationRiskLevel.MEDIUM,
            steps=(first, second),
        )


def test_remediation_plan_rejects_mutable_steps_collection() -> None:
    plan_id = uuid4()
    step = _make_step(plan_id, 1)

    invalid_steps = cast(
        tuple[RemediationStep, ...],
        [step],
    )

    with pytest.raises(
        ValueError,
        match="steps must be a tuple",
    ):
        RemediationPlan(
            plan_id=plan_id,
            incident_id=uuid4(),
            description="Test remediation plan.",
            risk_level=RemediationRiskLevel.MEDIUM,
            steps=invalid_steps,
        )


def test_remediation_plan_rejects_invalid_step_object() -> None:
    invalid_steps = cast(
        tuple[RemediationStep, ...],
        ("not-a-remediation-step",),
    )

    with pytest.raises(
        ValueError,
        match="steps must be RemediationStep instances",
    ):
        RemediationPlan(
            incident_id=uuid4(),
            description="Test remediation plan.",
            risk_level=RemediationRiskLevel.LOW,
            steps=invalid_steps,
        )


def test_remediation_plan_steps_cannot_be_modified_directly() -> None:
    plan_id = uuid4()
    first = _make_step(plan_id, 1)
    second = _make_step(plan_id, 2)

    plan = RemediationPlan(
        plan_id=plan_id,
        incident_id=uuid4(),
        description="Test remediation plan.",
        risk_level=RemediationRiskLevel.MEDIUM,
        steps=(first,),
    )

    mutable_steps = cast(
        MutableSequence[RemediationStep],
        plan.steps,
    )

    with pytest.raises(TypeError):
        mutable_steps[0] = second

    field_name = "steps"

    with pytest.raises(FrozenInstanceError):
        setattr(plan, field_name, (second,))

    assert plan.steps == (first,)


def test_add_step_returns_new_plan_without_modifying_original() -> None:
    plan = RemediationPlan(
        incident_id=uuid4(),
        hypothesis_id=uuid4(),
        description="Remediate payments-api degradation.",
        risk_level=RemediationRiskLevel.HIGH,
    )
    step = _make_step(plan.plan_id, 1)

    updated = plan.add_step(step)

    assert updated is not plan
    assert plan.steps == ()
    assert updated.steps == (step,)

    assert updated.plan_id == plan.plan_id
    assert updated.incident_id == plan.incident_id
    assert updated.hypothesis_id == plan.hypothesis_id
    assert updated.description == plan.description
    assert updated.risk_level is plan.risk_level
    assert updated.status is RemediationPlanStatus.DRAFT
    assert updated.created_at == plan.created_at
    assert updated.updated_at >= plan.updated_at


def test_add_step_sorts_multiple_steps() -> None:
    plan = RemediationPlan(
        incident_id=uuid4(),
        description="Investigate and remediate the API.",
        risk_level=RemediationRiskLevel.HIGH,
    )

    first = _make_step(plan.plan_id, 1)
    second = _make_step(plan.plan_id, 2)
    third = _make_step(plan.plan_id, 3)

    with_third = plan.add_step(third)
    with_first = with_third.add_step(first)
    with_second = with_first.add_step(second)

    assert with_second.steps == (first, second, third)
    assert [step.position for step in with_second.steps] == [1, 2, 3]

    assert plan.steps == ()
    assert with_third.steps == (third,)
    assert with_first.steps == (first, third)


def test_add_step_allows_nonconsecutive_positions() -> None:
    plan = RemediationPlan(
        incident_id=uuid4(),
        description="Test remediation plan.",
        risk_level=RemediationRiskLevel.LOW,
    )

    third = _make_step(plan.plan_id, 3)
    first = _make_step(plan.plan_id, 1)

    updated = plan.add_step(third).add_step(first)

    assert updated.steps == (first, third)


def test_add_step_rejects_foreign_plan_step() -> None:
    plan = RemediationPlan(
        incident_id=uuid4(),
        description="Test remediation plan.",
        risk_level=RemediationRiskLevel.MEDIUM,
    )
    foreign_step = _make_step(uuid4(), 1)

    with pytest.raises(
        ValueError,
        match="belongs to a different plan",
    ):
        plan.add_step(foreign_step)

    assert plan.steps == ()


def test_add_step_rejects_duplicate_position() -> None:
    plan = RemediationPlan(
        incident_id=uuid4(),
        description="Test remediation plan.",
        risk_level=RemediationRiskLevel.MEDIUM,
    )

    first = _make_step(plan.plan_id, 1)
    duplicate = _make_step(plan.plan_id, 1)

    with_first = plan.add_step(first)

    with pytest.raises(
        ValueError,
        match="step positions must be unique",
    ):
        with_first.add_step(duplicate)

    assert with_first.steps == (first,)


def test_add_step_rejects_duplicate_step_id() -> None:
    plan = RemediationPlan(
        incident_id=uuid4(),
        description="Test remediation plan.",
        risk_level=RemediationRiskLevel.MEDIUM,
    )
    shared_step_id = uuid4()

    first = _make_step(plan.plan_id, 1, step_id=shared_step_id)
    duplicate = _make_step(plan.plan_id, 2, step_id=shared_step_id)

    with_first = plan.add_step(first)

    with pytest.raises(
        ValueError,
        match="step identifiers must be unique",
    ):
        with_first.add_step(duplicate)

    assert with_first.steps == (first,)


def test_add_step_rejects_cancelled_plan() -> None:
    plan = RemediationPlan(
        incident_id=uuid4(),
        description="Test remediation plan.",
        risk_level=RemediationRiskLevel.HIGH,
    )
    cancelled = plan.transition_to(RemediationPlanStatus.CANCELLED)
    step = _make_step(plan.plan_id, 1)

    with pytest.raises(
        RemediationPlanStepError,
        match="Steps can only be added to a draft",
    ):
        cancelled.add_step(step)

    assert cancelled.status is RemediationPlanStatus.CANCELLED
    assert cancelled.steps == ()


def test_add_step_rejects_timestamp_regression() -> None:
    future_updated_at = datetime.now(UTC) + timedelta(days=1)

    plan = RemediationPlan(
        incident_id=uuid4(),
        description="Test remediation plan.",
        risk_level=RemediationRiskLevel.MEDIUM,
        updated_at=future_updated_at,
    )
    step = _make_step(plan.plan_id, 1)

    with pytest.raises(
        RemediationPlanStepError,
        match="Step addition time must not precede updated_at",
    ):
        plan.add_step(step)

    assert plan.steps == ()
    assert plan.updated_at == future_updated_at


def test_structural_readiness_rejects_empty_plan() -> None:
    plan = RemediationPlan(
        incident_id=uuid4(),
        description="Rollback the payments-api deployment.",
        risk_level=RemediationRiskLevel.HIGH,
    )

    with pytest.raises(
        RemediationPlanTransitionError,
        match="requires at least one step",
    ):
        plan.validate_structural_readiness()

    assert plan.status is RemediationPlanStatus.DRAFT
    assert plan.steps == ()


@pytest.mark.parametrize("step_count", [1, 3])
def test_structural_readiness_accepts_plan_with_steps(
    step_count: int,
) -> None:
    plan_id = uuid4()
    steps = tuple(_make_step(plan_id, position) for position in range(1, step_count + 1))

    plan = RemediationPlan(
        plan_id=plan_id,
        incident_id=uuid4(),
        description="Investigate and remediate payments-api.",
        risk_level=RemediationRiskLevel.MEDIUM,
        steps=steps,
    )

    plan.validate_structural_readiness()
    assert len(plan.steps) == step_count
    assert plan.status is RemediationPlanStatus.DRAFT


def test_structural_readiness_does_not_modify_plan() -> None:
    plan = RemediationPlan(
        incident_id=uuid4(),
        description="Investigate payments-api degradation.",
        risk_level=RemediationRiskLevel.LOW,
    )

    step = _make_step(plan.plan_id, 1)
    plan_with_step = plan.add_step(step)

    original_updated_at = plan_with_step.updated_at
    original_steps = plan_with_step.steps

    plan_with_step.validate_structural_readiness()

    assert plan_with_step.status is RemediationPlanStatus.DRAFT
    assert plan_with_step.updated_at == original_updated_at
    assert plan_with_step.steps == original_steps


def test_structural_readiness_does_not_authorize_ready_transition() -> None:
    plan = RemediationPlan(
        incident_id=uuid4(),
        description="Rollback the payments-api deployment.",
        risk_level=RemediationRiskLevel.HIGH,
    )

    step = _make_step(plan.plan_id, 1)
    plan_with_step = plan.add_step(step)

    plan_with_step.validate_structural_readiness()

    with pytest.raises(
        RemediationPlanTransitionError,
        match="requires validated remediation context",
    ):
        plan_with_step.transition_to(RemediationPlanStatus.READY)

    assert plan_with_step.status is RemediationPlanStatus.DRAFT
    assert plan_with_step.steps == (step,)


@pytest.mark.parametrize(
    ("plan_risk", "step_risk", "expected_valid"),
    [
        (RemediationRiskLevel.LOW, RemediationRiskLevel.LOW, True),
        (RemediationRiskLevel.LOW, RemediationRiskLevel.MEDIUM, False),
        (RemediationRiskLevel.LOW, RemediationRiskLevel.HIGH, False),
        (RemediationRiskLevel.MEDIUM, RemediationRiskLevel.LOW, True),
        (RemediationRiskLevel.MEDIUM, RemediationRiskLevel.MEDIUM, True),
        (RemediationRiskLevel.MEDIUM, RemediationRiskLevel.HIGH, False),
        (RemediationRiskLevel.HIGH, RemediationRiskLevel.LOW, True),
        (RemediationRiskLevel.HIGH, RemediationRiskLevel.MEDIUM, True),
        (RemediationRiskLevel.HIGH, RemediationRiskLevel.HIGH, True),
    ],
)
def test_remediation_plan_risk_consistency_matrix(
    plan_risk: RemediationRiskLevel,
    step_risk: RemediationRiskLevel,
    expected_valid: bool,
) -> None:
    plan_id = uuid4()
    step = _make_step(plan_id, 1, risk_level=step_risk)

    plan = RemediationPlan(
        plan_id=plan_id,
        incident_id=uuid4(),
        description="Test remediation plan.",
        risk_level=plan_risk,
        steps=(step,),
    )

    if expected_valid:
        plan.validate_risk_consistency()
    else:
        with pytest.raises(
            RemediationPlanTransitionError,
            match="risk level must not be lower",
        ):
            plan.validate_risk_consistency()

    assert plan.status is RemediationPlanStatus.DRAFT
    assert plan.steps == (step,)


def test_risk_consistency_rejects_high_risk_step_among_other_steps() -> None:
    plan_id = uuid4()

    steps = (
        _make_step(plan_id, 1, risk_level=RemediationRiskLevel.LOW),
        _make_step(plan_id, 2, risk_level=RemediationRiskLevel.HIGH),
        _make_step(plan_id, 3, risk_level=RemediationRiskLevel.MEDIUM),
    )

    plan = RemediationPlan(
        plan_id=plan_id,
        incident_id=uuid4(),
        description="Investigate and remediate payments-api.",
        risk_level=RemediationRiskLevel.MEDIUM,
        steps=steps,
    )

    with pytest.raises(
        RemediationPlanTransitionError,
        match="risk level must not be lower",
    ):
        plan.validate_risk_consistency()

    assert plan.status is RemediationPlanStatus.DRAFT
    assert plan.steps == steps


def test_risk_consistency_accepts_mixed_steps_with_sufficient_plan_risk() -> None:
    plan_id = uuid4()

    steps = (
        _make_step(plan_id, 1, risk_level=RemediationRiskLevel.LOW),
        _make_step(plan_id, 2, risk_level=RemediationRiskLevel.MEDIUM),
        _make_step(plan_id, 3, risk_level=RemediationRiskLevel.HIGH),
    )

    plan = RemediationPlan(
        plan_id=plan_id,
        incident_id=uuid4(),
        description="Investigate and remediate payments-api.",
        risk_level=RemediationRiskLevel.HIGH,
        steps=steps,
    )

    plan.validate_risk_consistency()

    assert len(plan.steps) == 3
    assert plan.risk_level is RemediationRiskLevel.HIGH
    assert plan.status is RemediationPlanStatus.DRAFT


def test_risk_consistency_does_not_modify_plan() -> None:
    plan_id = uuid4()
    step = _make_step(
        plan_id,
        1,
        risk_level=RemediationRiskLevel.LOW,
    )

    plan = RemediationPlan(
        plan_id=plan_id,
        incident_id=uuid4(),
        description="Inspect the affected service.",
        risk_level=RemediationRiskLevel.MEDIUM,
        steps=(step,),
    )

    original_updated_at = plan.updated_at
    original_steps = plan.steps

    plan.validate_risk_consistency()

    assert plan.status is RemediationPlanStatus.DRAFT
    assert plan.updated_at == original_updated_at
    assert plan.steps == original_steps
    assert plan.risk_level is RemediationRiskLevel.MEDIUM


def test_risk_consistency_allows_empty_draft_plan() -> None:
    plan = RemediationPlan(
        incident_id=uuid4(),
        description="Draft remediation plan.",
        risk_level=RemediationRiskLevel.LOW,
    )

    plan.validate_risk_consistency()

    with pytest.raises(
        RemediationPlanTransitionError,
        match="requires at least one step",
    ):
        plan.validate_structural_readiness()

    assert plan.status is RemediationPlanStatus.DRAFT
    assert plan.steps == ()
