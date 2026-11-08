"""Tests for deterministic remediation action fingerprints."""

from dataclasses import replace
from datetime import UTC, datetime
from re import fullmatch
from uuid import UUID

import pytest

from ai_incident_commander.application.action_fingerprint import (
    ActionFingerprintInputMismatchError,
    create_action_fingerprint,
)
from ai_incident_commander.application.action_policy_version import (
    create_action_policy_version,
)
from ai_incident_commander.application.remediation_preflight import (
    RemediationPreflightResult,
)
from ai_incident_commander.domain.action_catalog import (
    ActionCatalog,
    ActionDefinition,
    ActionEffect,
    ActionParameterDefinition,
    ActionParameterType,
)
from ai_incident_commander.domain.remediation import (
    RemediationParameterValue,
    RemediationRiskLevel,
    RemediationStep,
)
from ai_incident_commander.domain.target_identity import ResolvedTarget


def _make_step(
    *,
    parameters: dict[str, RemediationParameterValue] | None = None,
) -> RemediationStep:
    """Create a stable remediation step for fingerprint tests."""
    return RemediationStep(
        plan_id=UUID("00000000-0000-0000-0000-000000000001"),
        step_id=UUID("00000000-0000-0000-0000-000000000002"),
        position=1,
        action_name="restart_service",
        target="payments-api",
        environment="incident-lab",
        risk_level=RemediationRiskLevel.HIGH,
        parameters=({"timeout_seconds": 30, "dry_run": True} if parameters is None else parameters),
    )


def _make_preflight(*, step: RemediationStep) -> RemediationPreflightResult:
    """Build a consistent synthetic preflight result."""
    definition = ActionDefinition(
        action_name="restart_service",
        description="Restart an affected service.",
        effect=ActionEffect.MUTATING,
        risk_level=RemediationRiskLevel.HIGH,
        allowed_environments=("incident-lab", "staging"),
        parameters=(
            ActionParameterDefinition(
                name="timeout_seconds",
                value_type=ActionParameterType.NUMBER,
            ),
            ActionParameterDefinition(
                name="dry_run",
                value_type=ActionParameterType.BOOLEAN,
                required=False,
            ),
            ActionParameterDefinition(
                name="note",
                value_type=ActionParameterType.STRING,
                required=False,
                nullable=True,
            ),
        ),
    )
    resolved = ResolvedTarget(
        target="payments-api",
        resource_id="service-123",
        environment="incident-lab",
        source="service-inventory",
    )
    return RemediationPreflightResult(
        action=definition,
        target=resolved,
        step_snapshot=step,
        policy_version=create_action_policy_version(ActionCatalog(definitions=(definition,))),
    )


def test_fingerprint_has_versioned_sha256_format() -> None:
    step = _make_step()
    fingerprint = create_action_fingerprint(
        step,
        _make_preflight(step=step),
    )

    assert fullmatch(r"afp:v2:[0-9a-f]{64}", fingerprint) is not None


def test_fingerprint_is_deterministic() -> None:
    step = _make_step()
    preflight = _make_preflight(step=step)

    first = create_action_fingerprint(step, preflight)
    second = create_action_fingerprint(step, preflight)

    assert first == second


def test_fingerprint_ignores_parameter_dictionary_order() -> None:
    first_step = _make_step(
        parameters={"timeout_seconds": 30, "dry_run": True},
    )
    second_step = _make_step(
        parameters={"dry_run": True, "timeout_seconds": 30},
    )
    preflight = _make_preflight(step=first_step)

    assert create_action_fingerprint(first_step, preflight) == create_action_fingerprint(
        second_step, preflight
    )


def test_fingerprint_supports_unicode_parameters() -> None:
    step = _make_step(
        parameters={
            "timeout_seconds": 30,
            "note": "Zażółć gęślą jaźń",
        },
    )
    preflight = _make_preflight(step=step)

    assert create_action_fingerprint(step, preflight) == create_action_fingerprint(step, preflight)


@pytest.mark.parametrize(
    "changed_parameters",
    [
        {"timeout_seconds": 300, "dry_run": True},
        {"timeout_seconds": 30.0, "dry_run": True},
        {"timeout_seconds": 30, "dry_run": False},
        {"timeout_seconds": 30},
        {
            "timeout_seconds": 30,
            "dry_run": True,
            "note": "Approved restart",
        },
        {
            "timeout_seconds": 30,
            "dry_run": True,
            "note": None,
        },
    ],
)
def test_fingerprint_changes_when_parameters_change(
    changed_parameters: dict[str, RemediationParameterValue],
) -> None:
    original_step = _make_step()
    changed_step = _make_step(parameters=changed_parameters)

    original = create_action_fingerprint(original_step, _make_preflight(step=original_step))
    changed = create_action_fingerprint(changed_step, _make_preflight(step=changed_step))

    assert changed != original


@pytest.mark.parametrize(
    "field_name",
    ["plan_id", "step_id", "position"],
)
def test_fingerprint_changes_when_step_identity_changes(
    field_name: str,
) -> None:
    step = _make_step()
    preflight = _make_preflight(step=step)

    if field_name == "plan_id":
        changed_step = replace(
            step,
            plan_id=UUID("00000000-0000-0000-0000-000000000003"),
        )
    elif field_name == "step_id":
        changed_step = replace(
            step,
            step_id=UUID("00000000-0000-0000-0000-000000000004"),
        )
    else:
        changed_step = replace(step, position=2)

    assert create_action_fingerprint(
        changed_step, _make_preflight(step=changed_step)
    ) != create_action_fingerprint(step, preflight)


def test_fingerprint_changes_when_action_name_changes() -> None:
    step = _make_step()
    preflight = _make_preflight(step=step)

    changed_step = replace(step, action_name="stop_service")
    changed_preflight = replace(
        preflight,
        step_snapshot=changed_step,
        action=replace(
            preflight.action,
            action_name="stop_service",
        ),
    )

    assert create_action_fingerprint(changed_step, changed_preflight) != create_action_fingerprint(
        step, preflight
    )


def test_fingerprint_changes_when_action_effect_changes() -> None:
    step = _make_step()
    preflight = _make_preflight(step=step)

    changed_preflight = replace(
        preflight,
        action=replace(
            preflight.action,
            effect=ActionEffect.READ_ONLY,
        ),
    )

    assert create_action_fingerprint(step, changed_preflight) != create_action_fingerprint(
        step, preflight
    )


def test_fingerprint_changes_when_risk_level_changes() -> None:
    step = _make_step()
    preflight = _make_preflight(step=step)

    changed_step = replace(
        step,
        risk_level=RemediationRiskLevel.MEDIUM,
    )
    changed_preflight = replace(
        preflight,
        step_snapshot=changed_step,
        action=replace(
            preflight.action,
            risk_level=RemediationRiskLevel.MEDIUM,
        ),
    )

    assert create_action_fingerprint(changed_step, changed_preflight) != create_action_fingerprint(
        step, preflight
    )


def test_fingerprint_changes_when_target_name_changes() -> None:
    step = _make_step()
    preflight = _make_preflight(step=step)

    changed_step = replace(step, target="orders-api")
    changed_preflight = replace(
        preflight,
        step_snapshot=changed_step,
        target=replace(
            preflight.target,
            target="orders-api",
        ),
    )

    assert create_action_fingerprint(changed_step, changed_preflight) != create_action_fingerprint(
        step, preflight
    )


def test_fingerprint_changes_when_environment_changes() -> None:
    step = _make_step()
    preflight = _make_preflight(step=step)

    changed_step = replace(step, environment="staging")
    changed_preflight = replace(
        preflight,
        step_snapshot=changed_step,
        target=replace(
            preflight.target,
            environment="staging",
        ),
    )

    assert create_action_fingerprint(changed_step, changed_preflight) != create_action_fingerprint(
        step, preflight
    )


@pytest.mark.parametrize(
    ("field_name", "changed_value"),
    [
        ("resource_id", "service-456"),
        ("source", "another-inventory"),
    ],
)
def test_fingerprint_changes_when_resolved_identity_changes(
    field_name: str,
    changed_value: str,
) -> None:
    step = _make_step()
    preflight = _make_preflight(step=step)

    if field_name == "resource_id":
        changed_target = replace(
            preflight.target,
            resource_id=changed_value,
        )
    else:
        changed_target = replace(
            preflight.target,
            source=changed_value,
        )

    changed_preflight = replace(
        preflight,
        target=changed_target,
    )

    assert create_action_fingerprint(step, changed_preflight) != create_action_fingerprint(
        step, preflight
    )


@pytest.mark.parametrize(
    "mismatch",
    [
        "action_name",
        "risk_level",
        "environment_not_allowed",
        "target_name",
        "resolved_environment",
    ],
)
def test_fingerprint_rejects_inconsistent_inputs(
    mismatch: str,
) -> None:
    step = _make_step()
    preflight = _make_preflight(step=step)

    if mismatch == "action_name":
        step = replace(step, action_name="unknown_action")
    elif mismatch == "risk_level":
        step = replace(
            step,
            risk_level=RemediationRiskLevel.LOW,
        )
    elif mismatch == "environment_not_allowed":
        step = replace(step, environment="production")
    elif mismatch == "target_name":
        step = replace(step, target="other-api")
    else:
        preflight = replace(
            preflight,
            target=replace(
                preflight.target,
                environment="staging",
            ),
        )

    preflight = replace(preflight, step_snapshot=step)

    with pytest.raises(
        ActionFingerprintInputMismatchError,
        match="Remediation step and preflight result are inconsistent",
    ):
        create_action_fingerprint(step, preflight)


def test_fingerprint_does_not_modify_inputs() -> None:
    step = _make_step()
    preflight = _make_preflight(step=step)
    original_parameters = dict(step.parameters)
    original_resource_id = preflight.target.resource_id

    create_action_fingerprint(step, preflight)

    assert dict(step.parameters) == original_parameters
    assert preflight.target.resource_id == original_resource_id
    assert step.action_name == preflight.action.action_name


def test_fingerprint_does_not_depend_on_creation_timestamp() -> None:
    step = _make_step()
    changed_step = replace(
        step,
        created_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    preflight = _make_preflight(step=step)

    assert create_action_fingerprint(step, preflight) == create_action_fingerprint(
        changed_step, preflight
    )


def test_fingerprint_rejects_preflight_without_snapshot() -> None:
    step = _make_step()
    preflight = replace(_make_preflight(step=step), step_snapshot=None)

    with pytest.raises(
        ActionFingerprintInputMismatchError,
        match="no validated step snapshot",
    ):
        create_action_fingerprint(step, preflight)


@pytest.mark.parametrize(
    "changed_parameters",
    [
        {"timeout_seconds": 300, "dry_run": True},
        {"timeout_seconds": 30.0, "dry_run": True},
        {"timeout_seconds": 30, "dry_run": False},
        {"timeout_seconds": 30},
        {"timeout_seconds": 30, "dry_run": True, "note": None},
    ],
)
def test_fingerprint_rejects_parameters_changed_after_preflight(
    changed_parameters: dict[str, RemediationParameterValue],
) -> None:
    step = _make_step()
    preflight = _make_preflight(step=step)
    changed_step = replace(step, parameters=changed_parameters)

    with pytest.raises(
        ActionFingerprintInputMismatchError,
        match="differs from the validated preflight snapshot",
    ):
        create_action_fingerprint(changed_step, preflight)


@pytest.mark.parametrize(
    ("field_name", "changed_value"),
    [
        ("plan_id", UUID("00000000-0000-0000-0000-000000000003")),
        ("step_id", UUID("00000000-0000-0000-0000-000000000004")),
        ("position", 2),
        ("action_name", "stop_service"),
        ("risk_level", RemediationRiskLevel.MEDIUM),
        ("target", "orders-api"),
        ("environment", "staging"),
    ],
)
def test_fingerprint_rejects_step_scope_changed_after_preflight(
    field_name: str,
    changed_value: object,
) -> None:
    step = _make_step()
    preflight = _make_preflight(step=step)

    if field_name == "plan_id":
        assert isinstance(changed_value, UUID)
        changed_step = replace(step, plan_id=changed_value)
    elif field_name == "step_id":
        assert isinstance(changed_value, UUID)
        changed_step = replace(step, step_id=changed_value)
    elif field_name == "position":
        assert isinstance(changed_value, int)
        changed_step = replace(step, position=changed_value)
    elif field_name == "action_name":
        assert isinstance(changed_value, str)
        changed_step = replace(step, action_name=changed_value)
    elif field_name == "risk_level":
        assert isinstance(changed_value, RemediationRiskLevel)
        changed_step = replace(step, risk_level=changed_value)
    elif field_name == "target":
        assert isinstance(changed_value, str)
        changed_step = replace(step, target=changed_value)
    elif field_name == "environment":
        assert isinstance(changed_value, str)
        changed_step = replace(step, environment=changed_value)
    else:
        pytest.fail(f"Unexpected remediation step field: {field_name!r}")

    with pytest.raises(
        ActionFingerprintInputMismatchError,
        match="differs from the validated preflight snapshot",
    ):
        create_action_fingerprint(changed_step, preflight)


def test_fingerprint_uses_version_of_trusted_action_catalog() -> None:
    step = _make_step()
    preflight = _make_preflight(step=step)
    catalog = ActionCatalog(definitions=(preflight.action,))

    assert preflight.policy_version == create_action_policy_version(catalog)


def test_fingerprint_changes_when_unrelated_catalog_action_changes() -> None:
    step = _make_step()
    preflight = _make_preflight(step=step)
    additional_action = ActionDefinition(
        action_name="inspect_service",
        description="Inspect service status.",
        effect=ActionEffect.READ_ONLY,
        risk_level=RemediationRiskLevel.LOW,
        allowed_environments=("incident-lab",),
    )
    changed_catalog = ActionCatalog(
        definitions=(preflight.action, additional_action),
    )
    changed_preflight = replace(
        preflight,
        policy_version=create_action_policy_version(changed_catalog),
    )

    assert changed_preflight.policy_version != preflight.policy_version
    assert create_action_fingerprint(step, changed_preflight) != create_action_fingerprint(
        step, preflight
    )


@pytest.mark.parametrize(
    "invalid_policy_version",
    [
        None,
        "",
        "apv:v1:",
        "apv:v1:" + "0" * 63,
        "apv:v1:" + "z" * 64,
        "apv:v1:" + "A" * 64,
        "apv:v2:" + "0" * 64,
        "afp:v2:" + "0" * 64,
    ],
)
def test_fingerprint_rejects_invalid_policy_version(
    invalid_policy_version: str | None,
) -> None:
    step = _make_step()
    preflight = replace(
        _make_preflight(step=step),
        policy_version=invalid_policy_version,
    )

    with pytest.raises(
        ActionFingerprintInputMismatchError,
        match="no valid trusted policy version",
    ):
        create_action_fingerprint(step, preflight)
