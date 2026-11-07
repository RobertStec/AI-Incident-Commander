"""Unit tests for resolved remediation target identities."""

from dataclasses import FrozenInstanceError
from typing import cast

import pytest

from ai_incident_commander.domain.target_identity import ResolvedTarget


def _make_resolved_target(
    *,
    target: str = "payments-api",
    resource_id: str = "service-123",
    environment: str = "incident-lab",
    source: str = "service-inventory",
) -> ResolvedTarget:
    """Create a valid resolved target for domain tests."""
    return ResolvedTarget(
        target=target,
        resource_id=resource_id,
        environment=environment,
        source=source,
    )


def test_resolved_target_preserves_all_identity_fields() -> None:
    resolved = _make_resolved_target()

    assert resolved.target == "payments-api"
    assert resolved.resource_id == "service-123"
    assert resolved.environment == "incident-lab"
    assert resolved.source == "service-inventory"


@pytest.mark.parametrize(
    "environment",
    [
        "incident-lab",
        "production",
        "staging_eu_1",
    ],
)
def test_resolved_target_accepts_valid_environments(
    environment: str,
) -> None:
    resolved = _make_resolved_target(environment=environment)

    assert resolved.environment == environment


@pytest.mark.parametrize(
    "field_name",
    ["target", "resource_id", "environment", "source"],
)
@pytest.mark.parametrize("invalid_value", ["", " \t\n "])
def test_resolved_target_rejects_empty_or_blank_fields(
    field_name: str,
    invalid_value: str,
) -> None:
    values = {
        "target": "payments-api",
        "resource_id": "service-123",
        "environment": "incident-lab",
        "source": "service-inventory",
    }
    values[field_name] = invalid_value

    with pytest.raises(
        ValueError,
        match=f"Resolved target {field_name} must be a non-empty string",
    ):
        _make_resolved_target(
            target=values["target"],
            resource_id=values["resource_id"],
            environment=values["environment"],
            source=values["source"],
        )


@pytest.mark.parametrize(
    ("field_name", "invalid_value"),
    [
        ("target", None),
        ("resource_id", 123),
        ("environment", False),
        ("source", ["service-inventory"]),
    ],
)
def test_resolved_target_rejects_non_string_fields(
    field_name: str,
    invalid_value: object,
) -> None:
    values = {
        "target": "payments-api",
        "resource_id": "service-123",
        "environment": "incident-lab",
        "source": "service-inventory",
    }
    values[field_name] = cast(str, invalid_value)

    with pytest.raises(
        ValueError,
        match=f"Resolved target {field_name} must be a non-empty string",
    ):
        _make_resolved_target(
            target=values["target"],
            resource_id=values["resource_id"],
            environment=values["environment"],
            source=values["source"],
        )


@pytest.mark.parametrize(
    "environment",
    [
        "Production",
        "incident lab",
        "*",
        "_staging",
        "-staging",
        "staging.eu",
        "staging/blue",
    ],
)
def test_resolved_target_rejects_invalid_environment_identifiers(
    environment: str,
) -> None:
    with pytest.raises(
        ValueError,
        match="environment must use a lowercase environment identifier",
    ):
        _make_resolved_target(environment=environment)


def test_resolved_target_does_not_normalize_identity_values() -> None:
    resolved = _make_resolved_target(
        target=" payments-api ",
        resource_id=" arn:example:service:123 ",
        source=" service-inventory ",
    )

    assert resolved.target == " payments-api "
    assert resolved.resource_id == " arn:example:service:123 "
    assert resolved.source == " service-inventory "


def test_resolved_target_cannot_be_modified_directly() -> None:
    resolved = _make_resolved_target()
    field_name = "environment"

    with pytest.raises(FrozenInstanceError):
        setattr(resolved, field_name, "production")

    assert resolved.environment == "incident-lab"
