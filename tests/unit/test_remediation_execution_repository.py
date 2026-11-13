"""Structural contract tests for remediation execution lifecycle persistence."""

import inspect
from typing import Protocol, get_type_hints
from uuid import UUID

import pytest

from ai_incident_commander.application.remediation_execution_repository import (
    RemediationExecutionAlreadyStartedError,
    RemediationExecutionClaimNotFoundError,
    RemediationExecutionNotFoundError,
    RemediationExecutionOutcomeNotAllowedError,
    RemediationExecutionRepository,
    RemediationExecutionRepositoryError,
)
from ai_incident_commander.domain.remediation_execution import (
    RemediationExecution,
    RemediationExecutionStatus,
)


def test_repository_is_an_application_protocol() -> None:
    assert issubclass(RemediationExecutionRepository, Protocol)


@pytest.mark.parametrize(
    ("method_name", "parameters", "expected_types"),
    [
        (
            "start_once",
            ("claim_id",),
            {"claim_id": UUID, "return": RemediationExecution},
        ),
        (
            "record_outcome_once",
            ("execution_id", "outcome"),
            {
                "execution_id": UUID,
                "outcome": RemediationExecutionStatus,
                "return": RemediationExecution,
            },
        ),
        (
            "get_by_claim_id",
            ("claim_id",),
            {"claim_id": UUID, "return": RemediationExecution | None},
        ),
    ],
)
def test_repository_method_contract(
    method_name: str, parameters: tuple[str, ...], expected_types: dict[str, object]
) -> None:
    method = getattr(RemediationExecutionRepository, method_name)
    assert inspect.iscoroutinefunction(method)
    signature = inspect.signature(method)
    assert tuple(signature.parameters) == ("self", *parameters)
    for name in parameters:
        assert signature.parameters[name].kind is inspect.Parameter.KEYWORD_ONLY
    assert get_type_hints(method) == expected_types


@pytest.mark.parametrize(
    "error_type",
    [
        RemediationExecutionClaimNotFoundError,
        RemediationExecutionAlreadyStartedError,
        RemediationExecutionNotFoundError,
        RemediationExecutionOutcomeNotAllowedError,
    ],
)
def test_expected_refusals_share_repository_error_base(error_type: type[Exception]) -> None:
    assert issubclass(error_type, RemediationExecutionRepositoryError)


def test_expected_refusals_are_distinct() -> None:
    error_types = (
        RemediationExecutionClaimNotFoundError,
        RemediationExecutionAlreadyStartedError,
        RemediationExecutionNotFoundError,
        RemediationExecutionOutcomeNotAllowedError,
    )
    assert len(set(error_types)) == len(error_types)
