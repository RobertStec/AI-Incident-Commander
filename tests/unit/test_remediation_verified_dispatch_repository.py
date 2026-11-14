"""Structural contract tests for a scope-bound dispatch persistence boundary.

These tests do not prove the future PostgreSQL adapter's atomic behavior.
"""

import inspect
from typing import Protocol, get_type_hints
from uuid import UUID

import pytest

from ai_incident_commander.application.approval_execution_guard import (
    VerifiedExecutionScope,
)
from ai_incident_commander.application.remediation_dispatch_repository import (
    RemediationDispatchApprovalDeniedError,
    RemediationDispatchRepository,
    RemediationDispatchRepositoryError,
    RemediationDispatchScopeMismatchError,
    RemediationVerifiedDispatchRepository,
)
from ai_incident_commander.domain.remediation_dispatch import RemediationDispatch


def test_verified_dispatch_repository_is_a_protocol() -> None:
    assert issubclass(RemediationVerifiedDispatchRepository, Protocol)


def test_verified_reservation_requires_keyword_only_arguments() -> None:
    signature = inspect.signature(RemediationVerifiedDispatchRepository.reserve_verified_once)
    assert tuple(signature.parameters) == ("self", "execution_id", "verified_scope")
    assert signature.parameters["execution_id"].kind is inspect.Parameter.KEYWORD_ONLY
    assert signature.parameters["verified_scope"].kind is inspect.Parameter.KEYWORD_ONLY


def test_verified_reservation_has_expected_types() -> None:
    hints = get_type_hints(RemediationVerifiedDispatchRepository.reserve_verified_once)
    assert hints == {
        "execution_id": UUID,
        "verified_scope": VerifiedExecutionScope,
        "return": RemediationDispatch,
    }


def test_verified_reservation_is_async() -> None:
    assert inspect.iscoroutinefunction(RemediationVerifiedDispatchRepository.reserve_verified_once)


@pytest.mark.parametrize(
    "error_type",
    (RemediationDispatchApprovalDeniedError, RemediationDispatchScopeMismatchError),
)
def test_verified_dispatch_refusals_extend_repository_error(
    error_type: type[Exception],
) -> None:
    assert issubclass(error_type, RemediationDispatchRepositoryError)


def test_verified_port_has_no_unscoped_reserve_method() -> None:
    assert "reserve_once" not in vars(RemediationVerifiedDispatchRepository)
    assert "reserve_verified_once" in vars(RemediationVerifiedDispatchRepository)


def test_existing_legacy_port_retains_its_signatures_for_staged_migration() -> None:
    signature = inspect.signature(RemediationDispatchRepository.reserve_once)
    assert tuple(signature.parameters) == ("self", "execution_id")
    assert signature.parameters["execution_id"].kind is inspect.Parameter.KEYWORD_ONLY
    assert inspect.iscoroutinefunction(RemediationDispatchRepository.get_by_execution_id)
