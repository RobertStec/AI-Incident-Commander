"""Structural checks for dispatch errors and the read-only repository operation.

PostgreSQL transaction and concurrency behavior is covered by integration tests.
"""

import inspect
from typing import get_type_hints
from uuid import UUID

import pytest

from ai_incident_commander.application import remediation_dispatch_repository as dispatch_module
from ai_incident_commander.application.remediation_dispatch_repository import (
    RemediationDispatchAlreadyReservedError,
    RemediationDispatchExecutionNotExecutingError,
    RemediationDispatchExecutionNotFoundError,
    RemediationDispatchRepositoryError,
    RemediationVerifiedDispatchRepository,
)
from ai_incident_commander.domain.remediation_dispatch import RemediationDispatch


def test_unscoped_legacy_repository_port_is_not_exported() -> None:
    assert not hasattr(dispatch_module, "RemediationDispatchRepository")


def test_read_is_async_and_only_accepts_keyword_execution_id() -> None:
    method = RemediationVerifiedDispatchRepository.get_by_execution_id
    assert inspect.iscoroutinefunction(method)
    signature = inspect.signature(method)
    assert tuple(signature.parameters) == ("self", "execution_id")
    assert signature.parameters["execution_id"].kind is inspect.Parameter.KEYWORD_ONLY
    hints = get_type_hints(method)
    assert hints["execution_id"] is UUID
    assert hints["return"] == RemediationDispatch | None


def test_repository_base_error_is_an_exception() -> None:
    assert issubclass(RemediationDispatchRepositoryError, Exception)


@pytest.mark.parametrize(
    "error_type",
    (
        RemediationDispatchExecutionNotFoundError,
        RemediationDispatchExecutionNotExecutingError,
        RemediationDispatchAlreadyReservedError,
    ),
)
def test_expected_refusals_share_repository_error(error_type: type[Exception]) -> None:
    assert issubclass(error_type, RemediationDispatchRepositoryError)
