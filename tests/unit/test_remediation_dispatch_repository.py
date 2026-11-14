"""Structural contract checks for the remediation dispatch persistence port.

These tests do not verify PostgreSQL transactions or concurrency; that requires
an adapter and real database integration tests in the next implementation step.
"""

import inspect
from typing import get_type_hints
from uuid import UUID

import pytest

from ai_incident_commander.application.remediation_dispatch_repository import (
    RemediationDispatchAlreadyReservedError,
    RemediationDispatchExecutionNotExecutingError,
    RemediationDispatchExecutionNotFoundError,
    RemediationDispatchRepository,
    RemediationDispatchRepositoryError,
)
from ai_incident_commander.domain.remediation_dispatch import RemediationDispatch


def test_repository_is_a_protocol() -> None:
    assert RemediationDispatchRepository._is_protocol  # type: ignore[attr-defined]


def test_reserve_once_is_async_and_only_accepts_keyword_execution_id() -> None:
    method = RemediationDispatchRepository.reserve_once
    assert inspect.iscoroutinefunction(method)
    signature = inspect.signature(method)
    assert tuple(signature.parameters) == ("self", "execution_id")
    assert signature.parameters["execution_id"].kind is inspect.Parameter.KEYWORD_ONLY
    hints = get_type_hints(method)
    assert hints["execution_id"] is UUID
    assert hints["return"] is RemediationDispatch


def test_read_is_async_and_only_accepts_keyword_execution_id() -> None:
    method = RemediationDispatchRepository.get_by_execution_id
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
