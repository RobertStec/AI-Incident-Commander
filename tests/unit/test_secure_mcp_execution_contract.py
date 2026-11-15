"""Contract tests: no MCP gateway, network access, or mutations are involved."""

import asyncio
import inspect
from dataclasses import FrozenInstanceError
from typing import get_type_hints
from uuid import UUID, uuid4

import pytest

from ai_incident_commander.application.secure_mcp_execution_contract import (
    McpInvocationOutcome,
    McpInvocationResult,
    SecureMcpExecutor,
)
from ai_incident_commander.domain.remediation import RemediationRiskLevel, RemediationStep


@pytest.mark.parametrize(
    ("outcome", "expected"),
    [
        (McpInvocationOutcome.ACKNOWLEDGED, "acknowledged"),
        (McpInvocationOutcome.REJECTED, "rejected"),
        (McpInvocationOutcome.UNKNOWN, "unknown"),
    ],
)
def test_outcome_values_are_explicit(outcome: McpInvocationOutcome, expected: str) -> None:
    assert outcome.value == expected


def test_result_retains_audit_identifiers_and_observed_outcome() -> None:
    dispatch_id, execution_id = uuid4(), uuid4()

    result = McpInvocationResult(
        dispatch_id=dispatch_id,
        execution_id=execution_id,
        outcome=McpInvocationOutcome.UNKNOWN,
    )

    assert result.dispatch_id == dispatch_id
    assert result.execution_id == execution_id
    assert result.outcome is McpInvocationOutcome.UNKNOWN


def test_result_is_immutable() -> None:
    result = McpInvocationResult(
        dispatch_id=uuid4(),
        execution_id=uuid4(),
        outcome=McpInvocationOutcome.ACKNOWLEDGED,
    )

    with pytest.raises(FrozenInstanceError):
        result.outcome = McpInvocationOutcome.REJECTED  # type: ignore[misc]


@pytest.mark.parametrize("field_name", ["dispatch_id", "execution_id"])
@pytest.mark.parametrize("bad_value", [None, "not-a-uuid", 123])
def test_result_rejects_invalid_identifiers(field_name: str, bad_value: object) -> None:
    kwargs: dict[str, object] = {
        "dispatch_id": uuid4(),
        "execution_id": uuid4(),
        "outcome": McpInvocationOutcome.UNKNOWN,
    }
    kwargs[field_name] = bad_value

    with pytest.raises(ValueError, match=f"MCP invocation {field_name} must be a UUID"):
        McpInvocationResult(**kwargs)  # type: ignore[arg-type]


@pytest.mark.parametrize("bad_outcome", [None, "acknowledged", "failed", 42])
def test_result_rejects_untyped_or_unrecognized_outcomes(bad_outcome: object) -> None:
    with pytest.raises(ValueError, match="must be a McpInvocationOutcome"):
        McpInvocationResult(
            dispatch_id=uuid4(),
            execution_id=uuid4(),
            outcome=bad_outcome,  # type: ignore[arg-type]
        )


def test_executor_port_is_async_and_accepts_only_the_proposed_step() -> None:
    method = SecureMcpExecutor.execute_for_step
    parameters = inspect.signature(method).parameters

    assert inspect.iscoroutinefunction(method)
    assert tuple(parameters) == ("self", "request_id", "step")
    assert parameters["request_id"].kind is inspect.Parameter.KEYWORD_ONLY
    assert parameters["step"].kind is inspect.Parameter.KEYWORD_ONLY
    assert get_type_hints(method) == {
        "request_id": UUID,
        "step": RemediationStep,
        "return": McpInvocationResult,
    }


def test_fake_port_does_not_need_any_mcp_or_postgres_dependency() -> None:
    """A protocol can be implemented without executing anything externally."""

    class RecordingExecutor:
        def __init__(self) -> None:
            self.request_ids: list[UUID] = []

        async def execute_for_step(
            self, *, request_id: UUID, step: RemediationStep
        ) -> McpInvocationResult:
            self.request_ids.append(request_id)
            return McpInvocationResult(
                dispatch_id=uuid4(),
                execution_id=uuid4(),
                outcome=McpInvocationOutcome.UNKNOWN,
            )

    executor: SecureMcpExecutor = RecordingExecutor()
    request_id = uuid4()
    step = RemediationStep(
        plan_id=uuid4(),
        position=1,
        action_name="restart_service",
        target="payments-api",
        environment="incident-lab",
        risk_level=RemediationRiskLevel.HIGH,
    )
    result = asyncio.run(executor.execute_for_step(request_id=request_id, step=step))

    assert isinstance(result, McpInvocationResult)
    assert result.outcome is McpInvocationOutcome.UNKNOWN
    assert isinstance(executor, RecordingExecutor)
    assert executor.request_ids == [request_id]
