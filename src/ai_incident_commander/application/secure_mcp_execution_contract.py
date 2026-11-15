"""Application contract for a future restricted remediation MCP executor.

This module contains no MCP client, transport, scheduling, or executable side
effects. An implementation must own the trusted dispatch reservation and the
restricted MCP gateway; neither a dispatch record nor a caller-supplied scope
can authorize an invocation.
"""

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol
from uuid import UUID

from ai_incident_commander.domain.remediation import RemediationStep


class McpInvocationOutcome(StrEnum):
    """Observed tool-call outcome, NOT the verified remediation outcome.

    ACKNOWLEDGED: an authenticated MCP response acknowledged the call; actual
        remediation effects still require independent verification.
    REJECTED: the trusted server explicitly confirmed rejection before effects.
        A generic tool error must NOT be treated as proof of no side effects.
    UNKNOWN: a timeout, lost response, crash, or ambiguous tool error means an
        external effect may have occurred. Never automatically replay it.
    """

    ACKNOWLEDGED = "acknowledged"
    REJECTED = "rejected"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True, kw_only=True)
class McpInvocationResult:
    """Immutable observation correlated to one previously reserved dispatch.

    Construction is not proof of persistence, authorization, tool invocation,
    or success. IDs are audit correlations, never bearer capabilities.
    """

    dispatch_id: UUID
    execution_id: UUID
    outcome: McpInvocationOutcome

    def __post_init__(self) -> None:
        for name, value in (
            ("dispatch_id", self.dispatch_id),
            ("execution_id", self.execution_id),
        ):
            if not isinstance(value, UUID):
                raise ValueError(f"MCP invocation {name} must be a UUID.")

        if not isinstance(self.outcome, McpInvocationOutcome):
            raise ValueError("MCP invocation outcome must be a McpInvocationOutcome.")


class SecureMcpExecutor(Protocol):
    """Port for a future trusted, non-replaying MCP execution boundary.

    Callers provide only a request ID and proposed step; these are NOT trusted
    authorization. The implementation must perform a fresh MCP-bound approval
    check, obtain a durable verified dispatch reservation, select the tool from
    a trusted binding, and enforce least-privilege server access. It must not
    accept an execution ID, fabricated VerifiedExecutionScope, or existing
    dispatch as an execution permit.

    A successful reservation does not prove the call was sent. A process crash
    after commit may leave the outcome unknown; no automatic retry or LangGraph
    replay is permitted. Reconciliation and independent verification belong to
    later phases. This protocol alone cannot enforce those safety properties.
    """

    async def execute_for_step(
        self, *, request_id: UUID, step: RemediationStep
    ) -> McpInvocationResult: ...
