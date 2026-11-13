"""Domain lifecycle for one remediation execution attempt.

An ExecutionClaim reserves the step. This record describes a subsequent
execution attempt; it neither creates the claim nor invokes an MCP tool.
Persistence must enforce one attempt per claim and atomic status transitions.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from enum import StrEnum
from uuid import UUID, uuid4


class RemediationExecutionStatus(StrEnum):
    """What is known about the outcome of an execution attempt."""

    EXECUTING = "executing"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    UNKNOWN = "unknown"


_ALLOWED_EXECUTION_TRANSITIONS: dict[
    RemediationExecutionStatus, frozenset[RemediationExecutionStatus]
] = {
    RemediationExecutionStatus.EXECUTING: frozenset(
        {
            RemediationExecutionStatus.SUCCEEDED,
            RemediationExecutionStatus.FAILED,
            RemediationExecutionStatus.UNKNOWN,
        }
    ),
    RemediationExecutionStatus.SUCCEEDED: frozenset(),
    RemediationExecutionStatus.FAILED: frozenset(),
    RemediationExecutionStatus.UNKNOWN: frozenset(),
}


class RemediationExecutionTransitionError(ValueError):
    """An execution status transition is not permitted."""


def can_transition_remediation_execution_status(
    current: RemediationExecutionStatus,
    target: RemediationExecutionStatus,
) -> bool:
    """Return whether the transition is allowed by the initial lifecycle."""
    return (
        isinstance(current, RemediationExecutionStatus)
        and isinstance(target, RemediationExecutionStatus)
        and target in _ALLOWED_EXECUTION_TRANSITIONS[current]
    )


def _require_utc(timestamp: datetime, field_name: str) -> None:
    if not isinstance(timestamp, datetime) or timestamp.utcoffset() != timedelta(0):
        raise ValueError(f"Remediation execution {field_name} must use UTC.")


@dataclass(frozen=True, slots=True, kw_only=True)
class RemediationExecution:
    """Immutable snapshot of one execution attempt tied to a durable claim.

    EXECUTING is persisted *before* an MCP call is attempted. On a crash, an
    EXECUTING record must not trigger an automatic retry: the side effect may
    have happened. UNKNOWN also requires a separate reconciliation workflow.
    """

    claim_id: UUID
    started_at: datetime
    execution_id: UUID = field(default_factory=uuid4)
    status: RemediationExecutionStatus = RemediationExecutionStatus.EXECUTING
    status_changed_at: datetime | None = None

    def __post_init__(self) -> None:
        for field_name, value in (
            ("execution_id", self.execution_id),
            ("claim_id", self.claim_id),
        ):
            if not isinstance(value, UUID):
                raise ValueError(f"Remediation execution {field_name} must be a UUID.")

        if not isinstance(self.status, RemediationExecutionStatus):
            raise ValueError("Remediation execution status must be a valid status.")

        _require_utc(self.started_at, "started_at")
        if self.status is RemediationExecutionStatus.EXECUTING:
            if self.status_changed_at is not None:
                raise ValueError("EXECUTING must not have status_changed_at.")
        else:
            if self.status_changed_at is None:
                raise ValueError("A resolved execution status requires status_changed_at.")
            _require_utc(self.status_changed_at, "status_changed_at")
            if self.status_changed_at < self.started_at:
                raise ValueError("status_changed_at must not precede started_at.")

    def transition_to(
        self,
        target: RemediationExecutionStatus,
        *,
        occurred_at: datetime,
    ) -> RemediationExecution:
        """Return a new snapshot; caller persists transitions atomically.

        The timestamp is explicit so the future PostgreSQL adapter can use its
        database clock. A terminal or UNKNOWN status cannot be retried here.
        """
        if not can_transition_remediation_execution_status(self.status, target):
            raise RemediationExecutionTransitionError(
                f"Transition from {self.status.value} to {target!s} is not allowed."
            )
        return replace(self, status=target, status_changed_at=occurred_at)
