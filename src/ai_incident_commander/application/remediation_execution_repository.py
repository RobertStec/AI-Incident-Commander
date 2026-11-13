"""Persistence port for the durable lifecycle of one remediation execution.

A claimed remediation step may start at most one execution attempt. This port
records execution state; it never calls MCP or authorizes a new attempt.
"""

from typing import Protocol
from uuid import UUID

from ai_incident_commander.domain.remediation_execution import (
    RemediationExecution,
    RemediationExecutionStatus,
)


class RemediationExecutionRepositoryError(Exception):
    """Base class for expected execution-lifecycle persistence refusals."""


class RemediationExecutionClaimNotFoundError(RemediationExecutionRepositoryError):
    """The supplied execution claim does not exist in durable storage."""


class RemediationExecutionAlreadyStartedError(RemediationExecutionRepositoryError):
    """An execution attempt has already been started for this claim."""


class RemediationExecutionNotFoundError(RemediationExecutionRepositoryError):
    """The specified execution attempt does not exist."""


class RemediationExecutionOutcomeNotAllowedError(RemediationExecutionRepositoryError):
    """The outcome is invalid or the attempt has already left EXECUTING."""


class RemediationExecutionRepository(Protocol):
    """Persist one execution attempt per claim, with atomic state transitions.

    Implementations must enforce these rules in PostgreSQL:

    * start_once() requires an existing persisted ExecutionClaim, atomically
      inserts one EXECUTING attempt per claim_id, and commits before returning.
      Every second call must raise AlreadyStarted, even for an identical retry.
    * started_at and status_changed_at come from the PostgreSQL clock; callers
      cannot supply execution IDs, timestamps or prebuilt records.
    * record_outcome_once() accepts only SUCCEEDED, FAILED or UNKNOWN and
      atomically changes EXECUTING to that state. Concurrent or repeated
      updates must not overwrite the first committed outcome.
    * get_by_claim_id() only reads the durable record and never authorizes
      another attempt; absence is represented by None.
    * All unexpected database errors propagate. No call grants permission
      to retry or automatically invokes an MCP action.

    If a worker crashes after EXECUTING was committed, its outcome is
    uncertain, even when the external call might not have started. Such a
    record must NOT be treated as permission to retry.
    """

    async def start_once(self, *, claim_id: UUID) -> RemediationExecution:
        """Commit a single EXECUTING record for a persisted claim or refuse."""
        ...

    async def record_outcome_once(
        self, *, execution_id: UUID, outcome: RemediationExecutionStatus
    ) -> RemediationExecution:
        """Atomically persist one terminal outcome or refuse."""
        ...

    async def get_by_claim_id(self, *, claim_id: UUID) -> RemediationExecution | None:
        """Read a committed attempt without starting or retrying execution."""
        ...
