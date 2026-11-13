"""Persistence port for the durable lifecycle of one remediation execution.

A claimed remediation step may start at most one execution attempt. This port
records execution state; it never calls MCP or authorizes a new attempt.
"""

from typing import Protocol
from uuid import UUID

from ai_incident_commander.application.approval_execution_guard import (
    VerifiedExecutionScope,
)
from ai_incident_commander.domain.execution_claim_recovery_policy import (
    ExecutionClaimRecoveryWindowPolicy,
)
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


class RemediationExecutionRecoveryDeniedError(RemediationExecutionRepositoryError):
    """Base class for expected recovery-specific refusals; never a retry signal."""


class RemediationExecutionRecoveryApprovalDeniedError(RemediationExecutionRecoveryDeniedError):
    """The persisted approval is missing, rejected or inconsistent."""


class RemediationExecutionRecoveryScopeMismatchError(RemediationExecutionRecoveryDeniedError):
    """The freshly verified scope differs from the committed claim or approval."""


class RemediationExecutionRecoveryWindowNotSatisfiedError(RemediationExecutionRecoveryDeniedError):
    """The claim is too old or its timestamp is later than trusted database time."""


class RemediationExecutionRecoveryRepository(Protocol):
    """Specialized, fail-closed persistence port for recovering a committed claim.

    This is intentionally distinct from the standard RemediationExecutionRepository:
    the normal start_once() path must remain unchanged. Only a trusted recovery
    service may call this method, after obtaining verified_scope from a fresh
    ApprovalExecutionGuard.verify_scope_for_step() call. A caller-created scope
    is not itself proof of authorization.

    An implementation MUST, in one PostgreSQL transaction:

    * lock the committed claim for this claim_id (SELECT ... FOR UPDATE), or
      raise RemediationExecutionClaimNotFoundError;
    * verify that the claim and persisted approval request/decision agree on
      request ID, plan/step IDs, fingerprint and policy version, and that the
      persisted decision was APPROVED within its decision window;
    * compare those durable fields with freshly verified_scope;
    * enforce recovery_policy.max_claim_age using clock_timestamp() from
      PostgreSQL AFTER acquiring the claim lock and when authorizing INSERT:
      0 <= database_now - claimed_at < max_claim_age;
    * refuse if any execution for claim_id already exists, including EXECUTING
      or a terminal outcome; UNIQUE(claim_id) is the final concurrent safeguard;
    * commit exactly one EXECUTING attempt before returning the record.

    Deny missing/invalid approval with RecoveryApprovalDeniedError, changed
    scope with RecoveryScopeMismatchError, time outside the configured window
    with RecoveryWindowNotSatisfiedError, and prior attempts with the existing
    RemediationExecutionAlreadyStartedError. Unexpected DB errors propagate.

    This transaction cannot lock an external MCP target. Preflight-to-external
    action TOCTOU and idempotent external effects require provider-side guards
    or reconciliation in the future executor. This method never invokes MCP.
    """

    async def start_recovered_once(
        self,
        *,
        claim_id: UUID,
        verified_scope: VerifiedExecutionScope,
        recovery_policy: ExecutionClaimRecoveryWindowPolicy,
    ) -> RemediationExecution:
        """Commit a safe recovery start or refuse without creating a second claim."""
        ...
