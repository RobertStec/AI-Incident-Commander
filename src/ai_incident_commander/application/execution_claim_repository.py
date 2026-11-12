"""Application port for atomic, approval-bound remediation execution claims.

A claim reserves one remediation step; it does not execute an MCP action.
"""

from typing import Protocol
from uuid import UUID

from ai_incident_commander.domain.execution_claim import ExecutionClaim


class ExecutionClaimRepositoryError(Exception):
    """Base class for expected execution-claim persistence refusals."""


class ExecutionClaimAlreadyExistsError(ExecutionClaimRepositoryError):
    """The remediation step was already claimed, including by an earlier retry."""


class ExecutionClaimApprovalDeniedError(ExecutionClaimRepositoryError):
    """No persisted APPROVED decision exists for the specified request."""


class ExecutionClaimScopeMismatchError(ExecutionClaimRepositoryError):
    """The requested execution scope does not match the persisted approval."""


class ExecutionClaimRepository(Protocol):
    """Atomically claim an approved remediation step at most once.

    The implementation must enforce the following in ONE PostgreSQL transaction:
    - load the persisted approval request and decision, and require APPROVED;
    - compare plan_id, step_id, action_fingerprint and policy_version with
      the persisted approval request (never trust caller-provided scope alone);
    - enforce uniqueness by (plan_id, step_id), across ALL request IDs;
    - obtain claimed_at from the PostgreSQL clock and commit before returning.

    Every call for an already claimed step must raise
    ExecutionClaimAlreadyExistsError, even if all parameters match. It must
    never return an existing claim as a fresh right to execute.

    Missing/pending/rejected approval raises ExecutionClaimApprovalDeniedError;
    mismatched scope raises ExecutionClaimScopeMismatchError. Unexpected SQL
    errors must propagate, not be converted into an authorization success.

    A higher-level service must first run the trusted execution guard and
    supply its verified scope. Atomic database checks do not eliminate the
    race with a changing external target between preflight and MCP execution.
    """

    async def claim_once(
        self,
        *,
        request_id: UUID,
        plan_id: UUID,
        step_id: UUID,
        action_fingerprint: str,
        policy_version: str,
    ) -> ExecutionClaim:
        """Reserve one step or refuse; no caller-supplied claim time or ID."""
        ...
