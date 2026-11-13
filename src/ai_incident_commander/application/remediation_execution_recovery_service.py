"""Coordinate trusted re-verification before atomically recovering a claim.

A prior claim is only a recovery candidate, not a reusable execution right.
The PostgreSQL recovery repository owns the final authorization checks and
single committed EXECUTING transition. No MCP calls or automatic retries occur.
"""

from uuid import UUID

from ai_incident_commander.application.approval_execution_guard import ApprovalExecutionGuard
from ai_incident_commander.application.execution_claim_repository import ExecutionClaimRepository
from ai_incident_commander.application.remediation_execution_repository import (
    RemediationExecutionClaimNotFoundError,
    RemediationExecutionRecoveryRepository,
)
from ai_incident_commander.domain.execution_claim_recovery_policy import (
    ExecutionClaimRecoveryWindowPolicy,
)
from ai_incident_commander.domain.remediation import RemediationStep
from ai_incident_commander.domain.remediation_execution import RemediationExecution


class RemediationExecutionRecoveryService:
    """Recheck the current scope and request one atomic recovery start."""

    def __init__(
        self,
        *,
        guard: ApprovalExecutionGuard,
        claim_repository: ExecutionClaimRepository,
        recovery_repository: RemediationExecutionRecoveryRepository,
        recovery_policy: ExecutionClaimRecoveryWindowPolicy,
    ) -> None:
        self._guard = guard
        self._claim_repository = claim_repository
        self._recovery_repository = recovery_repository
        self._recovery_policy = recovery_policy

    async def recover_for_step(
        self, *, request_id: UUID, step: RemediationStep
    ) -> RemediationExecution:
        """Recover only a previously committed claim after a fresh trusted Guard.

        A missing claim fails closed without creating a new claim. The Guard's
        result is passed directly to the recovery repository, which rechecks
        the persisted approval, scope, PostgreSQL time and one-start invariant
        inside its own transaction. Refusals and unexpected errors propagate.

        No recovery is attempted for an already-started execution; the
        repository must refuse it. This method never calls MCP or retries.
        """
        claim = await self._claim_repository.get_by_request_id(request_id=request_id)
        if claim is None:
            raise RemediationExecutionClaimNotFoundError(
                "No committed execution claim exists for the request."
            )

        verified_scope = await self._guard.verify_scope_for_step(request_id=request_id, step=step)
        return await self._recovery_repository.start_recovered_once(
            claim_id=claim.claim_id,
            verified_scope=verified_scope,
            recovery_policy=self._recovery_policy,
        )
