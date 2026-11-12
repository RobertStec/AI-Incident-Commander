"""Coordinate trusted execution scope verification and a durable claim.

The service only reserves execution. It never invokes an MCP tool.
"""

from uuid import UUID

from ai_incident_commander.application.approval_execution_guard import ApprovalExecutionGuard
from ai_incident_commander.application.execution_claim_repository import ExecutionClaimRepository
from ai_incident_commander.domain.execution_claim import ExecutionClaim
from ai_incident_commander.domain.remediation import RemediationStep


class ExecutionClaimService:
    """Verify the proposed step once, then atomically claim its verified scope."""

    def __init__(
        self,
        *,
        guard: ApprovalExecutionGuard,
        repository: ExecutionClaimRepository,
    ) -> None:
        self._guard = guard
        self._repository = repository

    async def claim_for_step(self, *, request_id: UUID, step: RemediationStep) -> ExecutionClaim:
        """Return a newly committed claim, or propagate a fail-closed refusal.

        Scope always comes from the trusted guard, never from caller-supplied
        fingerprints or an independently repeated preflight. The repository
        independently checks the persisted approval inside its transaction.
        """
        scope = await self._guard.verify_scope_for_step(request_id=request_id, step=step)
        return await self._repository.claim_once(
            request_id=scope.request_id,
            plan_id=scope.plan_id,
            step_id=scope.step_id,
            action_fingerprint=scope.action_fingerprint,
            policy_version=scope.policy_version,
        )
