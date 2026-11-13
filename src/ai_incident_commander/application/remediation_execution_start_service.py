"""Coordinate a newly approved execution claim with one durable execution start.

This service does not invoke MCP, retry failed operations or recover an existing
claim. The claim and the execution start are separate committed transactions.
"""

from uuid import UUID

from ai_incident_commander.application.execution_claim_service import ExecutionClaimService
from ai_incident_commander.application.remediation_execution_repository import (
    RemediationExecutionRepository,
)
from ai_incident_commander.domain.remediation import RemediationStep
from ai_incident_commander.domain.remediation_execution import RemediationExecution


class RemediationExecutionStartService:
    """Start an execution only after successfully creating a new verified claim."""

    def __init__(
        self,
        *,
        claim_service: ExecutionClaimService,
        execution_repository: RemediationExecutionRepository,
    ) -> None:
        self._claim_service = claim_service
        self._execution_repository = execution_repository

    async def start_for_step(
        self, *, request_id: UUID, step: RemediationStep
    ) -> RemediationExecution:
        """Commit a claim, then commit EXECUTING for exactly that claim.

        A refusal or failure is propagated without retry or compensation. If the
        claim commits but start_once fails, recovery requires a separate trusted
        workflow; repeating this method must not reuse the committed claim.

        The returned record is proof of a durable start, not proof that an
        external MCP action occurred or permission to repeat such an action.
        """
        claim = await self._claim_service.claim_for_step(request_id=request_id, step=step)
        return await self._execution_repository.start_once(claim_id=claim.claim_id)
