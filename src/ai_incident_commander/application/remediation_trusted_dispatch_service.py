"""Coordinate one trusted, scope-bound reservation before a future MCP dispatch.

This service never invokes MCP. A committed reservation is not a reusable
capability, an indication that MCP was called, or permission to replay work.
"""

from dataclasses import dataclass
from uuid import UUID

from ai_incident_commander.application.approval_execution_guard import (
    ApprovalExecutionGuard,
    VerifiedExecutionContext,
)
from ai_incident_commander.application.execution_claim_repository import ExecutionClaimRepository
from ai_incident_commander.application.remediation_dispatch_repository import (
    RemediationDispatchExecutionNotFoundError,
    RemediationVerifiedDispatchRepository,
)
from ai_incident_commander.application.remediation_execution_repository import (
    RemediationExecutionClaimNotFoundError,
    RemediationExecutionRepository,
)
from ai_incident_commander.domain.remediation import RemediationStep
from ai_incident_commander.domain.remediation_dispatch import RemediationDispatch


@dataclass(frozen=True, slots=True, kw_only=True)
class ReservedVerifiedDispatch:
    """Committed reservation and the context verified for this invocation only.

    This value is not a bearer token. Future MCP execution must be restricted
    to a separate trusted, non-replayable execution boundary.
    """

    dispatch: RemediationDispatch
    context: VerifiedExecutionContext


class RemediationTrustedDispatchService:
    """Look up a durable attempt, reverify its scope, and reserve once.

    The final PostgreSQL reserve_verified_once() transaction MUST recheck the
    execution -> claim -> approval relationship, status, and uniqueness. The
    lookups in this service are not authorization decisions and may be stale.
    """

    def __init__(
        self,
        *,
        guard: ApprovalExecutionGuard,
        claim_repository: ExecutionClaimRepository,
        execution_repository: RemediationExecutionRepository,
        dispatch_repository: RemediationVerifiedDispatchRepository,
    ) -> None:
        self._guard = guard
        self._claim_repository = claim_repository
        self._execution_repository = execution_repository
        self._dispatch_repository = dispatch_repository

    async def reserve_for_step(
        self, *, request_id: UUID, step: RemediationStep
    ) -> ReservedVerifiedDispatch:
        """Reserve one dispatch for a previously started, approved execution.

        Neither execution_id nor VerifiedExecutionScope is accepted from the
        caller. A fresh Guard check happens after the read-only lookups and
        immediately before the atomic, scope-bound database reservation.

        Missing records, authorization denials, duplicates and DB failures
        propagate without retry or compensation. This method never calls MCP.
        """
        claim = await self._claim_repository.get_by_request_id(request_id=request_id)
        if claim is None:
            raise RemediationExecutionClaimNotFoundError(
                "No committed execution claim exists for the request."
            )

        execution = await self._execution_repository.get_by_claim_id(claim_id=claim.claim_id)
        if execution is None:
            raise RemediationDispatchExecutionNotFoundError(
                "No committed remediation execution exists for the claim."
            )

        context = await self._guard.verify_execution_context_for_step(
            request_id=request_id, step=step
        )
        dispatch = await self._dispatch_repository.reserve_verified_once(
            execution_id=execution.execution_id,
            verified_scope=context.scope,
        )
        return ReservedVerifiedDispatch(dispatch=dispatch, context=context)
