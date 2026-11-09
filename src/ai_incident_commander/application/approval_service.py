"""Application service for recording human remediation decisions."""

from datetime import datetime, timedelta
from uuid import UUID

from ai_incident_commander.application.approval_authorization import (
    ApprovalAuthorizer,
    AuthenticatedOperatorContext,
)
from ai_incident_commander.application.approval_repository import (
    ApprovalRepository,
    ApprovalRequestNotFoundError,
)
from ai_incident_commander.application.clock import Clock
from ai_incident_commander.domain.approval_decision_rules import (
    validate_approval_decision_for_request,
)
from ai_incident_commander.domain.remediation_approval import (
    RemediationApprovalDecision,
    RemediationApprovalOutcome,
)


class ApprovalClockError(ValueError):
    """Raised when the application clock does not provide UTC time."""


class ApprovalApplicationService:
    """Authorize and record a human decision for an approval request."""

    def __init__(
        self,
        *,
        repository: ApprovalRepository,
        authorizer: ApprovalAuthorizer,
        clock: Clock,
    ) -> None:
        self._repository = repository
        self._authorizer = authorizer
        self._clock = clock

    def _current_utc_time(self) -> datetime:
        """Read and validate the application-provided UTC time."""
        current_time = self._clock.now()

        if not isinstance(current_time, datetime) or current_time.utcoffset() != timedelta(0):
            raise ApprovalClockError("Approval clock must return a timezone-aware UTC datetime.")

        return current_time

    async def decide(
        self,
        *,
        request_id: UUID,
        operator: AuthenticatedOperatorContext,
        outcome: RemediationApprovalOutcome,
        reason: str,
    ) -> RemediationApprovalDecision:
        """Authorize, validate and atomically record an approval decision."""
        request = await self._repository.get_request(request_id)

        if request is None:
            raise ApprovalRequestNotFoundError("Approval request does not exist.")

        await self._authorizer.ensure_can_decide(
            operator=operator,
            request=request,
            outcome=outcome,
        )

        decision = RemediationApprovalDecision(
            request_id=request.request_id,
            operator_id=operator.operator_id,
            outcome=outcome,
            decided_at=self._current_utc_time(),
            reason=reason,
        )

        validate_approval_decision_for_request(
            request,
            decision,
        )

        await self._repository.record_decision_once(decision)

        return decision
