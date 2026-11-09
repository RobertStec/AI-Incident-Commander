"""Application port for authorizing human remediation decisions."""

from typing import Protocol

from ai_incident_commander.domain.remediation_approval import (
    RemediationApprovalOutcome,
    RemediationApprovalRequest,
)


class ApprovalAuthorizationError(Exception):
    """Base error for approval authorization failures."""


class ApprovalPermissionDeniedError(ApprovalAuthorizationError):
    """Raised when an operator cannot decide an approval request."""


class ApprovalAuthorizer(Protocol):
    """Authorize an operator to decide a remediation approval request."""

    async def ensure_can_decide(
        self,
        *,
        operator_id: str,
        request: RemediationApprovalRequest,
        outcome: RemediationApprovalOutcome,
    ) -> None:
        """Return on success or raise ApprovalPermissionDeniedError."""
        ...
