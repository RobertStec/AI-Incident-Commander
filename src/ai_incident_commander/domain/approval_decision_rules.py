"""Domain rules for matching approval decisions to their requests."""

from ai_incident_commander.domain.remediation_approval import (
    RemediationApprovalDecision,
    RemediationApprovalRequest,
)


class ApprovalDecisionRequestMismatchError(ValueError):
    """Raised when a decision refers to another approval request."""


class ApprovalDecisionOutsideWindowError(ValueError):
    """Raised when a decision timestamp is outside the request window."""


def validate_approval_decision_for_request(
    request: RemediationApprovalRequest,
    decision: RemediationApprovalDecision,
) -> None:
    """Validate the structural and temporal relationship of a decision."""
    if decision.request_id != request.request_id:
        raise ApprovalDecisionRequestMismatchError(
            "Approval decision does not belong to the approval request."
        )

    if not (request.requested_at <= decision.decided_at < request.expires_at):
        raise ApprovalDecisionOutsideWindowError(
            "Approval decision is outside the request validity window."
        )
