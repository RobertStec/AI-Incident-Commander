"""Application port for authorizing human remediation decisions."""

from dataclasses import dataclass
from typing import Protocol

from ai_incident_commander.domain.remediation_approval import (
    RemediationApprovalOutcome,
    RemediationApprovalRequest,
)


class ApprovalAuthorizationError(Exception):
    """Base error for approval authorization failures."""


class ApprovalPermissionDeniedError(ApprovalAuthorizationError):
    """Raised when an operator cannot decide an approval request."""


@dataclass(frozen=True, slots=True, kw_only=True)
class AuthenticatedOperatorContext:
    """Operator identity supplied by a verified authentication boundary.

    Constructing this object does not itself authenticate an operator.
    The authentication adapter must supply a stable, trusted operator ID.
    """

    operator_id: str

    def __post_init__(self) -> None:
        """Reject missing or non-canonical operator identifiers."""
        if (
            type(self.operator_id) is not str
            or not self.operator_id
            or self.operator_id != self.operator_id.strip()
        ):
            raise ValueError("Authenticated operator_id must be a non-empty canonical string.")


class ApprovalAuthorizer(Protocol):
    """Authorize an operator to decide a remediation approval request."""

    async def ensure_can_decide(
        self,
        *,
        operator: AuthenticatedOperatorContext,
        request: RemediationApprovalRequest,
        outcome: RemediationApprovalOutcome,
    ) -> None:
        """Return on success or raise ApprovalPermissionDeniedError."""
        ...
