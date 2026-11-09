"""Application port for persistent remediation approval records."""

from typing import Protocol
from uuid import UUID

from ai_incident_commander.domain.remediation_approval import (
    RemediationApprovalDecision,
    RemediationApprovalRequest,
)


class ApprovalRepositoryError(Exception):
    """Base error for approval persistence failures."""


class ApprovalRequestAlreadyExistsError(ApprovalRepositoryError):
    """Raised when an approval request identifier already exists."""


class ApprovalRequestNotFoundError(ApprovalRepositoryError):
    """Raised when a decision references a missing approval request."""


class ApprovalAlreadyDecidedError(ApprovalRepositoryError):
    """Raised when an approval request already has a decision."""


class ApprovalRepository(Protocol):
    """Persist approval requests and enforce single-decision semantics."""

    async def create_request(
        self,
        request: RemediationApprovalRequest,
    ) -> None:
        """Insert a request or raise ApprovalRequestAlreadyExistsError."""
        ...

    async def get_request(
        self,
        request_id: UUID,
    ) -> RemediationApprovalRequest | None:
        """Retrieve a request, returning None when it does not exist."""
        ...

    async def record_decision_once(
        self,
        decision: RemediationApprovalDecision,
    ) -> None:
        """Atomically record one decision for an existing request."""
        ...
