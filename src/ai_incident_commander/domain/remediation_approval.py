"""Domain models for human approval of remediation actions."""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import StrEnum
from re import fullmatch
from uuid import UUID, uuid4


@dataclass(frozen=True, slots=True, kw_only=True)
class RemediationApprovalRequest:
    """Request human approval for one exact remediation action."""

    plan_id: UUID
    step_id: UUID
    action_fingerprint: str
    policy_version: str
    requested_at: datetime
    expires_at: datetime

    request_id: UUID = field(default_factory=uuid4)

    def __post_init__(self) -> None:
        """Validate the structural invariants of an approval request."""
        for field_name, value in (
            ("request_id", self.request_id),
            ("plan_id", self.plan_id),
            ("step_id", self.step_id),
        ):
            if not isinstance(value, UUID):
                raise ValueError(f"Approval request {field_name} must be a UUID.")

        if (
            type(self.action_fingerprint) is not str
            or fullmatch(
                r"afp:v2:[0-9a-f]{64}",
                self.action_fingerprint,
            )
            is None
        ):
            raise ValueError("Approval request requires a valid action fingerprint.")

        if (
            type(self.policy_version) is not str
            or fullmatch(
                r"apv:v1:[0-9a-f]{64}",
                self.policy_version,
            )
            is None
        ):
            raise ValueError("Approval request requires a valid policy version.")

        for field_name, timestamp in (
            ("requested_at", self.requested_at),
            ("expires_at", self.expires_at),
        ):
            if not isinstance(timestamp, datetime) or timestamp.utcoffset() != timedelta(0):
                raise ValueError(f"Approval request {field_name} must use UTC.")

        if self.expires_at <= self.requested_at:
            raise ValueError("Approval request expires_at must be later than requested_at.")


class RemediationApprovalOutcome(StrEnum):
    """Possible outcomes of a human remediation approval decision."""

    APPROVED = "approved"
    REJECTED = "rejected"


@dataclass(frozen=True, slots=True, kw_only=True)
class RemediationApprovalDecision:
    """Immutable record of one human approval decision."""

    request_id: UUID
    operator_id: str
    outcome: RemediationApprovalOutcome
    decided_at: datetime
    reason: str

    decision_id: UUID = field(default_factory=uuid4)

    def __post_init__(self) -> None:
        """Validate the structural invariants of an approval decision."""
        for field_name, value in (
            ("decision_id", self.decision_id),
            ("request_id", self.request_id),
        ):
            if not isinstance(value, UUID):
                raise ValueError(f"Approval decision {field_name} must be a UUID.")

        if type(self.operator_id) is not str or not self.operator_id.strip():
            raise ValueError("Approval decision operator_id must be a non-empty string.")

        if not isinstance(self.outcome, RemediationApprovalOutcome):
            raise ValueError("Approval decision outcome must be a valid approval outcome.")

        if not isinstance(self.decided_at, datetime) or self.decided_at.utcoffset() != timedelta(0):
            raise ValueError("Approval decision decided_at must use UTC.")

        if type(self.reason) is not str or not self.reason.strip():
            raise ValueError("Approval decision reason must be a non-empty string.")
