"""Domain record of an execution reservation for one remediation step.

This model validates a claim's structure. It does not authorize execution,
reserve a step, or prove that a persisted approval exists. Atomic uniqueness
and approval checks belong to the future PostgreSQL claim repository.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from re import fullmatch
from uuid import UUID, uuid4


@dataclass(frozen=True, slots=True, kw_only=True)
class ExecutionClaim:
    """Immutable record describing the scope of an execution reservation."""

    plan_id: UUID
    step_id: UUID
    request_id: UUID
    action_fingerprint: str
    policy_version: str
    claimed_at: datetime

    claim_id: UUID = field(default_factory=uuid4)

    def __post_init__(self) -> None:
        """Reject malformed claim identifiers, scope and timestamps."""
        for field_name, value in (
            ("claim_id", self.claim_id),
            ("plan_id", self.plan_id),
            ("step_id", self.step_id),
            ("request_id", self.request_id),
        ):
            if not isinstance(value, UUID):
                raise ValueError(f"Execution claim {field_name} must be a UUID.")

        if (
            type(self.action_fingerprint) is not str
            or fullmatch(r"afp:v2:[0-9a-f]{64}", self.action_fingerprint) is None
        ):
            raise ValueError("Execution claim requires a valid action fingerprint.")

        if (
            type(self.policy_version) is not str
            or fullmatch(r"apv:v1:[0-9a-f]{64}", self.policy_version) is None
        ):
            raise ValueError("Execution claim requires a valid policy version.")

        if not isinstance(self.claimed_at, datetime) or self.claimed_at.utcoffset() != timedelta(0):
            raise ValueError("Execution claim claimed_at must use UTC.")
