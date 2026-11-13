"""Time-window criterion for a previously committed execution claim.

This pure policy does not authorize recovery or external tool execution. A
caller must use trusted PostgreSQL time and independently reverify the current
scope and authorization before a guarded, atomic execution start.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta

from ai_incident_commander.domain.execution_claim import ExecutionClaim


@dataclass(frozen=True, slots=True, kw_only=True)
class ExecutionClaimRecoveryWindowPolicy:
    """Determine only whether a claim is within a configured recovery window.

    No implicit default is provided: a deployment must explicitly choose a
    maximum claim age, distinct from the approval decision window.
    """

    max_claim_age: timedelta

    def __post_init__(self) -> None:
        if not isinstance(self.max_claim_age, timedelta) or self.max_claim_age <= timedelta(0):
            raise ValueError("Recovery maximum claim age must be a positive timedelta.")

    def is_within_time_window(self, *, claim: ExecutionClaim, observed_at: datetime) -> bool:
        """Check [claimed_at, claimed_at + max_claim_age) using trusted UTC time.

        True is a necessary temporal condition, never an authorization to
        call start_once() or execute MCP. A clock preceding the claim fails
        closed rather than being treated as a valid fresh claim.
        """
        if not isinstance(observed_at, datetime) or observed_at.utcoffset() != timedelta(0):
            raise ValueError("Recovery observed_at must be a UTC datetime.")

        age = observed_at - claim.claimed_at
        return timedelta(0) <= age < self.max_claim_age
