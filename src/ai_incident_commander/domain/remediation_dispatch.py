"""Domain record of a reservation for one external remediation dispatch.

A reservation must be durably committed *before* attempting an MCP call.
This record is not a capability or evidence that a call was sent or succeeded.
The future PostgreSQL repository must enforce at most one reservation per
execution_id and require a persisted EXECUTING execution in the same transaction.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from uuid import UUID, uuid4


@dataclass(frozen=True, slots=True, kw_only=True)
class RemediationDispatch:
    """Immutable snapshot of an already-reserved external dispatch attempt.

    A newly constructed object does not itself reserve a dispatch. The trusted
    persistence adapter owns the unique constraint, database time and commit.
    """

    execution_id: UUID
    reserved_at: datetime
    dispatch_id: UUID = field(default_factory=uuid4)

    def __post_init__(self) -> None:
        for field_name, value in (
            ("execution_id", self.execution_id),
            ("dispatch_id", self.dispatch_id),
        ):
            if not isinstance(value, UUID):
                raise ValueError(f"Remediation dispatch {field_name} must be a UUID.")

        if not isinstance(self.reserved_at, datetime) or self.reserved_at.utcoffset() != timedelta(
            0
        ):
            raise ValueError("Remediation dispatch reserved_at must use UTC.")
