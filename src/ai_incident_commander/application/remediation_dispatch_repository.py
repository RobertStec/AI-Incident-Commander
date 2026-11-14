"""Persistence contract for at-most-once reservation of an external dispatch.

Reserving a dispatch is a database fact, NOT permission for an arbitrary caller
or LangGraph replay to invoke MCP. A separate trusted application boundary must
reverify the approved operation and bind it to the resolved target.
"""

from typing import Protocol
from uuid import UUID

from ai_incident_commander.domain.remediation_dispatch import RemediationDispatch


class RemediationDispatchRepositoryError(Exception):
    """Base class for expected dispatch-reservation persistence refusals."""


class RemediationDispatchExecutionNotFoundError(RemediationDispatchRepositoryError):
    """No durable remediation execution exists for this execution_id."""


class RemediationDispatchExecutionNotExecutingError(RemediationDispatchRepositoryError):
    """The durable execution is no longer in EXECUTING state."""


class RemediationDispatchAlreadyReservedError(RemediationDispatchRepositoryError):
    """A dispatch has already been reserved for this execution_id."""


class RemediationDispatchRepository(Protocol):
    """Reserve at most one dispatch per durable execution, or read its record.

    The future PostgreSQL adapter MUST enforce, in a single transaction:

    * The execution exists and currently has status EXECUTING.
    * Lock the execution row to serialize concurrent reservations and outcome
      transitions; UNIQUE(execution_id) is the final database safeguard.
    * An existing reservation is always refused, including identical retries.
    * Generate dispatch_id and reserved_at on the persistence side; use the
      PostgreSQL clock for reserved_at. Commit before returning the record.
    * Unexpected database errors must propagate without silent retries.

    get_by_execution_id() is strictly read-only. A returned reservation is NOT
    permission to send or resend an MCP call, including after a worker crash.

    This contract only protects reservation state; it does not verify an action
    fingerprint, target identity, or caller authorization. A future trusted
    dispatch service must supply those safeguards before MCP is invoked.
    """

    async def reserve_once(self, *, execution_id: UUID) -> RemediationDispatch:
        """Commit one dispatch reservation for an EXECUTING execution or refuse."""
        ...

    async def get_by_execution_id(self, *, execution_id: UUID) -> RemediationDispatch | None:
        """Read a committed reservation; absence returns None, never a retry right."""
        ...
