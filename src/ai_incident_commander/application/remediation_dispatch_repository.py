"""Persistence contract for at-most-once reservation of an external dispatch.

Reserving a dispatch is a database fact, NOT permission for an arbitrary caller
or LangGraph replay to invoke MCP. A separate trusted application boundary must
reverify the approved operation and bind it to the resolved target.
"""

from typing import Protocol
from uuid import UUID

from ai_incident_commander.application.approval_execution_guard import (
    VerifiedExecutionScope,
)
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


class RemediationDispatchApprovalDeniedError(RemediationDispatchRepositoryError):
    """The persisted approval is missing, rejected, or inconsistent."""


class RemediationDispatchScopeMismatchError(RemediationDispatchRepositoryError):
    """The execution's persisted claim and approval differ from the verified scope."""


class RemediationVerifiedDispatchRepository(Protocol):
    """Atomically bind a fresh trusted scope to one durable dispatch reservation.

    Only a trusted dispatch service may call reserve_verified_once(), using the
    scope returned by a fresh ApprovalExecutionGuard verification. The scope
    is data, NOT a self-authenticating capability.

    In ONE PostgreSQL transaction, the implementation MUST:

    * Lock the execution row; require status EXECUTING.
    * Follow execution -> claim -> approval request / decision in durable data.
    * Require an APPROVED decision consistent with its request and its
      original decision window.
    * Verify request_id, plan_id, step_id, action_fingerprint and policy_version
      agree across the persisted claim and approval and verified_scope.
    * Refuse any existing dispatch, including identical retries.
    * Insert at most one dispatch (UNIQUE(execution_id)), generate the ID on
      the persistence side, use the PostgreSQL clock and commit before return.
    * Propagate unexpected database failures; never retry silently.

    Use the existing NotFound, NotExecuting and AlreadyReserved errors, plus
    ApprovalDenied or ScopeMismatch for scope-specific refusals.

    The legacy RemediationDispatchRepository.reserve_once(execution_id) only
    guarantees an unscoped reservation. It MUST NOT be used by the future MCP
    execution path. Its removal or restriction must be completed before any
    production MCP dispatch can occur.

    A committed reservation is NOT evidence that MCP was invoked and is never
    permission to send or resend a request after crash or replay. This port
    cannot prevent external target changes after a trusted preflight.
    """

    async def reserve_verified_once(
        self,
        *,
        execution_id: UUID,
        verified_scope: VerifiedExecutionScope,
    ) -> RemediationDispatch:
        """Commit a scope-bound dispatch reservation or refuse without retry."""
        ...
