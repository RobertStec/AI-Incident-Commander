"""Persistence contract for at-most-once reservation of an external dispatch.

Reserving a dispatch is a database fact, NOT permission for an arbitrary caller
or LangGraph replay to invoke MCP. Only a trusted application boundary may
request a scope-bound reservation; a committed record is not an MCP permit.
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

    Only the scope-bound reservation is part of this persistence contract.
    No unscoped reserve_once() entry point may be exposed through this port.
    The concrete adapter's legacy implementation must be removed separately
    before production MCP calls are enabled.

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

    async def get_by_execution_id(self, *, execution_id: UUID) -> RemediationDispatch | None:
        """Read a committed reservation; never grant a send or retry right."""
        ...
