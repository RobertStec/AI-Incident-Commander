"""PostgreSQL persistence for a single durable remediation dispatch reservation.

This adapter reserves a dispatch *before* a possible MCP call. It requires a
verified scope and independently checks persisted approval; it never calls MCP.
"""

from datetime import UTC
from uuid import UUID, uuid4

import sqlalchemy as sa
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncEngine

from ai_incident_commander.application.approval_execution_guard import VerifiedExecutionScope
from ai_incident_commander.application.remediation_dispatch_repository import (
    RemediationDispatchAlreadyReservedError,
    RemediationDispatchApprovalDeniedError,
    RemediationDispatchExecutionNotExecutingError,
    RemediationDispatchExecutionNotFoundError,
    RemediationDispatchScopeMismatchError,
)
from ai_incident_commander.domain.remediation_approval import RemediationApprovalOutcome
from ai_incident_commander.domain.remediation_dispatch import RemediationDispatch
from ai_incident_commander.domain.remediation_execution import RemediationExecutionStatus
from ai_incident_commander.infrastructure.approval_tables import (
    approval_decisions_table,
    approval_requests_table,
)
from ai_incident_commander.infrastructure.execution_claim_tables import execution_claims_table
from ai_incident_commander.infrastructure.remediation_dispatch_tables import (
    remediation_dispatches_table,
)
from ai_incident_commander.infrastructure.remediation_execution_tables import (
    remediation_executions_table,
)


class PostgresRemediationDispatchRepository:
    """Reserve at most one dispatch for a committed EXECUTING execution.

    The execution-row lock serializes reservation with lifecycle outcome
    transitions. UNIQUE(execution_id) is a second, database-enforced safeguard.
    Reading a reservation never permits an MCP call or retry. Only the verified
    reservation method may create a dispatch; no unscoped write path exists.
    """

    def __init__(self, *, engine: AsyncEngine) -> None:
        self._engine = engine

    async def reserve_verified_once(
        self,
        *,
        execution_id: UUID,
        verified_scope: VerifiedExecutionScope,
    ) -> RemediationDispatch:
        """Commit one reservation only when persisted execution matches a fresh scope.

        The execution lock serializes with record_outcome_once(). Shared locks on
        the claim and approval rows prevent them changing before this commit.
        The calling trusted service must independently run Guard/Preflight.
        """
        lock_execution = (
            sa.select(
                remediation_executions_table.c.claim_id,
                remediation_executions_table.c.status,
            )
            .where(remediation_executions_table.c.execution_id == execution_id)
            .with_for_update()
        )
        lock_claim = (
            sa.select(execution_claims_table)
            .where(execution_claims_table.c.claim_id == sa.bindparam("expected_claim_id"))
            .with_for_update(read=True)
        )
        lock_request = (
            sa.select(approval_requests_table)
            .where(approval_requests_table.c.request_id == sa.bindparam("expected_request_id"))
            .with_for_update(read=True)
        )
        lock_decision = (
            sa.select(approval_decisions_table)
            .where(approval_decisions_table.c.request_id == sa.bindparam("expected_request_id"))
            .with_for_update(read=True)
        )
        find_reservation = sa.select(remediation_dispatches_table.c.dispatch_id).where(
            remediation_dispatches_table.c.execution_id == execution_id
        )
        dispatch_id = uuid4()
        insert_reservation = (
            sa.insert(remediation_dispatches_table)
            .values(
                dispatch_id=dispatch_id,
                execution_id=execution_id,
                reserved_at=sa.func.clock_timestamp(),
            )
            .returning(remediation_dispatches_table.c.reserved_at)
        )

        try:
            async with self._engine.begin() as connection:
                execution = (await connection.execute(lock_execution)).mappings().one_or_none()
                if execution is None:
                    raise RemediationDispatchExecutionNotFoundError(
                        "Remediation execution does not exist."
                    )
                if execution["status"] != RemediationExecutionStatus.EXECUTING.value:
                    raise RemediationDispatchExecutionNotExecutingError(
                        "Remediation execution is no longer EXECUTING."
                    )

                claim = (
                    (
                        await connection.execute(
                            lock_claim, {"expected_claim_id": execution["claim_id"]}
                        )
                    )
                    .mappings()
                    .one_or_none()
                )
                if claim is None:
                    raise RemediationDispatchApprovalDeniedError(
                        "Execution claim is missing from durable storage."
                    )

                request = (
                    (
                        await connection.execute(
                            lock_request, {"expected_request_id": claim["request_id"]}
                        )
                    )
                    .mappings()
                    .one_or_none()
                )
                decision = (
                    (
                        await connection.execute(
                            lock_decision, {"expected_request_id": claim["request_id"]}
                        )
                    )
                    .mappings()
                    .one_or_none()
                )
                if request is None or decision is None:
                    raise RemediationDispatchApprovalDeniedError(
                        "Persisted approval request or decision is missing."
                    )
                if (
                    decision["outcome"] != RemediationApprovalOutcome.APPROVED.value
                    or decision["request_id"] != request["request_id"]
                    or not (
                        request["requested_at"] <= decision["decided_at"] < request["expires_at"]
                    )
                    or not (
                        request["requested_at"] <= decision["recorded_at"] < request["expires_at"]
                    )
                ):
                    raise RemediationDispatchApprovalDeniedError(
                        "Persisted approval is not a valid in-window APPROVED decision."
                    )

                scope_fields = (
                    "request_id",
                    "plan_id",
                    "step_id",
                    "action_fingerprint",
                    "policy_version",
                )
                if any(claim[name] != request[name] for name in scope_fields):
                    raise RemediationDispatchApprovalDeniedError(
                        "Persisted execution claim conflicts with the approval request."
                    )
                if not isinstance(verified_scope, VerifiedExecutionScope) or any(
                    claim[name] != getattr(verified_scope, name) for name in scope_fields
                ):
                    raise RemediationDispatchScopeMismatchError(
                        "Verified scope differs from the execution's persisted approval."
                    )

                existing = await connection.execute(find_reservation)
                if existing.scalar_one_or_none() is not None:
                    raise RemediationDispatchAlreadyReservedError(
                        "A dispatch has already been reserved for this execution."
                    )
                reserved_at = (await connection.execute(insert_reservation)).scalar_one()
        except IntegrityError as exc:
            original = exc.orig
            diagnostic = getattr(original, "diag", None)
            constraint_name = (
                getattr(diagnostic, "constraint_name", None)
                or getattr(original, "constraint_name", None)
                or getattr(getattr(original, "__cause__", None), "constraint_name", None)
            )
            if (
                getattr(original, "sqlstate", None) == "23505"
                and constraint_name == "uq_remediation_dispatches_execution_id"
            ):
                raise RemediationDispatchAlreadyReservedError(
                    "A dispatch has already been reserved for this execution."
                ) from exc
            raise

        # Transaction has committed before the successful snapshot escapes.
        return RemediationDispatch(
            dispatch_id=dispatch_id,
            execution_id=execution_id,
            reserved_at=reserved_at.astimezone(UTC),
        )

    async def get_by_execution_id(self, *, execution_id: UUID) -> RemediationDispatch | None:
        """Read an existing reservation; never grant dispatch or retry rights."""
        select_reservation = sa.select(remediation_dispatches_table).where(
            remediation_dispatches_table.c.execution_id == execution_id
        )
        async with self._engine.connect() as connection:
            row = (await connection.execute(select_reservation)).mappings().one_or_none()

        if row is None:
            return None
        return RemediationDispatch(
            dispatch_id=row["dispatch_id"],
            execution_id=row["execution_id"],
            reserved_at=row["reserved_at"].astimezone(UTC),
        )
