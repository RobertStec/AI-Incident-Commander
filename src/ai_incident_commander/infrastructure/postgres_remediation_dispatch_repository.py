"""PostgreSQL persistence for a single durable remediation dispatch reservation.

This adapter reserves a dispatch *before* a possible MCP call. It neither
verifies action authorization nor executes an external operation.
"""

from datetime import UTC
from uuid import UUID, uuid4

import sqlalchemy as sa
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncEngine

from ai_incident_commander.application.remediation_dispatch_repository import (
    RemediationDispatchAlreadyReservedError,
    RemediationDispatchExecutionNotExecutingError,
    RemediationDispatchExecutionNotFoundError,
)
from ai_incident_commander.domain.remediation_dispatch import RemediationDispatch
from ai_incident_commander.domain.remediation_execution import RemediationExecutionStatus
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
    Reading a reservation never permits an MCP call or retry.
    """

    def __init__(self, *, engine: AsyncEngine) -> None:
        self._engine = engine

    async def reserve_once(self, *, execution_id: UUID) -> RemediationDispatch:
        """Commit one reservation with PostgreSQL time or refuse, without retry."""
        lock_execution = (
            sa.select(remediation_executions_table.c.status)
            .where(remediation_executions_table.c.execution_id == execution_id)
            .with_for_update()
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
                result = await connection.execute(lock_execution)
                status = result.scalar_one_or_none()
                if status is None:
                    raise RemediationDispatchExecutionNotFoundError(
                        "Remediation execution does not exist."
                    )
                if status != RemediationExecutionStatus.EXECUTING.value:
                    raise RemediationDispatchExecutionNotExecutingError(
                        "Remediation execution is no longer EXECUTING."
                    )

                existing = await connection.execute(find_reservation)
                if existing.scalar_one_or_none() is not None:
                    raise RemediationDispatchAlreadyReservedError(
                        "A dispatch has already been reserved for this execution."
                    )

                reserved_at = (await connection.execute(insert_reservation)).scalar_one()
        except IntegrityError as exc:
            # Convert only the known uniqueness conflict; do not hide FK, PK,
            # CHECK, or other database errors as an ordinary retry refusal.
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

        # Successful return is possible only after the transaction commits.
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
