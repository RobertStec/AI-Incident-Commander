"""PostgreSQL persistence for the remediation execution lifecycle.

This adapter durably starts execution, records terminal outcomes at most once,
and reads committed attempts. It does not invoke MCP or authorize retries.
"""

from datetime import UTC
from uuid import UUID, uuid4

import sqlalchemy as sa
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncEngine

from ai_incident_commander.application.remediation_execution_repository import (
    RemediationExecutionAlreadyStartedError,
    RemediationExecutionClaimNotFoundError,
    RemediationExecutionNotFoundError,
    RemediationExecutionOutcomeNotAllowedError,
)
from ai_incident_commander.domain.remediation_execution import (
    RemediationExecution,
    RemediationExecutionStatus,
)
from ai_incident_commander.infrastructure.execution_claim_tables import (
    execution_claims_table,
)
from ai_incident_commander.infrastructure.remediation_execution_tables import (
    remediation_executions_table,
)


class PostgresRemediationExecutionRepository:
    """Persist the start of an execution attempt before any external side effect.

    The adapter starts one attempt, records its outcome once, and reads the
    committed state. An EXECUTING record never authorizes an automatic retry.
    """

    def __init__(self, *, engine: AsyncEngine) -> None:
        self._engine = engine

    async def start_once(self, *, claim_id: UUID) -> RemediationExecution:
        """Commit one EXECUTING attempt for a persisted claim, or refuse.

        Locking the claim serializes concurrent starts for the same claim; the
        unique constraint remains the database-level guarantee. An existing
        attempt is never returned as a fresh permission to invoke MCP.
        """
        lock_claim = (
            sa.select(execution_claims_table.c.claim_id)
            .where(execution_claims_table.c.claim_id == claim_id)
            .with_for_update()
        )
        find_existing = sa.select(remediation_executions_table.c.execution_id).where(
            remediation_executions_table.c.claim_id == claim_id
        )
        execution_id = uuid4()
        insert_execution = (
            sa.insert(remediation_executions_table)
            .values(
                execution_id=execution_id,
                claim_id=claim_id,
                status=RemediationExecutionStatus.EXECUTING.value,
                started_at=sa.func.clock_timestamp(),
                status_changed_at=None,
            )
            .returning(remediation_executions_table.c.started_at)
        )

        try:
            async with self._engine.begin() as connection:
                claim_result = await connection.execute(lock_claim)
                if claim_result.scalar_one_or_none() is None:
                    raise RemediationExecutionClaimNotFoundError("Execution claim does not exist.")

                existing_result = await connection.execute(find_existing)
                if existing_result.scalar_one_or_none() is not None:
                    raise RemediationExecutionAlreadyStartedError(
                        "Remediation execution has already started for this claim."
                    )

                started_at = (await connection.execute(insert_execution)).scalar_one()
        except IntegrityError as exc:
            # Never disguise FK, CHECK or unexpected PK failures as a retry.
            original = exc.orig
            diagnostic = getattr(original, "diag", None)
            constraint_name = (
                getattr(diagnostic, "constraint_name", None)
                or getattr(original, "constraint_name", None)
                or getattr(getattr(original, "__cause__", None), "constraint_name", None)
            )
            if (
                getattr(original, "sqlstate", None) == "23505"
                and constraint_name == "uq_remediation_executions_claim_id"
            ):
                raise RemediationExecutionAlreadyStartedError(
                    "Remediation execution has already started for this claim."
                ) from exc
            raise

        # The context manager committed successfully before returning.
        return RemediationExecution(
            execution_id=execution_id,
            claim_id=claim_id,
            status=RemediationExecutionStatus.EXECUTING,
            started_at=started_at.astimezone(UTC),
        )

    async def record_outcome_once(
        self, *, execution_id: UUID, outcome: RemediationExecutionStatus
    ) -> RemediationExecution:
        """Commit one terminal outcome using PostgreSQL's clock, or refuse.

        A conditional UPDATE is the concurrency boundary: racing workers cannot
        both change EXECUTING to a terminal state. No existing outcome is
        returned as a fresh successful transition, including identical retries.
        """
        if not isinstance(outcome, RemediationExecutionStatus) or outcome not in {
            RemediationExecutionStatus.SUCCEEDED,
            RemediationExecutionStatus.FAILED,
            RemediationExecutionStatus.UNKNOWN,
        }:
            raise RemediationExecutionOutcomeNotAllowedError(
                "Only terminal remediation execution outcomes can be recorded."
            )

        update_execution = (
            sa.update(remediation_executions_table)
            .where(
                remediation_executions_table.c.execution_id == execution_id,
                remediation_executions_table.c.status == RemediationExecutionStatus.EXECUTING.value,
            )
            .values(
                status=outcome.value,
                status_changed_at=sa.func.clock_timestamp(),
            )
            .returning(*remediation_executions_table.c)
        )
        find_execution = sa.select(remediation_executions_table.c.execution_id).where(
            remediation_executions_table.c.execution_id == execution_id
        )

        async with self._engine.begin() as connection:
            updated = (await connection.execute(update_execution)).mappings().one_or_none()
            if updated is None:
                # Distinguish an unknown ID from a previously finalized attempt.
                # Under PostgreSQL READ COMMITTED this SELECT observes a winner
                # after the competing conditional UPDATE releases its row lock.
                exists = (await connection.execute(find_execution)).scalar_one_or_none()
                if exists is None:
                    raise RemediationExecutionNotFoundError("Remediation execution does not exist.")
                raise RemediationExecutionOutcomeNotAllowedError(
                    "Remediation execution outcome has already been recorded."
                )

        # No successful snapshot escapes before the transaction is committed.
        return RemediationExecution(
            execution_id=updated["execution_id"],
            claim_id=updated["claim_id"],
            status=RemediationExecutionStatus(updated["status"]),
            started_at=updated["started_at"].astimezone(UTC),
            status_changed_at=updated["status_changed_at"].astimezone(UTC),
        )

    async def get_by_claim_id(self, *, claim_id: UUID) -> RemediationExecution | None:
        """Read one committed execution attempt without claiming or restarting it.

        A missing claim and an existing claim without an attempt both return None.
        Reading UNKNOWN or EXECUTING never authorizes an MCP retry.
        """
        find_execution = sa.select(remediation_executions_table).where(
            remediation_executions_table.c.claim_id == claim_id
        )
        async with self._engine.connect() as connection:
            row = (await connection.execute(find_execution)).mappings().one_or_none()

        if row is None:
            return None

        changed_at = row["status_changed_at"]
        return RemediationExecution(
            execution_id=row["execution_id"],
            claim_id=row["claim_id"],
            status=RemediationExecutionStatus(row["status"]),
            started_at=row["started_at"].astimezone(UTC),
            status_changed_at=changed_at.astimezone(UTC) if changed_at is not None else None,
        )
