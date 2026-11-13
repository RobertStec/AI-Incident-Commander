"""PostgreSQL persistence for the remediation execution lifecycle.

This adapter durably starts execution, records terminal outcomes at most once,
and reads committed attempts. It does not invoke MCP or authorize retries.
"""

from datetime import UTC
from uuid import UUID, uuid4

import sqlalchemy as sa
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncEngine

from ai_incident_commander.application.approval_execution_guard import VerifiedExecutionScope
from ai_incident_commander.application.remediation_execution_repository import (
    RemediationExecutionAlreadyStartedError,
    RemediationExecutionClaimNotFoundError,
    RemediationExecutionNotFoundError,
    RemediationExecutionOutcomeNotAllowedError,
    RemediationExecutionRecoveryApprovalDeniedError,
    RemediationExecutionRecoveryScopeMismatchError,
    RemediationExecutionRecoveryWindowNotSatisfiedError,
)
from ai_incident_commander.domain.execution_claim_recovery_policy import (
    ExecutionClaimRecoveryWindowPolicy,
)
from ai_incident_commander.domain.remediation_approval import RemediationApprovalOutcome
from ai_incident_commander.domain.remediation_execution import (
    RemediationExecution,
    RemediationExecutionStatus,
)
from ai_incident_commander.infrastructure.approval_tables import (
    approval_decisions_table,
    approval_requests_table,
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

    async def start_recovered_once(
        self,
        *,
        claim_id: UUID,
        verified_scope: VerifiedExecutionScope,
        recovery_policy: ExecutionClaimRecoveryWindowPolicy,
    ) -> RemediationExecution:
        """Atomically recover one previously committed claim, or fail closed.

        A trusted service must obtain verified_scope from a fresh Guard call.
        This method rechecks the durable approval, scope, and claim age under
        PostgreSQL locks; it cannot verify the current external resource.
        """
        if not isinstance(verified_scope, VerifiedExecutionScope):
            raise RemediationExecutionRecoveryScopeMismatchError(
                "Recovery requires a verified execution scope."
            )
        if not isinstance(recovery_policy, ExecutionClaimRecoveryWindowPolicy):
            raise ValueError("Recovery requires a configured claim recovery policy.")

        lock_claim = (
            sa.select(execution_claims_table)
            .where(execution_claims_table.c.claim_id == claim_id)
            .with_for_update()
        )
        lock_request = sa.select(approval_requests_table).with_for_update()
        lock_decision = sa.select(approval_decisions_table).with_for_update(read=True)
        existing_attempt = sa.select(remediation_executions_table.c.execution_id).where(
            remediation_executions_table.c.claim_id == claim_id
        )

        execution_id = uuid4()
        try:
            async with self._engine.begin() as connection:
                claim = (await connection.execute(lock_claim)).mappings().one_or_none()
                if claim is None:
                    raise RemediationExecutionClaimNotFoundError("Execution claim does not exist.")

                # Lock the request identified by the durable claim, not by an
                # untrusted argument. This preserves the FK and lock ordering.
                request = (
                    (
                        await connection.execute(
                            lock_request.where(
                                approval_requests_table.c.request_id == claim["request_id"]
                            )
                        )
                    )
                    .mappings()
                    .one_or_none()
                )
                if request is None:
                    raise RemediationExecutionRecoveryApprovalDeniedError(
                        "Persisted approval request is unavailable."
                    )
                decision = (
                    (
                        await connection.execute(
                            lock_decision.where(
                                approval_decisions_table.c.request_id == claim["request_id"]
                            )
                        )
                    )
                    .mappings()
                    .one_or_none()
                )
                if (
                    decision is None
                    or decision["outcome"] != RemediationApprovalOutcome.APPROVED.value
                    or not (
                        request["requested_at"] <= decision["decided_at"] < request["expires_at"]
                    )
                    or not (
                        request["requested_at"] <= decision["recorded_at"] < request["expires_at"]
                    )
                ):
                    raise RemediationExecutionRecoveryApprovalDeniedError(
                        "Persisted approval is missing, rejected or outside its decision window."
                    )

                durable_fields = (
                    "request_id",
                    "plan_id",
                    "step_id",
                    "action_fingerprint",
                    "policy_version",
                )
                if any(claim[name] != request[name] for name in durable_fields):
                    raise RemediationExecutionRecoveryApprovalDeniedError(
                        "Persisted claim does not match the approval request."
                    )
                if any(claim[name] != getattr(verified_scope, name) for name in durable_fields):
                    raise RemediationExecutionRecoveryScopeMismatchError(
                        "Freshly verified scope differs from the persisted claim."
                    )

                existing = (await connection.execute(existing_attempt)).scalar_one_or_none()
                if existing is not None:
                    raise RemediationExecutionAlreadyStartedError(
                        "Remediation execution has already started for this claim."
                    )

                # The same PostgreSQL clock sample drives BOTH the expiry
                # predicate and started_at. It is evaluated by the INSERT,
                # not by a preceding application-level time check.
                recovery_clock = (
                    sa.select(sa.func.clock_timestamp().label("observed_at"))
                    .cte("recovery_clock")
                    .prefix_with("MATERIALIZED", dialect="postgresql")
                )
                insert_execution = (
                    sa.insert(remediation_executions_table)
                    .from_select(
                        [
                            "execution_id",
                            "claim_id",
                            "status",
                            "started_at",
                            "status_changed_at",
                        ],
                        sa.select(
                            sa.literal(execution_id),
                            sa.literal(claim_id),
                            sa.literal(RemediationExecutionStatus.EXECUTING.value),
                            recovery_clock.c.observed_at,
                            sa.null(),
                        ).where(
                            recovery_clock.c.observed_at >= claim["claimed_at"],
                            recovery_clock.c.observed_at
                            < claim["claimed_at"]
                            + sa.literal(recovery_policy.max_claim_age, type_=sa.Interval()),
                        ),
                    )
                    .returning(remediation_executions_table.c.started_at)
                )
                started_at = (await connection.execute(insert_execution)).scalar_one_or_none()
                if started_at is None:
                    raise RemediationExecutionRecoveryWindowNotSatisfiedError(
                        "Execution claim is outside the configured recovery window."
                    )
        except IntegrityError as exc:
            # Only a recognized claim uniqueness violation maps to AlreadyStarted.
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

        return RemediationExecution(
            execution_id=execution_id,
            claim_id=claim_id,
            status=RemediationExecutionStatus.EXECUTING,
            started_at=started_at.astimezone(UTC),
        )
