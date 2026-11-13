"""PostgreSQL adapter for approval-bound, at-most-once execution claims.

This grants a durable claim, not permission to call MCP without a trusted guard.
"""

from datetime import UTC
from uuid import UUID, uuid4

import sqlalchemy as sa
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncEngine

from ai_incident_commander.application.execution_claim_repository import (
    ExecutionClaimAlreadyExistsError,
    ExecutionClaimApprovalDeniedError,
    ExecutionClaimScopeMismatchError,
)
from ai_incident_commander.domain.execution_claim import ExecutionClaim
from ai_incident_commander.domain.remediation_approval import RemediationApprovalOutcome
from ai_incident_commander.infrastructure.approval_tables import (
    approval_decisions_table,
    approval_requests_table,
)
from ai_incident_commander.infrastructure.execution_claim_tables import (
    execution_claims_table,
)


class PostgresExecutionClaimRepository:
    """Atomically reserve one approved remediation step across all workers."""

    def __init__(self, *, engine: AsyncEngine) -> None:
        self._engine = engine

    async def get_by_request_id(self, *, request_id: UUID) -> ExecutionClaim | None:
        """Read a committed claim without creating or reauthorizing an attempt."""
        statement = sa.select(execution_claims_table).where(
            execution_claims_table.c.request_id == request_id
        )

        async with self._engine.connect() as connection:
            row = (await connection.execute(statement)).mappings().one_or_none()

        if row is None:
            return None

        return ExecutionClaim(
            claim_id=row["claim_id"],
            plan_id=row["plan_id"],
            step_id=row["step_id"],
            request_id=row["request_id"],
            action_fingerprint=row["action_fingerprint"],
            policy_version=row["policy_version"],
            claimed_at=row["claimed_at"].astimezone(UTC),
        )

    async def claim_once(
        self,
        *,
        request_id: UUID,
        plan_id: UUID,
        step_id: UUID,
        action_fingerprint: str,
        policy_version: str,
    ) -> ExecutionClaim:
        """Verify persisted approval and commit exactly one reservation.

        An earlier claim always causes refusal, including on an identical retry.
        The unique indexes arbitrate races between separate transactions.
        """
        existing_claim = sa.select(execution_claims_table.c.claim_id).where(
            sa.or_(
                sa.and_(
                    execution_claims_table.c.plan_id == plan_id,
                    execution_claims_table.c.step_id == step_id,
                ),
                execution_claims_table.c.request_id == request_id,
            )
        )
        lock_request = (
            sa.select(approval_requests_table)
            .where(approval_requests_table.c.request_id == request_id)
            .with_for_update()
        )
        lock_decision = (
            sa.select(approval_decisions_table)
            .where(approval_decisions_table.c.request_id == request_id)
            .with_for_update(read=True)
        )
        claim_id = uuid4()
        insert_claim = (
            sa.insert(execution_claims_table)
            .values(
                claim_id=claim_id,
                plan_id=plan_id,
                step_id=step_id,
                request_id=request_id,
                action_fingerprint=action_fingerprint,
                policy_version=policy_version,
                claimed_at=sa.func.clock_timestamp(),
            )
            .returning(execution_claims_table.c.claimed_at)
        )

        try:
            async with self._engine.begin() as connection:
                # This check gives clear retry semantics for already committed claims.
                # The unique constraints still protect against concurrent races.
                existing_result = await connection.execute(existing_claim)
                if existing_result.scalar_one_or_none() is not None:
                    raise ExecutionClaimAlreadyExistsError("Remediation step is already claimed.")

                request_result = await connection.execute(lock_request)
                request = request_result.mappings().one_or_none()
                if request is None:
                    raise ExecutionClaimApprovalDeniedError("Approval request does not exist.")

                # FOR SHARE protects the persisted decision against concurrent
                # deletion or mutation until the claim transaction commits.
                decision_result = await connection.execute(lock_decision)
                decision = decision_result.mappings().one_or_none()
                if (
                    decision is None
                    or decision["outcome"] != RemediationApprovalOutcome.APPROVED.value
                ):
                    raise ExecutionClaimApprovalDeniedError("No approved decision exists.")

                # Both audit timestamps must refer to the approval window; the
                # expiry does NOT serve as a separate execution deadline.
                if not (
                    request["requested_at"] <= decision["decided_at"] < request["expires_at"]
                    and request["requested_at"] <= decision["recorded_at"] < request["expires_at"]
                ):
                    raise ExecutionClaimApprovalDeniedError("Persisted approval timing is invalid.")

                if (
                    request["plan_id"] != plan_id
                    or request["step_id"] != step_id
                    or request["action_fingerprint"] != action_fingerprint
                    or request["policy_version"] != policy_version
                ):
                    raise ExecutionClaimScopeMismatchError("Execution scope differs from approval.")

                claimed_at = (await connection.execute(insert_claim)).scalar_one()
        except IntegrityError as exc:
            # Translate ONLY the expected uniqueness conflicts. Unexpected DB
            # integrity failures must remain visible to callers/observability.
            original = exc.orig
            diagnostic = getattr(original, "diag", None)
            constraint_name = (
                getattr(diagnostic, "constraint_name", None)
                or getattr(original, "constraint_name", None)
                or getattr(getattr(original, "__cause__", None), "constraint_name", None)
            )
            if getattr(original, "sqlstate", None) == "23505" and constraint_name in {
                "uq_execution_claims_plan_step",
                "uq_execution_claims_request_id",
            }:
                raise ExecutionClaimAlreadyExistsError(
                    "Remediation step is already claimed."
                ) from exc
            raise

        # We reach this point only after the context manager committed the TX.
        return ExecutionClaim(
            claim_id=claim_id,
            plan_id=plan_id,
            step_id=step_id,
            request_id=request_id,
            action_fingerprint=action_fingerprint,
            policy_version=policy_version,
            claimed_at=claimed_at.astimezone(UTC),
        )
