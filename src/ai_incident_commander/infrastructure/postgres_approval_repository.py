"""PostgreSQL implementation of the approval repository."""

from datetime import UTC
from uuid import UUID

import sqlalchemy as sa
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncEngine

from ai_incident_commander.application.approval_repository import (
    ApprovalAlreadyDecidedError,
    ApprovalRequestAlreadyExistsError,
    ApprovalRequestNotActiveError,
    ApprovalRequestNotFoundError,
)
from ai_incident_commander.domain.remediation_approval import (
    RemediationApprovalDecision,
    RemediationApprovalOutcome,
    RemediationApprovalRequest,
)
from ai_incident_commander.infrastructure.approval_tables import (
    approval_decisions_table,
    approval_requests_table,
)


class PostgresApprovalRepository:
    """Persist remediation approval records in PostgreSQL."""

    def __init__(self, *, engine: AsyncEngine) -> None:
        self._engine = engine

    async def create_request(
        self,
        request: RemediationApprovalRequest,
    ) -> None:
        """Insert a request atomically, rejecting duplicate identifiers."""
        statement = sa.insert(approval_requests_table).values(
            request_id=request.request_id,
            plan_id=request.plan_id,
            step_id=request.step_id,
            action_fingerprint=request.action_fingerprint,
            policy_version=request.policy_version,
            requested_at=request.requested_at,
            expires_at=request.expires_at,
        )

        try:
            async with self._engine.begin() as connection:
                await connection.execute(statement)
        except IntegrityError as exc:
            original_error = exc.orig
            diagnostic = getattr(original_error, "diag", None)

            if (
                getattr(original_error, "sqlstate", None) == "23505"
                and getattr(diagnostic, "constraint_name", None) == "pk_approval_requests"
            ):
                raise ApprovalRequestAlreadyExistsError("Approval request already exists.") from exc

            raise

    async def get_request(
        self,
        request_id: UUID,
    ) -> RemediationApprovalRequest | None:
        """Retrieve an approval request and reconstruct its domain model."""
        statement = sa.select(approval_requests_table).where(
            approval_requests_table.c.request_id == request_id
        )

        async with self._engine.connect() as connection:
            result = await connection.execute(statement)
            row = result.mappings().one_or_none()

        if row is None:
            return None

        return RemediationApprovalRequest(
            request_id=row["request_id"],
            plan_id=row["plan_id"],
            step_id=row["step_id"],
            action_fingerprint=row["action_fingerprint"],
            policy_version=row["policy_version"],
            requested_at=row["requested_at"].astimezone(UTC),
            expires_at=row["expires_at"].astimezone(UTC),
        )

    async def get_decision(
        self,
        request_id: UUID,
    ) -> RemediationApprovalDecision | None:
        """Read a persisted decision without modifying approval records."""
        statement = sa.select(approval_decisions_table).where(
            approval_decisions_table.c.request_id == request_id
        )

        async with self._engine.connect() as connection:
            result = await connection.execute(statement)
            row = result.mappings().one_or_none()

        if row is None:
            return None

        return RemediationApprovalDecision(
            decision_id=row["decision_id"],
            request_id=row["request_id"],
            operator_id=row["operator_id"],
            outcome=RemediationApprovalOutcome(row["outcome"]),
            decided_at=row["decided_at"].astimezone(UTC),
            reason=row["reason"],
        )

    async def record_decision_once(
        self,
        decision: RemediationApprovalDecision,
    ) -> None:
        """Record one decision only while its request is active in PostgreSQL."""
        lock_request = (
            sa.select(approval_requests_table.c.request_id)
            .where(approval_requests_table.c.request_id == decision.request_id)
            .with_for_update()
        )
        find_decision = sa.select(approval_decisions_table.c.decision_id).where(
            approval_decisions_table.c.request_id == decision.request_id
        )

        # Evaluate the database clock once inside the INSERT statement,
        # after locking the request, and reuse it for both validation and audit.
        recording_clock = sa.select(sa.func.clock_timestamp().label("recorded_at")).cte(
            "recording_clock"
        )

        insert_source = (
            sa.select(
                sa.literal(decision.decision_id),
                sa.literal(decision.request_id),
                sa.literal(decision.operator_id),
                sa.literal(decision.outcome.value),
                sa.literal(decision.decided_at, type_=sa.DateTime(timezone=True)),
                recording_clock.c.recorded_at,
                sa.literal(decision.reason),
            )
            .select_from(approval_requests_table.join(recording_clock, sa.true()))
            .where(approval_requests_table.c.request_id == decision.request_id)
            .where(approval_requests_table.c.requested_at <= recording_clock.c.recorded_at)
            .where(recording_clock.c.recorded_at < approval_requests_table.c.expires_at)
        )
        insert_decision = (
            sa.insert(approval_decisions_table)
            .from_select(
                [
                    "decision_id",
                    "request_id",
                    "operator_id",
                    "outcome",
                    "decided_at",
                    "recorded_at",
                    "reason",
                ],
                insert_source,
            )
            .returning(approval_decisions_table.c.decision_id)
        )

        try:
            async with self._engine.begin() as connection:
                request_result = await connection.execute(lock_request)
                if request_result.scalar_one_or_none() is None:
                    raise ApprovalRequestNotFoundError("Approval request does not exist.")

                decision_result = await connection.execute(find_decision)
                if decision_result.scalar_one_or_none() is not None:
                    raise ApprovalAlreadyDecidedError("Approval request already has a decision.")

                insert_result = await connection.execute(insert_decision)
                if insert_result.scalar_one_or_none() is None:
                    raise ApprovalRequestNotActiveError("Approval request is not active.")

        except IntegrityError as exc:
            original_error = exc.orig
            diagnostic = getattr(original_error, "diag", None)
            constraint_name = (
                getattr(diagnostic, "constraint_name", None)
                or getattr(original_error, "constraint_name", None)
                or getattr(getattr(original_error, "__cause__", None), "constraint_name", None)
            )

            if (
                getattr(original_error, "sqlstate", None) == "23505"
                and constraint_name == "uq_approval_decisions_request_id"
            ):
                raise ApprovalAlreadyDecidedError(
                    "Approval request already has a decision."
                ) from exc

            raise
