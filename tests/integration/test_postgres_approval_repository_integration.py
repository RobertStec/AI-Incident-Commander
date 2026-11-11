"""Opt-in integration tests for the PostgreSQL approval repository."""

import asyncio
import os
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

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
from ai_incident_commander.infrastructure.database_config import DatabaseConfig
from ai_incident_commander.infrastructure.database_engine import create_database_engine
from ai_incident_commander.infrastructure.postgres_approval_repository import (
    PostgresApprovalRepository,
)


def _require_database_tests() -> None:
    if os.environ.get("RUN_DB_APPROVAL_TESTS") != "1":
        pytest.skip("Set RUN_DB_APPROVAL_TESTS=1 to enable approval database tests")


def _make_request() -> RemediationApprovalRequest:
    requested_at = datetime(2030, 1, 1, tzinfo=UTC)
    return RemediationApprovalRequest(
        request_id=uuid4(),
        plan_id=uuid4(),
        step_id=uuid4(),
        action_fingerprint="afp:v2:" + "a" * 64,
        policy_version="apv:v1:" + "b" * 64,
        requested_at=requested_at,
        expires_at=requested_at + timedelta(minutes=30),
    )


async def _delete_test_request(engine: AsyncEngine, request_id: UUID) -> None:
    """Remove test-owned decisions before their parent request (FK RESTRICT)."""
    async with engine.begin() as connection:
        await connection.execute(
            sa.delete(approval_decisions_table).where(
                approval_decisions_table.c.request_id == request_id
            )
        )
        await connection.execute(
            sa.delete(approval_requests_table).where(
                approval_requests_table.c.request_id == request_id
            )
        )


def test_create_request_persists_all_fields() -> None:
    """Read committed data through a separate database connection."""
    _require_database_tests()

    async def run_scenario() -> None:
        request = _make_request()
        engine = create_database_engine(DatabaseConfig.from_environment())
        try:
            repository = PostgresApprovalRepository(engine=engine)
            await repository.create_request(request)

            async with engine.connect() as connection:
                result = await connection.execute(
                    sa.select(approval_requests_table).where(
                        approval_requests_table.c.request_id == request.request_id
                    )
                )
                row = result.mappings().one()

            assert row["request_id"] == request.request_id
            assert row["plan_id"] == request.plan_id
            assert row["step_id"] == request.step_id
            assert row["action_fingerprint"] == request.action_fingerprint
            assert row["policy_version"] == request.policy_version
            assert row["requested_at"] == request.requested_at
            assert row["expires_at"] == request.expires_at
        finally:
            try:
                await _delete_test_request(engine, request.request_id)
            finally:
                await engine.dispose()

    asyncio.run(run_scenario())


def test_create_request_rejects_duplicate_request_id() -> None:
    """Translate the database primary-key violation into a domain-port error."""
    _require_database_tests()

    async def run_scenario() -> None:
        request = _make_request()
        engine = create_database_engine(DatabaseConfig.from_environment())
        try:
            repository = PostgresApprovalRepository(engine=engine)
            await repository.create_request(request)

            with pytest.raises(ApprovalRequestAlreadyExistsError):
                await repository.create_request(request)

            async with engine.connect() as connection:
                count = await connection.scalar(
                    sa.select(sa.func.count())
                    .select_from(approval_requests_table)
                    .where(approval_requests_table.c.request_id == request.request_id)
                )
            assert count == 1
        finally:
            try:
                await _delete_test_request(engine, request.request_id)
            finally:
                await engine.dispose()

    asyncio.run(run_scenario())


def test_get_request_returns_complete_domain_model() -> None:
    """Reconstruct all fields from a committed request as a domain object."""
    _require_database_tests()

    async def run_scenario() -> None:
        request = _make_request()
        engine = create_database_engine(DatabaseConfig.from_environment())
        try:
            repository = PostgresApprovalRepository(engine=engine)
            await repository.create_request(request)

            restored = await repository.get_request(request.request_id)

            assert isinstance(restored, RemediationApprovalRequest)
            assert restored is not request
            assert restored == request
            assert restored.requested_at.tzinfo is UTC
            assert restored.expires_at.tzinfo is UTC
        finally:
            try:
                await _delete_test_request(engine, request.request_id)
            finally:
                await engine.dispose()

    asyncio.run(run_scenario())


def test_get_request_returns_none_for_missing_id() -> None:
    """A missing request is not confused with a database failure."""
    _require_database_tests()

    async def run_scenario() -> None:
        engine = create_database_engine(DatabaseConfig.from_environment())
        try:
            repository = PostgresApprovalRepository(engine=engine)
            assert await repository.get_request(uuid4()) is None
        finally:
            await engine.dispose()

    asyncio.run(run_scenario())


def test_get_request_normalizes_non_utc_session_timestamps() -> None:
    """Always restore UTC timestamps even when the DB session uses another zone."""
    _require_database_tests()

    async def run_scenario() -> None:
        request = _make_request()
        config = DatabaseConfig.from_environment()
        engine = create_async_engine(
            config.url,
            connect_args={"options": "-c TimeZone=Asia/Tokyo"},
            hide_parameters=True,
        )
        try:
            repository = PostgresApprovalRepository(engine=engine)
            await repository.create_request(request)

            async with engine.connect() as connection:
                raw_timestamp = await connection.scalar(
                    sa.select(approval_requests_table.c.requested_at).where(
                        approval_requests_table.c.request_id == request.request_id
                    )
                )

            assert raw_timestamp is not None
            assert raw_timestamp.utcoffset() == timedelta(hours=9)

            restored = await repository.get_request(request.request_id)
            assert restored is not None
            assert restored.requested_at == request.requested_at
            assert restored.expires_at == request.expires_at
            assert restored.requested_at.tzinfo is UTC
            assert restored.expires_at.tzinfo is UTC
        finally:
            try:
                await _delete_test_request(engine, request.request_id)
            finally:
                await engine.dispose()

    asyncio.run(run_scenario())


def test_get_request_does_not_modify_persisted_record() -> None:
    """A read leaves the stored request unchanged."""
    _require_database_tests()

    async def run_scenario() -> None:
        request = _make_request()
        engine = create_database_engine(DatabaseConfig.from_environment())
        statement = sa.select(approval_requests_table).where(
            approval_requests_table.c.request_id == request.request_id
        )
        try:
            repository = PostgresApprovalRepository(engine=engine)
            await repository.create_request(request)

            async with engine.connect() as connection:
                before = dict((await connection.execute(statement)).mappings().one())

            restored = await repository.get_request(request.request_id)
            assert restored is not None

            async with engine.connect() as connection:
                after = dict((await connection.execute(statement)).mappings().one())

            assert after == before
        finally:
            try:
                await _delete_test_request(engine, request.request_id)
            finally:
                await engine.dispose()

    asyncio.run(run_scenario())


def test_record_decision_once_persists_first_decision_for_active_request() -> None:
    """Commit the first decision and verify it via a separate DB connection."""
    _require_database_tests()

    async def run_scenario() -> None:
        engine = create_database_engine(DatabaseConfig.from_environment())
        request = _make_request()
        try:
            # Use PostgreSQL time to avoid application/database clock skew.
            async with engine.connect() as connection:
                database_now = await connection.scalar(sa.select(sa.func.clock_timestamp()))
            assert isinstance(database_now, datetime)
            database_now = database_now.astimezone(UTC)

            request = replace(
                request,
                requested_at=database_now - timedelta(minutes=5),
                expires_at=database_now + timedelta(minutes=25),
            )
            decision = RemediationApprovalDecision(
                request_id=request.request_id,
                operator_id="operator-integration-test",
                outcome=RemediationApprovalOutcome.APPROVED,
                decided_at=database_now,
                reason="Approved for the integration test.",
            )

            repository = PostgresApprovalRepository(engine=engine)
            await repository.create_request(request)
            await repository.record_decision_once(decision)

            async with engine.connect() as connection:
                result = await connection.execute(
                    sa.select(approval_decisions_table).where(
                        approval_decisions_table.c.request_id == request.request_id
                    )
                )
                row = result.mappings().one()

            assert row["decision_id"] == decision.decision_id
            assert row["request_id"] == decision.request_id
            assert row["operator_id"] == decision.operator_id
            assert row["outcome"] == decision.outcome.value
            assert row["decided_at"] == decision.decided_at
            assert row["reason"] == decision.reason
            assert row["recorded_at"] is not None
            assert request.requested_at <= row["recorded_at"] < request.expires_at
        finally:
            try:
                await _delete_test_request(engine, request.request_id)
            finally:
                await engine.dispose()

    asyncio.run(run_scenario())


def test_record_decision_once_rejects_missing_request_without_persisting() -> None:
    """Reject a decision for a missing request and leave no decision behind."""
    _require_database_tests()

    async def run_scenario() -> None:
        missing_request_id = uuid4()
        decision = RemediationApprovalDecision(
            request_id=missing_request_id,
            operator_id="operator-integration-test",
            outcome=RemediationApprovalOutcome.REJECTED,
            decided_at=datetime.now(UTC),
            reason="Reject an unknown approval request.",
        )
        engine = create_database_engine(DatabaseConfig.from_environment())
        try:
            repository = PostgresApprovalRepository(engine=engine)

            with pytest.raises(ApprovalRequestNotFoundError):
                await repository.record_decision_once(decision)

            async with engine.connect() as connection:
                count = await connection.scalar(
                    sa.select(sa.func.count())
                    .select_from(approval_decisions_table)
                    .where(approval_decisions_table.c.request_id == missing_request_id)
                )
            assert count == 0
        finally:
            try:
                await _delete_test_request(engine, missing_request_id)
            finally:
                await engine.dispose()

    asyncio.run(run_scenario())


def test_record_decision_once_rejects_expired_request_even_with_backdated_decision() -> None:
    """Enforce database-time expiration rather than trusting decision.decided_at."""
    _require_database_tests()

    async def run_scenario() -> None:
        engine = create_database_engine(DatabaseConfig.from_environment())
        request = _make_request()
        try:
            # Anchor the test to the PostgreSQL clock, not the machine clock.
            async with engine.connect() as connection:
                database_now = await connection.scalar(sa.select(sa.func.clock_timestamp()))
            assert isinstance(database_now, datetime)
            database_now = database_now.astimezone(UTC)

            request = replace(
                request,
                requested_at=database_now - timedelta(minutes=60),
                expires_at=database_now - timedelta(minutes=30),
            )
            decision = RemediationApprovalDecision(
                request_id=request.request_id,
                operator_id="operator-integration-test",
                outcome=RemediationApprovalOutcome.APPROVED,
                decided_at=request.requested_at + timedelta(minutes=5),
                reason="Backdated decision must not bypass request expiration.",
            )
            assert request.requested_at <= decision.decided_at < request.expires_at

            repository = PostgresApprovalRepository(engine=engine)
            await repository.create_request(request)

            with pytest.raises(ApprovalRequestNotActiveError):
                await repository.record_decision_once(decision)

            # The rejected write must leave no persisted decision.
            async with engine.connect() as connection:
                decision_count = await connection.scalar(
                    sa.select(sa.func.count())
                    .select_from(approval_decisions_table)
                    .where(approval_decisions_table.c.request_id == request.request_id)
                )
                request_count = await connection.scalar(
                    sa.select(sa.func.count())
                    .select_from(approval_requests_table)
                    .where(approval_requests_table.c.request_id == request.request_id)
                )
            assert decision_count == 0
            assert request_count == 1
        finally:
            try:
                await _delete_test_request(engine, request.request_id)
            finally:
                await engine.dispose()

    asyncio.run(run_scenario())


def test_record_decision_once_rejects_not_yet_active_request() -> None:
    """Reject future-window requests based on PostgreSQL time, not decided_at."""
    _require_database_tests()

    async def run_scenario() -> None:
        engine = create_database_engine(DatabaseConfig.from_environment())
        request = _make_request()
        try:
            async with engine.connect() as connection:
                database_now = await connection.scalar(sa.select(sa.func.clock_timestamp()))
            assert isinstance(database_now, datetime)
            database_now = database_now.astimezone(UTC)

            request = replace(
                request,
                requested_at=database_now + timedelta(minutes=30),
                expires_at=database_now + timedelta(minutes=60),
            )
            decision = RemediationApprovalDecision(
                request_id=request.request_id,
                operator_id="operator-integration-test",
                outcome=RemediationApprovalOutcome.REJECTED,
                decided_at=database_now + timedelta(minutes=35),
                reason="A future-dated decision cannot activate the request early.",
            )
            assert request.requested_at <= decision.decided_at < request.expires_at

            repository = PostgresApprovalRepository(engine=engine)
            await repository.create_request(request)

            with pytest.raises(ApprovalRequestNotActiveError):
                await repository.record_decision_once(decision)

            async with engine.connect() as connection:
                decision_count = await connection.scalar(
                    sa.select(sa.func.count())
                    .select_from(approval_decisions_table)
                    .where(approval_decisions_table.c.request_id == request.request_id)
                )
                request_count = await connection.scalar(
                    sa.select(sa.func.count())
                    .select_from(approval_requests_table)
                    .where(approval_requests_table.c.request_id == request.request_id)
                )
            assert decision_count == 0
            assert request_count == 1
        finally:
            try:
                await _delete_test_request(engine, request.request_id)
            finally:
                await engine.dispose()

    asyncio.run(run_scenario())


def test_record_decision_once_rejects_second_decision_without_overwriting_first() -> None:
    """A second operator cannot overwrite an already committed decision."""
    _require_database_tests()

    async def run_scenario() -> None:
        engine = create_database_engine(DatabaseConfig.from_environment())
        request = _make_request()
        try:
            async with engine.connect() as connection:
                database_now = await connection.scalar(sa.select(sa.func.clock_timestamp()))
            assert isinstance(database_now, datetime)
            database_now = database_now.astimezone(UTC)

            request = replace(
                request,
                requested_at=database_now - timedelta(minutes=5),
                expires_at=database_now + timedelta(minutes=25),
            )
            first = RemediationApprovalDecision(
                request_id=request.request_id,
                operator_id="first-operator",
                outcome=RemediationApprovalOutcome.APPROVED,
                decided_at=database_now,
                reason="First decision is authoritative.",
            )
            second = RemediationApprovalDecision(
                request_id=request.request_id,
                operator_id="second-operator",
                outcome=RemediationApprovalOutcome.REJECTED,
                decided_at=database_now,
                reason="Conflicting second decision must be rejected.",
            )
            repository = PostgresApprovalRepository(engine=engine)
            await repository.create_request(request)
            await repository.record_decision_once(first)

            statement = sa.select(approval_decisions_table).where(
                approval_decisions_table.c.request_id == request.request_id
            )
            async with engine.connect() as connection:
                original_row = dict((await connection.execute(statement)).mappings().one())

            with pytest.raises(ApprovalAlreadyDecidedError):
                await repository.record_decision_once(second)

            async with engine.connect() as connection:
                persisted_rows = (await connection.execute(statement)).mappings().all()

            assert len(persisted_rows) == 1
            assert dict(persisted_rows[0]) == original_row
            assert original_row["decision_id"] == first.decision_id
            assert original_row["operator_id"] == first.operator_id
            assert original_row["outcome"] == first.outcome.value
            assert original_row["reason"] == first.reason
            assert original_row["decision_id"] != second.decision_id
        finally:
            try:
                await _delete_test_request(engine, request.request_id)
            finally:
                await engine.dispose()

    asyncio.run(run_scenario())


def test_record_decision_once_prioritizes_existing_decision_over_expiration() -> None:
    """Return AlreadyDecided for an expired request with a historical decision."""
    _require_database_tests()

    async def run_scenario() -> None:
        engine = create_database_engine(DatabaseConfig.from_environment())
        request = _make_request()
        try:
            async with engine.connect() as connection:
                database_now = await connection.scalar(sa.select(sa.func.clock_timestamp()))
            assert isinstance(database_now, datetime)
            database_now = database_now.astimezone(UTC)

            request = replace(
                request,
                requested_at=database_now - timedelta(minutes=60),
                expires_at=database_now - timedelta(minutes=30),
            )
            historical_time = request.requested_at + timedelta(minutes=5)
            original = RemediationApprovalDecision(
                request_id=request.request_id,
                operator_id="first-operator",
                outcome=RemediationApprovalOutcome.APPROVED,
                decided_at=historical_time,
                reason="Approved while the request was active.",
            )
            attempted = RemediationApprovalDecision(
                request_id=request.request_id,
                operator_id="second-operator",
                outcome=RemediationApprovalOutcome.REJECTED,
                decided_at=database_now,
                reason="Attempt to replace a historical decision after expiration.",
            )

            repository = PostgresApprovalRepository(engine=engine)
            await repository.create_request(request)

            # Seed a legitimate historical state: a decision recorded when the
            # request was active. The adapter must not backdate live writes.
            async with engine.begin() as connection:
                await connection.execute(
                    sa.insert(approval_decisions_table).values(
                        decision_id=original.decision_id,
                        request_id=original.request_id,
                        operator_id=original.operator_id,
                        outcome=original.outcome.value,
                        decided_at=original.decided_at,
                        recorded_at=historical_time,
                        reason=original.reason,
                    )
                )

            statement = sa.select(approval_decisions_table).where(
                approval_decisions_table.c.request_id == request.request_id
            )
            async with engine.connect() as connection:
                before = dict((await connection.execute(statement)).mappings().one())

            assert request.requested_at <= before["recorded_at"] < request.expires_at
            assert request.expires_at < database_now

            with pytest.raises(ApprovalAlreadyDecidedError):
                await repository.record_decision_once(attempted)

            async with engine.connect() as connection:
                after = (await connection.execute(statement)).mappings().all()

            assert len(after) == 1
            assert dict(after[0]) == before
            assert before["decision_id"] == original.decision_id
            assert before["operator_id"] == original.operator_id
            assert before["outcome"] == original.outcome.value
        finally:
            try:
                await _delete_test_request(engine, request.request_id)
            finally:
                await engine.dispose()

    asyncio.run(run_scenario())


def test_record_decision_once_allows_only_one_concurrent_operator() -> None:
    """Two transactions contending for the same row must yield exactly one winner."""
    _require_database_tests()

    async def run_scenario() -> None:
        engine = create_database_engine(DatabaseConfig.from_environment())
        request = _make_request()
        pending: list[asyncio.Task[None]] = []
        try:
            async with engine.connect() as connection:
                database_now = await connection.scalar(sa.select(sa.func.clock_timestamp()))
            assert isinstance(database_now, datetime)
            database_now = database_now.astimezone(UTC)

            request = replace(
                request,
                requested_at=database_now - timedelta(minutes=5),
                expires_at=database_now + timedelta(minutes=25),
            )
            approved = RemediationApprovalDecision(
                request_id=request.request_id,
                operator_id="concurrent-operator-A",
                outcome=RemediationApprovalOutcome.APPROVED,
                decided_at=database_now,
                reason="Operator A approves remediation.",
            )
            rejected = RemediationApprovalDecision(
                request_id=request.request_id,
                operator_id="concurrent-operator-B",
                outcome=RemediationApprovalOutcome.REJECTED,
                decided_at=database_now,
                reason="Operator B rejects remediation.",
            )
            decisions = (approved, rejected)

            repository = PostgresApprovalRepository(engine=engine)
            await repository.create_request(request)

            lock_attempt_count = 0
            both_attempts_started = asyncio.Event()

            def observe_lock_attempt(
                _connection: object,
                _cursor: object,
                statement: str,
                _parameters: object,
                _context: object,
                _executemany: bool,
            ) -> None:
                nonlocal lock_attempt_count
                sql = statement.upper()
                if "FOR UPDATE" not in sql or "REMEDIATION_APPROVAL_REQUESTS" not in sql:
                    return
                lock_attempt_count += 1
                if lock_attempt_count == 2:
                    both_attempts_started.set()

            # Hold the request row locked in a third transaction until both
            # operators have attempted their own SELECT ... FOR UPDATE.
            lock_request = (
                sa.select(approval_requests_table.c.request_id)
                .where(approval_requests_table.c.request_id == request.request_id)
                .with_for_update()
            )
            async with engine.begin() as blocker:
                locked_request_id = await blocker.scalar(lock_request)
                assert locked_request_id == request.request_id

                sa.event.listen(engine.sync_engine, "before_cursor_execute", observe_lock_attempt)
                try:
                    pending = [
                        asyncio.create_task(repository.record_decision_once(decision))
                        for decision in decisions
                    ]
                    # No timing-based sleeps: require both real adapter calls to
                    # reach their row-lock SQL before releasing the blocker.
                    await asyncio.wait_for(both_attempts_started.wait(), timeout=10)
                finally:
                    sa.event.remove(
                        engine.sync_engine, "before_cursor_execute", observe_lock_attempt
                    )
            # The blocker committed. Both operators now race for the same row.
            results = await asyncio.gather(*pending, return_exceptions=True)
            winner_indices = [index for index, result in enumerate(results) if result is None]
            assert len(winner_indices) == 1
            loser_index = 1 - winner_indices[0]
            assert isinstance(results[loser_index], ApprovalAlreadyDecidedError)
            winner = decisions[winner_indices[0]]

            # Observe committed state through an independent database connection.
            async with engine.connect() as connection:
                persisted = (
                    (
                        await connection.execute(
                            sa.select(approval_decisions_table).where(
                                approval_decisions_table.c.request_id == request.request_id
                            )
                        )
                    )
                    .mappings()
                    .all()
                )

            assert len(persisted) == 1
            row = persisted[0]
            assert row["decision_id"] == winner.decision_id
            assert row["operator_id"] == winner.operator_id
            assert row["outcome"] == winner.outcome.value
            assert row["decided_at"] == winner.decided_at
            assert row["reason"] == winner.reason
            assert request.requested_at <= row["recorded_at"] < request.expires_at
        finally:
            for task in pending:
                if not task.done():
                    task.cancel()
            if pending:
                await asyncio.gather(*pending, return_exceptions=True)
            try:
                await _delete_test_request(engine, request.request_id)
            finally:
                await engine.dispose()

    asyncio.run(run_scenario())


def test_record_decision_once_rejects_decisions_expired_while_waiting_for_lock() -> None:
    """Recheck DB time after row-lock contention; reject both expired attempts."""
    _require_database_tests()

    async def run_scenario() -> None:
        engine = create_database_engine(DatabaseConfig.from_environment())
        request = _make_request()
        pending: list[asyncio.Task[None]] = []
        try:
            async with engine.connect() as connection:
                database_now = await connection.scalar(sa.select(sa.func.clock_timestamp()))
            assert isinstance(database_now, datetime)
            database_now = database_now.astimezone(UTC)

            # The request starts active and expires shortly after both operators
            # have tried to acquire the row lock.
            request = replace(
                request,
                requested_at=database_now - timedelta(minutes=5),
                expires_at=database_now + timedelta(seconds=6),
            )
            approved = RemediationApprovalDecision(
                request_id=request.request_id,
                operator_id="waiting-operator-A",
                outcome=RemediationApprovalOutcome.APPROVED,
                decided_at=database_now,
                reason="Approval submitted before the request expired.",
            )
            rejected = RemediationApprovalDecision(
                request_id=request.request_id,
                operator_id="waiting-operator-B",
                outcome=RemediationApprovalOutcome.REJECTED,
                decided_at=database_now,
                reason="Rejection submitted before the request expired.",
            )
            repository = PostgresApprovalRepository(engine=engine)
            await repository.create_request(request)

            attempts = 0
            both_attempts_started = asyncio.Event()

            def observe_lock_attempt(
                _connection: object,
                _cursor: object,
                statement: str,
                _parameters: object,
                _context: object,
                _executemany: bool,
            ) -> None:
                nonlocal attempts
                sql = statement.upper()
                if "FOR UPDATE" not in sql or "REMEDIATION_APPROVAL_REQUESTS" not in sql:
                    return
                attempts += 1
                if attempts == 2:
                    both_attempts_started.set()

            lock_request = (
                sa.select(approval_requests_table.c.request_id)
                .where(approval_requests_table.c.request_id == request.request_id)
                .with_for_update()
            )
            async with engine.begin() as blocker:
                assert await blocker.scalar(lock_request) == request.request_id

                sa.event.listen(engine.sync_engine, "before_cursor_execute", observe_lock_attempt)
                try:
                    pending = [
                        asyncio.create_task(repository.record_decision_once(decision))
                        for decision in (approved, rejected)
                    ]
                    await asyncio.wait_for(both_attempts_started.wait(), timeout=10)
                finally:
                    sa.event.remove(
                        engine.sync_engine, "before_cursor_execute", observe_lock_attempt
                    )

                # Verify that the attempts reached the lock while the request
                # was still active. Then hold the lock across the actual
                # PostgreSQL expiration boundary (not a Python clock).
                before_expiration = await blocker.scalar(sa.select(sa.func.clock_timestamp()))
                assert isinstance(before_expiration, datetime)
                assert before_expiration < request.expires_at

                await blocker.execute(
                    sa.text(
                        "SELECT pg_sleep(CAST(GREATEST(0.0, "
                        "EXTRACT(EPOCH FROM (CAST(:deadline AS timestamptz) "
                        "- clock_timestamp())) + 0.1) AS double precision))"
                    ),
                    {"deadline": request.expires_at},
                )
                after_expiration = await blocker.scalar(sa.select(sa.func.clock_timestamp()))
                assert isinstance(after_expiration, datetime)
                assert after_expiration >= request.expires_at

            # Both operators are released only after PostgreSQL reports expiry.
            results = await asyncio.wait_for(
                asyncio.gather(*pending, return_exceptions=True), timeout=10
            )
            assert len(results) == 2
            assert all(isinstance(result, ApprovalRequestNotActiveError) for result in results)

            async with engine.connect() as connection:
                decision_count = await connection.scalar(
                    sa.select(sa.func.count())
                    .select_from(approval_decisions_table)
                    .where(approval_decisions_table.c.request_id == request.request_id)
                )
                request_count = await connection.scalar(
                    sa.select(sa.func.count())
                    .select_from(approval_requests_table)
                    .where(approval_requests_table.c.request_id == request.request_id)
                )
            assert decision_count == 0
            assert request_count == 1
        finally:
            for task in pending:
                if not task.done():
                    task.cancel()
            if pending:
                await asyncio.gather(*pending, return_exceptions=True)
            try:
                await _delete_test_request(engine, request.request_id)
            finally:
                await engine.dispose()

    asyncio.run(run_scenario())


def test_record_decision_once_rolls_back_unexpected_primary_key_violation() -> None:
    """Do not mask an unexpected PK conflict; leave state intact and engine usable."""
    _require_database_tests()

    async def run_scenario() -> None:
        engine = create_database_engine(DatabaseConfig.from_environment())
        original_request = _make_request()
        competing_request = _make_request()
        try:
            async with engine.connect() as connection:
                database_now = await connection.scalar(sa.select(sa.func.clock_timestamp()))
            assert isinstance(database_now, datetime)
            database_now = database_now.astimezone(UTC)

            active_window = {
                "requested_at": database_now - timedelta(minutes=5),
                "expires_at": database_now + timedelta(minutes=25),
            }
            original_request = replace(original_request, **active_window)
            competing_request = replace(competing_request, **active_window)

            original_decision = RemediationApprovalDecision(
                request_id=original_request.request_id,
                operator_id="original-operator",
                outcome=RemediationApprovalOutcome.APPROVED,
                decided_at=database_now,
                reason="First valid decision remains unchanged.",
            )
            # The request IDs differ, but this attempt reuses a *decision* PK.
            conflicting_decision = RemediationApprovalDecision(
                decision_id=original_decision.decision_id,
                request_id=competing_request.request_id,
                operator_id="competing-operator",
                outcome=RemediationApprovalOutcome.REJECTED,
                decided_at=database_now,
                reason="Must fail because decision_id is already used.",
            )
            repository = PostgresApprovalRepository(engine=engine)
            await repository.create_request(original_request)
            await repository.create_request(competing_request)
            await repository.record_decision_once(original_decision)

            # This is an unexpected primary-key violation, NOT the expected
            # UNIQUE(request_id) conflict mapped to ApprovalAlreadyDecidedError.
            with pytest.raises(sa.exc.IntegrityError) as captured:
                await repository.record_decision_once(conflicting_decision)

            db_error = captured.value.orig
            assert getattr(db_error, "sqlstate", None) == "23505"
            diagnostic = getattr(db_error, "diag", None)
            assert getattr(diagnostic, "constraint_name", None) == "pk_approval_decisions"

            # Check committed data using a separate connection after rollback.
            statement = sa.select(approval_decisions_table).where(
                approval_decisions_table.c.request_id.in_(
                    [original_request.request_id, competing_request.request_id]
                )
            )
            async with engine.connect() as connection:
                rows = (await connection.execute(statement)).mappings().all()
                remaining_requests = await connection.scalar(
                    sa.select(sa.func.count())
                    .select_from(approval_requests_table)
                    .where(
                        approval_requests_table.c.request_id.in_(
                            [original_request.request_id, competing_request.request_id]
                        )
                    )
                )

            assert remaining_requests == 2
            assert len(rows) == 1
            assert rows[0]["request_id"] == original_request.request_id
            assert rows[0]["decision_id"] == original_decision.decision_id
            assert rows[0]["operator_id"] == original_decision.operator_id
            assert rows[0]["outcome"] == original_decision.outcome.value
            assert rows[0]["reason"] == original_decision.reason

            # A clean, valid operation must still succeed after the failed TX.
            retry = replace(conflicting_decision, decision_id=uuid4())
            await repository.record_decision_once(retry)

            async with engine.connect() as connection:
                stored_retry = (
                    (
                        await connection.execute(
                            sa.select(approval_decisions_table).where(
                                approval_decisions_table.c.request_id
                                == competing_request.request_id
                            )
                        )
                    )
                    .mappings()
                    .one()
                )
            assert stored_retry["decision_id"] == retry.decision_id
            assert stored_retry["outcome"] == retry.outcome.value
            assert competing_request.requested_at <= stored_retry["recorded_at"]
            assert stored_retry["recorded_at"] < competing_request.expires_at
        finally:
            try:
                await _delete_test_request(engine, competing_request.request_id)
            finally:
                try:
                    await _delete_test_request(engine, original_request.request_id)
                finally:
                    await engine.dispose()

    asyncio.run(run_scenario())
