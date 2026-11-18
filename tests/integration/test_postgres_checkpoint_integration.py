"""Opt-in PostgreSQL integration tests for the nested incident graph checkpointer.

Requires a pre-provisioned local langgraph_checkpoint schema. Tests never run
AsyncPostgresSaver.setup() and only delete checkpoints owned by their thread IDs.
"""

import asyncio
import os
import signal
import subprocess
import sys
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from uuid import NAMESPACE_URL, UUID, uuid4, uuid5

import pytest
from psycopg import AsyncConnection

from ai_incident_commander.application.checkpoint_bootstrap import (
    postgres_checkpoint_lifespan,
)
from ai_incident_commander.domain.evidence import Evidence, EvidenceType
from ai_incident_commander.domain.incident import Incident
from ai_incident_commander.infrastructure.checkpoint_connection import (
    create_checkpoint_conninfo,
)
from ai_incident_commander.infrastructure.database_config import DatabaseConfig
from ai_incident_commander.orchestration.incident_graph import build_incident_graph
from ai_incident_commander.orchestration.incident_state import (
    IncidentSnapshot,
    InvestigationPlanSnapshot,
    create_investigation_plan,
    initial_incident_state,
)

_OBSERVED_AT = datetime(2026, 11, 17, 12, 0, tzinfo=UTC)


def _local_checkpoint_config() -> DatabaseConfig:
    if os.environ.get("RUN_DB_CHECKPOINT_TESTS") != "1":
        pytest.skip("Set RUN_DB_CHECKPOINT_TESTS=1 to enable checkpoint database tests")

    config = DatabaseConfig.from_environment()
    if (
        config.url.host not in ("localhost", "127.0.0.1", "::1")
        or config.url.database != "incident_commander"
        or config.url.username != "incident_commander"
    ):
        pytest.fail("Checkpoint integration tests require the local incident_commander database")
    return config


async def _assert_prepared_checkpoint_schema(config: DatabaseConfig) -> None:
    """Read-only preflight; schema migrations must be applied out of band."""
    async with await AsyncConnection.connect(create_checkpoint_conninfo(config)) as conn:
        async with conn.cursor() as cursor:
            await cursor.execute(
                """
                SELECT current_database(), current_user, current_schema(),
                       current_setting('search_path'),
                       to_regclass('langgraph_checkpoint.checkpoints') IS NOT NULL,
                       to_regclass('langgraph_checkpoint.checkpoint_blobs') IS NOT NULL,
                       to_regclass('langgraph_checkpoint.checkpoint_writes') IS NOT NULL,
                       to_regclass('langgraph_checkpoint.checkpoint_migrations') IS NOT NULL,
                       to_regclass('public.checkpoints') IS NULL
                """
            )
            identity = await cursor.fetchone()

    if identity != (
        "incident_commander",
        "incident_commander",
        "langgraph_checkpoint",
        "langgraph_checkpoint",
        True,
        True,
        True,
        True,
        True,
    ):
        pytest.fail("Checkpoint integration schema is missing or the connection is misconfigured")


def _incident() -> Incident:
    return Incident(
        incident_id=uuid4(),
        title="Checkpoint integration incident",
        description="Read-only diagnostic checkpoint persistence test",
        created_at=_OBSERVED_AT,
        updated_at=_OBSERVED_AT,
    )


async def _logs(incident: IncidentSnapshot) -> list[Evidence]:
    incident_id = UUID(incident["incident_id"])
    evidence_id = uuid5(NAMESPACE_URL, f"checkpoint-integration:{incident_id}")
    return [
        Evidence(
            evidence_id=evidence_id,
            incident_id=incident_id,
            evidence_type=EvidenceType.LOG,
            source="checkpoint-integration-test",
            source_reference=f"log-{evidence_id}",
            summary="Integration test observation",
            observed_at=_OBSERVED_AT,
            collected_at=_OBSERVED_AT,
            metadata={},
        )
    ]


async def _metrics(_incident: IncidentSnapshot) -> list[Evidence]:
    return []


def _thread_id() -> str:
    return f"checkpoint-integration-{uuid4()}"


def test_completed_incident_persists_across_independent_checkpointer_lifespans() -> None:
    """Persist the actual parent + Investigator graph and reload its history."""
    config = _local_checkpoint_config()
    thread_id = _thread_id()
    run_config = {"configurable": {"thread_id": thread_id}}
    incident = _incident()

    async def scenario() -> None:
        await _assert_prepared_checkpoint_schema(config)
        try:
            async with postgres_checkpoint_lifespan(config=config) as saver:
                graph = build_incident_graph(
                    collect_logs=_logs,
                    collect_metrics=_metrics,
                    checkpointer=saver,
                )
                result = await graph.ainvoke(
                    initial_incident_state(incident),
                    config=run_config,
                    durability="sync",
                )
                assert result["workflow_phase"] == "analyzing"
                assert len(result["evidence"]) == 1

            # The first DB connection has closed. This graph has a fresh saver.
            async with postgres_checkpoint_lifespan(config=config) as saver:
                graph = build_incident_graph(
                    collect_logs=_logs,
                    collect_metrics=_metrics,
                    checkpointer=saver,
                )
                snapshot = await graph.aget_state(run_config)
                history = [item async for item in graph.aget_state_history(run_config)]

                assert snapshot.next == ()
                assert snapshot.values["workflow_phase"] == "analyzing"
                assert snapshot.values["incident"]["incident_id"] == str(incident.incident_id)
                assert snapshot.values["evidence"] == result["evidence"]
                assert snapshot.values["hypotheses"] == []
                assert len(history) >= 2
                assert any(item.values.get("workflow_phase") == "planning" for item in history)
        finally:
            # The ID is random and owned only by this test. Never truncate tables.
            async with postgres_checkpoint_lifespan(config=config) as saver:
                await saver.adelete_thread(thread_id)

    asyncio.run(scenario())


def test_checkpoint_threads_remain_isolated_in_shared_postgres_schema() -> None:
    """Two independent incident runs cannot read each other's checkpoint state."""
    config = _local_checkpoint_config()
    first_id, second_id = _thread_id(), _thread_id()
    first, second = _incident(), _incident()
    first_config = {"configurable": {"thread_id": first_id}}
    second_config = {"configurable": {"thread_id": second_id}}

    async def scenario() -> None:
        await _assert_prepared_checkpoint_schema(config)
        try:
            async with postgres_checkpoint_lifespan(config=config) as saver:
                graph = build_incident_graph(
                    collect_logs=_logs,
                    collect_metrics=_metrics,
                    checkpointer=saver,
                )
                await graph.ainvoke(
                    initial_incident_state(first), config=first_config, durability="sync"
                )
                await graph.ainvoke(
                    initial_incident_state(second), config=second_config, durability="sync"
                )

            async with postgres_checkpoint_lifespan(config=config) as saver:
                graph = build_incident_graph(
                    collect_logs=_logs,
                    collect_metrics=_metrics,
                    checkpointer=saver,
                )
                first_state = (await graph.aget_state(first_config)).values
                second_state = (await graph.aget_state(second_config)).values
                assert first_state["incident"]["incident_id"] == str(first.incident_id)
                assert second_state["incident"]["incident_id"] == str(second.incident_id)
                assert first_state["workflow_phase"] == "analyzing"
                assert second_state["workflow_phase"] == "analyzing"
                assert len(first_state["evidence"]) == len(second_state["evidence"]) == 1
                assert first_state["evidence"][0]["incident_id"] == str(first.incident_id)
                assert second_state["evidence"][0]["incident_id"] == str(second.incident_id)
                assert first_state["evidence"] != second_state["evidence"]
        finally:
            async with postgres_checkpoint_lifespan(config=config) as saver:
                await saver.adelete_thread(first_id)
                await saver.adelete_thread(second_id)

    asyncio.run(scenario())


def test_failed_parallel_collector_resumes_across_independent_checkpointer_lifespans() -> None:
    """Persist pending writes and resume only unfinished read-only work."""
    config = _local_checkpoint_config()
    thread_id = _thread_id()
    run_config = {"configurable": {"thread_id": thread_id}}
    incident = _incident()
    calls = {"planner": 0, "logs": 0, "metrics": 0}
    logs_completed = asyncio.Event()
    metric_id = uuid5(NAMESPACE_URL, f"checkpoint-metric:{incident.incident_id}")
    log_id = uuid5(NAMESPACE_URL, f"checkpoint-integration:{incident.incident_id}")

    async def planner(_snapshot: IncidentSnapshot) -> InvestigationPlanSnapshot:
        calls["planner"] += 1
        return create_investigation_plan(
            sources=["logs", "metrics"],
            rationale="Verify PostgreSQL recovery of parallel diagnostic collectors.",
        )

    async def counting_logs(snapshot: IncidentSnapshot) -> list[Evidence]:
        calls["logs"] += 1
        observations = await _logs(snapshot)
        logs_completed.set()
        return observations

    async def transient_metrics(snapshot: IncidentSnapshot) -> list[Evidence]:
        calls["metrics"] += 1
        if calls["metrics"] == 1:
            # Ensure the logs branch has completed before the controlled failure.
            await logs_completed.wait()
            await asyncio.sleep(0.02)
            raise RuntimeError("Simulated transient metrics collector failure")

        return [
            Evidence(
                evidence_id=metric_id,
                incident_id=UUID(snapshot["incident_id"]),
                evidence_type=EvidenceType.METRIC,
                source="checkpoint-integration-test",
                source_reference=f"metric-{metric_id}",
                summary="Metric observation after manual resume",
                observed_at=_OBSERVED_AT,
                collected_at=_OBSERVED_AT,
                metadata={},
            )
        ]

    async def scenario() -> None:
        await _assert_prepared_checkpoint_schema(config)
        try:
            # First lifespan: logs succeeds; metrics fails in the same superstep.
            async with postgres_checkpoint_lifespan(config=config) as saver:
                graph = build_incident_graph(
                    collect_logs=counting_logs,
                    collect_metrics=transient_metrics,
                    investigation_planner=planner,
                    checkpointer=saver,
                )
                with pytest.raises(
                    RuntimeError, match="Simulated transient metrics collector failure"
                ):
                    await graph.ainvoke(
                        initial_incident_state(incident),
                        config=run_config,
                        durability="sync",
                    )

                assert calls == {"planner": 1, "logs": 1, "metrics": 1}
                failed_state = await graph.aget_state(run_config)
                assert failed_state.next  # The parent graph is not yet finished.

            # New saver and graph: manually resume the *same* thread with no new input.
            async with postgres_checkpoint_lifespan(config=config) as saver:
                graph = build_incident_graph(
                    collect_logs=counting_logs,
                    collect_metrics=transient_metrics,
                    investigation_planner=planner,
                    checkpointer=saver,
                )
                result = await graph.ainvoke(None, config=run_config, durability="sync")
                state = await graph.aget_state(run_config)

                assert result["workflow_phase"] == "analyzing"
                assert state.next == ()
                assert state.values["workflow_phase"] == "analyzing"
                assert state.values["incident"]["incident_id"] == str(incident.incident_id)
                assert state.values["evidence"] == result["evidence"]
                assert len(result["evidence"]) == 2
                assert {item["evidence_id"] for item in result["evidence"]} == {
                    str(log_id),
                    str(metric_id),
                }
                assert calls == {"planner": 1, "logs": 1, "metrics": 2}
        finally:
            # Delete only this test's random thread, including failed-step writes.
            async with postgres_checkpoint_lifespan(config=config) as saver:
                await saver.adelete_thread(thread_id)

    asyncio.run(scenario())


def test_failed_investigation_resumes_after_python_process_restart(tmp_path: Path) -> None:
    """A failed parallel step resumes in a fresh Python process using PostgreSQL."""
    config = _local_checkpoint_config()
    thread_id = _thread_id()
    incident = _incident()
    trace_path = tmp_path / "checkpoint-restart-events.txt"
    worker = Path(__file__).with_name("_checkpoint_restart_worker.py")
    run_config = {"configurable": {"thread_id": thread_id}}

    def run_worker(phase: str) -> None:
        # Each subprocess is a new interpreter, graph and PostgreSQL connection.
        # No shell or credentials in CLI arguments; environment is inherited.
        completed = subprocess.run(
            [
                sys.executable,
                str(worker),
                phase,
                thread_id,
                str(incident.incident_id),
                str(trace_path),
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=45,
        )
        assert completed.returncode == 0, (
            f"Checkpoint {phase} worker exited with code {completed.returncode}: {completed.stderr}"
        )

    async def inspect_state() -> None:
        async with postgres_checkpoint_lifespan(config=config) as saver:
            graph = build_incident_graph(
                collect_logs=_logs,
                collect_metrics=_metrics,
                checkpointer=saver,
            )
            state = await graph.aget_state(run_config)
            assert state.next == ()
            assert state.values["workflow_phase"] == "analyzing"
            assert state.values["incident"]["incident_id"] == str(incident.incident_id)
            assert len(state.values["evidence"]) == 2
            assert {item["evidence_type"] for item in state.values["evidence"]} == {
                EvidenceType.LOG.value,
                EvidenceType.METRIC.value,
            }

    async def cleanup() -> None:
        async with postgres_checkpoint_lifespan(config=config) as saver:
            await saver.adelete_thread(thread_id)

    asyncio.run(_assert_prepared_checkpoint_schema(config))
    try:
        run_worker("fail")
        assert Counter(trace_path.read_text(encoding="utf-8").splitlines()) == {
            "fail:planner": 1,
            "fail:logs": 1,
            "fail:metrics": 1,
        }
        run_worker("resume")
        assert Counter(trace_path.read_text(encoding="utf-8").splitlines()) == {
            "fail:planner": 1,
            "fail:logs": 1,
            "fail:metrics": 1,
            "resume:metrics": 1,
        }
        asyncio.run(inspect_state())
    finally:
        # Remove only checkpoints created under this test's random thread ID.
        asyncio.run(cleanup())


@pytest.mark.skipif(os.name != "posix", reason="SIGKILL test requires POSIX")
def test_inflight_collector_recovers_after_sigkill(tmp_path: Path) -> None:
    """SIGKILL only the owned worker, after logs' pending write is committed."""
    config = _local_checkpoint_config()
    thread_id = _thread_id()
    incident = _incident()
    run_config = {"configurable": {"thread_id": thread_id}}
    worker_path = Path(__file__).with_name("_checkpoint_restart_worker.py")
    trace_path = tmp_path / "checkpoint-sigkill-events.txt"
    argv = (
        sys.executable,
        str(worker_path),
        "hang",
        thread_id,
        str(incident.incident_id),
        str(trace_path),
    )
    expected_first_events = {"hang:planner", "hang:logs", "hang:metrics"}

    async def scenario() -> None:
        await _assert_prepared_checkpoint_schema(config)
        child: asyncio.subprocess.Process | None = None
        try:
            # Only the process handle created here may be killed. No shell or PID lookup.
            child = await asyncio.create_subprocess_exec(
                *argv,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            async def wait_for_committed_logs() -> None:
                # A trace entry means a function was entered, not that its
                # returned update reached durable storage. Check the real DB.
                conninfo = create_checkpoint_conninfo(config)
                async with await AsyncConnection.connect(conninfo) as conn:
                    async with conn.cursor() as cursor:
                        while True:
                            assert child is not None
                            if child.returncode is not None:
                                raise AssertionError(
                                    f"SIGKILL worker exited prematurely: {child.returncode}"
                                )
                            events = (
                                set(trace_path.read_text(encoding="utf-8").splitlines())
                                if trace_path.exists()
                                else set()
                            )
                            if expected_first_events.issubset(events):
                                await cursor.execute(
                                    """
                                    SELECT EXISTS (
                                        SELECT 1
                                        FROM langgraph_checkpoint.checkpoint_writes
                                        WHERE thread_id = %s
                                          AND checkpoint_ns <> ''
                                          AND channel = 'evidence'
                                    )
                                    """,
                                    (thread_id,),
                                )
                                durable = await cursor.fetchone()
                                if durable is not None and durable[0]:
                                    return
                            await asyncio.sleep(0.1)

            # Bounded readiness check; never kill based on an arbitrary delay.
            await asyncio.wait_for(wait_for_committed_logs(), timeout=30)
            assert child.returncode is None
            child.kill()  # SIGKILL only this test-owned subprocess (WSL/Linux).
            await asyncio.wait_for(child.communicate(), timeout=10)
            assert child.returncode == -signal.SIGKILL

            # Read the unfinished parent state from an independent connection.
            async with postgres_checkpoint_lifespan(config=config) as saver:
                graph = build_incident_graph(
                    collect_logs=_logs,
                    collect_metrics=_metrics,
                    checkpointer=saver,
                )
                unfinished = await graph.aget_state(run_config)
                assert unfinished.next

            # Fresh interpreter; use the production graph and the same thread_id.
            child = await asyncio.create_subprocess_exec(
                sys.executable,
                str(worker_path),
                "resume",
                thread_id,
                str(incident.incident_id),
                str(trace_path),
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _stdout, stderr = await asyncio.wait_for(child.communicate(), timeout=45)
            assert child.returncode == 0, (
                f"Resume worker failed with exit code {child.returncode}: "
                f"{stderr.decode(errors='replace')}"
            )

            assert Counter(trace_path.read_text(encoding="utf-8").splitlines()) == {
                "hang:planner": 1,
                "hang:logs": 1,
                "hang:metrics": 1,
                "resume:metrics": 1,
            }
            async with postgres_checkpoint_lifespan(config=config) as saver:
                graph = build_incident_graph(
                    collect_logs=_logs,
                    collect_metrics=_metrics,
                    checkpointer=saver,
                )
                completed = await graph.aget_state(run_config)
                assert completed.next == ()
                assert completed.values["workflow_phase"] == "analyzing"
                assert completed.values["incident"]["incident_id"] == str(incident.incident_id)
                assert {item["evidence_type"] for item in completed.values["evidence"]} == {
                    EvidenceType.LOG.value,
                    EvidenceType.METRIC.value,
                }
                assert len(completed.values["evidence"]) == 2
        finally:
            # Always reap our child before deleting its test-owned checkpoint data.
            if child is not None:
                if child.returncode is None:
                    child.kill()
                await asyncio.wait_for(child.communicate(), timeout=10)
            async with postgres_checkpoint_lifespan(config=config) as saver:
                await saver.adelete_thread(thread_id)

    asyncio.run(scenario())
