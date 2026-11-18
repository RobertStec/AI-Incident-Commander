"""In-memory checkpoint contract for the parent graph and nested Investigator.

These tests exercise checkpoint persistence, not crash-safe durable execution.
"""

import asyncio
from datetime import UTC, datetime
from uuid import UUID

import pytest
from langchain_core.runnables import RunnableConfig
from langgraph.checkpoint.memory import InMemorySaver

from ai_incident_commander.domain.evidence import Evidence, EvidenceType
from ai_incident_commander.domain.incident import Incident
from ai_incident_commander.orchestration.incident_graph import (
    EvidenceCollector,
    IncidentGraph,
    baseline_investigation_planner,
    build_incident_graph,
)
from ai_incident_commander.orchestration.incident_state import (
    IncidentSnapshot,
    IncidentState,
    InvestigationPlanSnapshot,
    initial_incident_state,
)

_OBSERVED_AT = datetime(2026, 11, 16, 9, 0, tzinfo=UTC)


def _state(incident_number: int = 100) -> IncidentState:
    incident = Incident(
        incident_id=UUID(int=incident_number),
        title="Payments API errors",
        description="HTTP 500 rate increased after deployment",
        created_at=_OBSERVED_AT,
        updated_at=_OBSERVED_AT,
    )
    return initial_incident_state(incident)


def _collector(kind: EvidenceType, evidence_number: int) -> EvidenceCollector:
    async def collect(incident: IncidentSnapshot) -> list[Evidence]:
        return [
            Evidence(
                evidence_id=UUID(int=evidence_number),
                incident_id=UUID(incident["incident_id"]),
                evidence_type=kind,
                source="test-observability",
                source_reference=f"checkpoint-source-{evidence_number}",
                summary="Observed increased failures",
                observed_at=_OBSERVED_AT,
                collected_at=_OBSERVED_AT,
                metadata={"count": 4},
            )
        ]

    return collect


def _graph(checkpointer: InMemorySaver | None = None) -> IncidentGraph:
    return build_incident_graph(
        collect_logs=_collector(EvidenceType.LOG, 1),
        collect_metrics=_collector(EvidenceType.METRIC, 2),
        checkpointer=checkpointer,
    )


def test_existing_invocation_without_checkpointer_still_works() -> None:
    result = asyncio.run(_graph().ainvoke(_state()))
    assert result["workflow_phase"] == "analyzing"
    assert len(result["evidence"]) == 2


def test_checkpoint_stores_complete_parent_state_after_nested_investigation() -> None:
    async def scenario() -> tuple[IncidentState, dict[str, object], tuple[str, ...]]:
        saver = InMemorySaver()
        graph = _graph(saver)
        config: RunnableConfig = {"configurable": {"thread_id": "run-checkpoint-001"}}
        result = await graph.ainvoke(_state(), config=config)
        saved = await graph.aget_state(config)
        return result, dict(saved.values), saved.next

    result, saved_values, next_nodes = asyncio.run(scenario())
    assert saved_values == result
    assert saved_values["workflow_phase"] == "analyzing"
    assert saved_values["investigation_plan"] == result["investigation_plan"]
    assert len(result["evidence"]) == 2
    assert saved_values["hypotheses"] == []
    assert next_nodes == ()


def test_checkpoint_history_records_parent_intake_and_subgraph_completion() -> None:
    async def scenario() -> tuple[list[str], int]:
        graph = _graph(InMemorySaver())
        config: RunnableConfig = {"configurable": {"thread_id": "run-history-001"}}
        await graph.ainvoke(_state(), config=config)
        history = [item async for item in graph.aget_state_history(config)]
        phases = [item.values.get("workflow_phase", "") for item in history]
        return phases, len(history)

    phases, count = asyncio.run(scenario())
    assert count >= 3
    assert phases[0] == "analyzing"
    assert "planning" in phases


def test_two_thread_ids_do_not_share_incident_state() -> None:
    async def scenario() -> tuple[str, str]:
        graph = _graph(InMemorySaver())
        first: RunnableConfig = {"configurable": {"thread_id": "run-A"}}
        second: RunnableConfig = {"configurable": {"thread_id": "run-B"}}
        await graph.ainvoke(_state(100), config=first)
        await graph.ainvoke(_state(101), config=second)
        snapshot_a = await graph.aget_state(first)
        snapshot_b = await graph.aget_state(second)
        return (
            snapshot_a.values["incident"]["incident_id"],
            snapshot_b.values["incident"]["incident_id"],
        )

    first_id, second_id = asyncio.run(scenario())
    assert first_id == str(UUID(int=100))
    assert second_id == str(UUID(int=101))
    assert first_id != second_id


def test_new_graph_instance_can_read_state_from_same_in_memory_saver() -> None:
    async def scenario() -> dict[str, object]:
        saver = InMemorySaver()
        config: RunnableConfig = {"configurable": {"thread_id": "run-shared-saver"}}
        await _graph(saver).ainvoke(_state(), config=config)
        return dict((await _graph(saver).aget_state(config)).values)

    saved = asyncio.run(scenario())
    assert saved["workflow_phase"] == "analyzing"
    assert isinstance(saved["evidence"], list)
    assert len(saved["evidence"]) == 2


def test_checkpointer_requires_thread_id_for_invocation() -> None:
    async def scenario() -> None:
        graph = _graph(InMemorySaver())
        with pytest.raises(ValueError, match="thread_id"):
            await graph.ainvoke(_state())

    asyncio.run(scenario())


def test_resume_failed_metrics_preserves_successful_parallel_work() -> None:
    """Resume a nested investigation without repeating completed sibling work.

    The first invocation fails in metrics after logs finishes. A second graph
    instance with the same saver and thread_id explicitly resumes the run.
    """

    async def scenario() -> None:
        saver = InMemorySaver()
        config: RunnableConfig = {"configurable": {"thread_id": "run-failed-metrics-resume"}}
        calls = {"planner": 0, "logs": 0, "metrics": 0}
        logs_finished = asyncio.Event()
        log_collector = _collector(EvidenceType.LOG, 1)
        metric_collector = _collector(EvidenceType.METRIC, 2)

        async def planner(incident: IncidentSnapshot) -> InvestigationPlanSnapshot:
            calls["planner"] += 1
            return await baseline_investigation_planner(incident)

        async def logs(incident: IncidentSnapshot) -> list[Evidence]:
            calls["logs"] += 1
            result = await log_collector(incident)
            logs_finished.set()
            return result

        async def metrics(incident: IncidentSnapshot) -> list[Evidence]:
            calls["metrics"] += 1
            if calls["metrics"] == 1:
                await logs_finished.wait()
                # Allow the successful sibling to return before raising.
                await asyncio.sleep(0.05)
                raise RuntimeError("transient metrics failure")
            return await metric_collector(incident)

        def make_graph() -> IncidentGraph:
            return build_incident_graph(
                collect_logs=logs,
                collect_metrics=metrics,
                investigation_planner=planner,
                checkpointer=saver,
            )

        original = make_graph()
        with pytest.raises(RuntimeError, match="transient metrics failure"):
            await original.ainvoke(_state(), config=config, durability="sync")

        failed = await original.aget_state(config)
        assert failed.next  # The parent graph has not finished.
        assert calls == {"planner": 1, "logs": 1, "metrics": 1}

        # This is resume, not a fresh call with initial state.
        resumed = make_graph()
        result = await resumed.ainvoke(None, config=config, durability="sync")
        final = await resumed.aget_state(config)

        assert result["workflow_phase"] == "analyzing"
        assert {item["evidence_id"] for item in result["evidence"]} == {
            str(UUID(int=1)),
            str(UUID(int=2)),
        }
        assert len(result["evidence"]) == 2
        assert final.next == ()
        assert dict(final.values) == result
        assert calls == {"planner": 1, "logs": 1, "metrics": 2}

    asyncio.run(scenario())
