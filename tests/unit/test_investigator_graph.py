"""Tests for the standalone, narrower-state Investigator subgraph."""

import asyncio
import json
from copy import deepcopy
from datetime import UTC, datetime
from typing import cast
from uuid import UUID

import pytest
from langgraph.types import RetryPolicy

from ai_incident_commander.domain.evidence import Evidence, EvidenceType
from ai_incident_commander.domain.incident import Incident
from ai_incident_commander.orchestration.incident_state import (
    EvidenceSnapshotConflictError,
    IncidentSnapshot,
    InvestigationPlanSnapshot,
    InvestigationSource,
    InvestigatorState,
    snapshot_evidence,
    snapshot_incident,
)
from ai_incident_commander.orchestration.investigator_graph import (
    EvidenceCollector,
    EvidenceIncidentMismatchError,
    InvestigationPlanner,
    TransientEvidenceCollectionError,
    build_investigator_graph,
)

_INCIDENT_ID = UUID(int=100)
_OBSERVED_AT = datetime(2026, 11, 16, 9, 0, tzinfo=UTC)


def _state() -> InvestigatorState:
    incident = Incident(
        incident_id=_INCIDENT_ID,
        title="Payments API errors",
        description="HTTP 500 rate increased after deployment",
        created_at=_OBSERVED_AT,
        updated_at=_OBSERVED_AT,
    )
    return InvestigatorState(
        incident=snapshot_incident(incident),
        workflow_phase="planning",
        investigation_plan=None,
        evidence=[],
    )


def _observation(
    identifier: int,
    *,
    evidence_type: EvidenceType = EvidenceType.LOG,
    incident_id: UUID = _INCIDENT_ID,
    summary: str = "Observed increased failures",
) -> Evidence:
    return Evidence(
        evidence_id=UUID(int=identifier),
        incident_id=incident_id,
        evidence_type=evidence_type,
        source="test-observability",
        source_reference=f"source-{identifier}",
        summary=summary,
        observed_at=_OBSERVED_AT,
        collected_at=_OBSERVED_AT,
        metadata={"count": 4},
    )


def _collector(*items: Evidence) -> EvidenceCollector:
    async def collect(_incident: IncidentSnapshot) -> list[Evidence]:
        return list(items)

    return collect


def _planner(*sources: InvestigationSource) -> InvestigationPlanner:
    async def plan(_incident: IncidentSnapshot) -> InvestigationPlanSnapshot:
        return InvestigationPlanSnapshot(sources=list(sources), rationale="Check signals.")

    return plan


def _run(
    *,
    logs: EvidenceCollector,
    metrics: EvidenceCollector,
    planner: InvestigationPlanner | None = None,
    state: InvestigatorState | None = None,
) -> InvestigatorState:
    if planner is None:
        graph = build_investigator_graph(collect_logs=logs, collect_metrics=metrics)
    else:
        graph = build_investigator_graph(
            collect_logs=logs,
            collect_metrics=metrics,
            investigation_planner=planner,
        )
    return asyncio.run(graph.ainvoke(_state() if state is None else state))


def test_subgraph_default_planner_collects_both_without_coordinator_fields() -> None:
    logs = _observation(1)
    metrics = _observation(2, evidence_type=EvidenceType.METRIC)

    result = _run(logs=_collector(logs), metrics=_collector(metrics))

    assert result["workflow_phase"] == "analyzing"
    assert result["investigation_plan"] == {
        "sources": ["logs", "metrics"],
        "rationale": f"Collect baseline logs and metrics for incident {_INCIDENT_ID}.",
    }
    assert [item["evidence_id"] for item in result["evidence"]] == [
        str(logs.evidence_id),
        str(metrics.evidence_id),
    ]
    assert set(result) == {
        "incident",
        "workflow_phase",
        "investigation_plan",
        "evidence",
    }
    assert json.loads(json.dumps(result, allow_nan=False)) == result


@pytest.mark.parametrize(
    "sources",
    [
        ("logs",),
        ("metrics",),
        ("logs", "metrics"),
    ],
)
def test_only_selected_collectors_run_and_aggregation_fires_once(
    sources: tuple[InvestigationSource, ...],
) -> None:
    calls: list[str] = []

    async def logs(_incident: IncidentSnapshot) -> list[Evidence]:
        calls.append("logs")
        return []

    async def metrics(_incident: IncidentSnapshot) -> list[Evidence]:
        calls.append("metrics")
        return []

    async def scenario() -> int:
        graph = build_investigator_graph(
            collect_logs=logs,
            collect_metrics=metrics,
            investigation_planner=_planner(*sources),
        )
        aggregations = 0
        async for update in graph.astream(_state(), stream_mode="updates"):
            if "aggregate_evidence" in update:
                aggregations += 1
        return aggregations

    assert asyncio.run(scenario()) == 1
    assert sorted(calls) == sorted(sources)
    assert len(calls) == len(sources)


def test_selected_collectors_really_run_concurrently() -> None:
    async def scenario() -> InvestigatorState:
        logs_started = asyncio.Event()
        metrics_started = asyncio.Event()

        async def logs(_incident: IncidentSnapshot) -> list[Evidence]:
            logs_started.set()
            await metrics_started.wait()
            return [_observation(1)]

        async def metrics(_incident: IncidentSnapshot) -> list[Evidence]:
            metrics_started.set()
            await logs_started.wait()
            return [_observation(2, evidence_type=EvidenceType.METRIC)]

        graph = build_investigator_graph(collect_logs=logs, collect_metrics=metrics)
        return await asyncio.wait_for(graph.ainvoke(_state()), timeout=5)

    result = asyncio.run(scenario())
    assert result["workflow_phase"] == "analyzing"
    assert len(result["evidence"]) == 2


def test_subgraph_deduplicates_same_observation_from_parallel_branches() -> None:
    item = _observation(1)

    result = _run(logs=_collector(item), metrics=_collector(item))

    assert len(result["evidence"]) == 1


def test_subgraph_rejects_conflicting_evidence_identifiers() -> None:
    with pytest.raises(EvidenceSnapshotConflictError, match="Conflicting evidence"):
        _run(
            logs=_collector(_observation(1)),
            metrics=_collector(_observation(1, summary="Different measurement")),
        )


def test_subgraph_rejects_evidence_from_another_incident() -> None:
    with pytest.raises(EvidenceIncidentMismatchError, match="different incident"):
        _run(
            logs=_collector(_observation(1, incident_id=UUID(int=999))),
            metrics=_collector(),
        )


def test_subgraph_unions_seeded_and_new_evidence() -> None:
    state = _state()
    existing = snapshot_evidence(_observation(10))
    state["evidence"] = [existing]

    result = _run(
        logs=_collector(_observation(1)),
        metrics=_collector(),
        planner=_planner("logs"),
        state=state,
    )

    assert [item["evidence_id"] for item in result["evidence"]] == [
        str(UUID(int=1)),
        str(UUID(int=10)),
    ]
    assert state["evidence"] == [existing]


def test_subgraph_revalidates_planner_before_calling_collectors() -> None:
    calls: list[str] = []

    async def collector(_incident: IncidentSnapshot) -> list[Evidence]:
        calls.append("collector")
        return []

    async def planner(_incident: IncidentSnapshot) -> InvestigationPlanSnapshot:
        unknown = cast("InvestigationSource", "deployments")
        return InvestigationPlanSnapshot(sources=[unknown], rationale="Investigate release impact.")

    with pytest.raises(ValueError, match="unsupported source"):
        _run(logs=collector, metrics=collector, planner=planner)

    assert calls == []


def test_subgraph_requires_planning_phase_and_unset_plan() -> None:
    state = _state()
    state["workflow_phase"] = "intake"
    with pytest.raises(ValueError, match="planning phase"):
        _run(logs=_collector(), metrics=_collector(), state=state)

    state = _state()
    state["investigation_plan"] = InvestigationPlanSnapshot(
        sources=["logs"], rationale="Injected by caller."
    )
    with pytest.raises(ValueError, match="plan must be unset"):
        _run(logs=_collector(), metrics=_collector(), state=state)


def test_subgraph_does_not_retry_failed_planner() -> None:
    attempts = 0

    async def failing(_incident: IncidentSnapshot) -> InvestigationPlanSnapshot:
        nonlocal attempts
        attempts += 1
        raise RuntimeError("Planner offline")

    with pytest.raises(RuntimeError, match="Planner offline"):
        _run(logs=_collector(), metrics=_collector(), planner=failing)

    assert attempts == 1


def test_subgraph_does_not_retry_failed_collector() -> None:
    attempts = 0

    async def failing(_incident: IncidentSnapshot) -> list[Evidence]:
        nonlocal attempts
        attempts += 1
        raise RuntimeError("Observability offline")

    with pytest.raises(RuntimeError, match="Observability offline"):
        _run(logs=failing, metrics=_collector())

    assert attempts == 1


def test_subgraph_isolates_incident_snapshot_from_injected_dependencies() -> None:
    state = _state()
    original = deepcopy(state)

    async def planner(incident: IncidentSnapshot) -> InvestigationPlanSnapshot:
        incident["title"] = "Untrusted replacement"
        incident["affected_services"].append("wrong-service")
        return InvestigationPlanSnapshot(sources=["logs"], rationale="Inspect logs.")

    async def logs(incident: IncidentSnapshot) -> list[Evidence]:
        incident["title"] = "Changed by collector"
        incident["affected_services"].append("foreign-service")
        return [_observation(1)]

    result = _run(logs=logs, metrics=_collector(), planner=planner, state=state)

    assert result["incident"] == original["incident"]
    assert state == original


def _retry_transient_reads() -> RetryPolicy:
    """Explicitly retry only classified transient read-only source failures."""
    return RetryPolicy(
        max_attempts=3,
        initial_interval=0.001,
        max_interval=0.01,
        backoff_factor=2.0,
        jitter=False,
        retry_on=TransientEvidenceCollectionError,
    )


def test_transient_collector_failure_retries_only_selected_source() -> None:
    attempts = {"logs": 0, "metrics": 0}

    async def logs(_incident: IncidentSnapshot) -> list[Evidence]:
        attempts["logs"] += 1
        if attempts["logs"] < 3:
            raise TransientEvidenceCollectionError("Transient observability read failure")
        return [_observation(1)]

    async def metrics(_incident: IncidentSnapshot) -> list[Evidence]:
        attempts["metrics"] += 1
        raise AssertionError("Metrics were not selected")

    graph = build_investigator_graph(
        collect_logs=logs,
        collect_metrics=metrics,
        investigation_planner=_planner("logs"),
        collector_retry_policy=_retry_transient_reads(),
    )
    result = asyncio.run(graph.ainvoke(_state()))

    assert attempts == {"logs": 3, "metrics": 0}
    assert result["workflow_phase"] == "analyzing"
    assert [item["evidence_id"] for item in result["evidence"]] == [str(UUID(int=1))]


def test_permanent_collector_failure_is_not_retried() -> None:
    attempts = 0

    async def permanent(_incident: IncidentSnapshot) -> list[Evidence]:
        nonlocal attempts
        attempts += 1
        raise ValueError("Permanent source configuration error")

    graph = build_investigator_graph(
        collect_logs=permanent,
        collect_metrics=_collector(),
        investigation_planner=_planner("logs"),
        collector_retry_policy=_retry_transient_reads(),
    )
    with pytest.raises(ValueError, match="Permanent source configuration error"):
        asyncio.run(graph.ainvoke(_state()))

    assert attempts == 1


def test_transient_collector_failure_propagates_after_bounded_attempts() -> None:
    attempts = 0

    async def unavailable(_incident: IncidentSnapshot) -> list[Evidence]:
        nonlocal attempts
        attempts += 1
        raise TransientEvidenceCollectionError("Observability still unavailable")

    graph = build_investigator_graph(
        collect_logs=unavailable,
        collect_metrics=_collector(),
        investigation_planner=_planner("logs"),
        collector_retry_policy=_retry_transient_reads(),
    )
    with pytest.raises(TransientEvidenceCollectionError, match="still unavailable"):
        asyncio.run(graph.ainvoke(_state()))

    assert attempts == 3


def test_wrong_incident_evidence_is_not_retried() -> None:
    attempts = 0

    async def foreign(_incident: IncidentSnapshot) -> list[Evidence]:
        nonlocal attempts
        attempts += 1
        return [_observation(1, incident_id=UUID(int=999))]

    graph = build_investigator_graph(
        collect_logs=foreign,
        collect_metrics=_collector(),
        investigation_planner=_planner("logs"),
        collector_retry_policy=_retry_transient_reads(),
    )
    with pytest.raises(EvidenceIncidentMismatchError, match="different incident"):
        asyncio.run(graph.ainvoke(_state()))

    assert attempts == 1


def test_planner_is_not_retried_even_when_raising_transient_collector_error() -> None:
    attempts = 0

    async def planner(_incident: IncidentSnapshot) -> InvestigationPlanSnapshot:
        nonlocal attempts
        attempts += 1
        raise TransientEvidenceCollectionError("Planner must not inherit collector retry")

    graph = build_investigator_graph(
        collect_logs=_collector(),
        collect_metrics=_collector(),
        investigation_planner=planner,
        collector_retry_policy=_retry_transient_reads(),
    )
    with pytest.raises(TransientEvidenceCollectionError, match="Planner must not"):
        asyncio.run(graph.ainvoke(_state()))

    assert attempts == 1
