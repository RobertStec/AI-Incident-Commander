"""Coordinator tests for the nested Investigator subgraph workflow."""

import asyncio
import json
from copy import deepcopy
from datetime import UTC, datetime
from typing import cast
from uuid import UUID, uuid4

import pytest
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.graph import END, START
from langgraph.types import Command, RetryPolicy

from ai_incident_commander.domain.evidence import Evidence, EvidenceType
from ai_incident_commander.domain.hypothesis import Hypothesis
from ai_incident_commander.domain.incident import Incident
from ai_incident_commander.orchestration.incident_graph import (
    EvidenceCollector,
    EvidenceIncidentMismatchError,
    InvestigationPlanner,
    TransientEvidenceCollectionError,
    build_incident_graph,
)
from ai_incident_commander.orchestration.incident_state import (
    EvidenceSnapshotConflictError,
    IncidentSnapshot,
    IncidentState,
    InvestigationPlanSnapshot,
    InvestigationSource,
    initial_incident_state,
    snapshot_evidence,
    snapshot_hypothesis,
)

_INCIDENT_ID = UUID(int=100)
_OBSERVED_AT = datetime(2026, 11, 16, 9, 0, tzinfo=UTC)


def _state() -> IncidentState:
    incident = Incident(
        incident_id=_INCIDENT_ID,
        title="Payments API errors",
        description="HTTP 500 rate increased after deployment",
        created_at=_OBSERVED_AT,
        updated_at=_OBSERVED_AT,
    )
    return initial_incident_state(incident)


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


def _run(
    *,
    logs: EvidenceCollector,
    metrics: EvidenceCollector,
    state: IncidentState | None = None,
    planner: InvestigationPlanner | None = None,
) -> IncidentState:
    if planner is None:
        graph = build_incident_graph(collect_logs=logs, collect_metrics=metrics)
    else:
        graph = build_incident_graph(
            collect_logs=logs,
            collect_metrics=metrics,
            investigation_planner=planner,
        )
    return asyncio.run(graph.ainvoke(_state() if state is None else state))


def test_graph_collects_both_sources_and_transitions_to_analysis() -> None:
    logs = _observation(1)
    metrics = _observation(2, evidence_type=EvidenceType.METRIC)

    result = _run(logs=_collector(logs), metrics=_collector(metrics))

    assert result["workflow_phase"] == "analyzing"
    assert [item["evidence_id"] for item in result["evidence"]] == [
        str(logs.evidence_id),
        str(metrics.evidence_id),
    ]
    assert {item["evidence_type"] for item in result["evidence"]} == {"log", "metric"}
    assert result["hypotheses"] == []
    assert result["investigation_plan"] == {
        "sources": ["logs", "metrics"],
        "rationale": f"Collect baseline logs and metrics for incident {_INCIDENT_ID}.",
    }
    assert result["incident"]["status"] == "reported"


def test_parallel_nodes_wait_for_each_other_without_deadlock() -> None:
    async def scenario() -> IncidentState:
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

        graph = build_incident_graph(collect_logs=logs, collect_metrics=metrics)
        return await asyncio.wait_for(graph.ainvoke(_state()), timeout=5)

    result = asyncio.run(scenario())
    assert result["workflow_phase"] == "analyzing"
    assert len(result["evidence"]) == 2


def test_graph_deduplicates_replayed_identical_evidence() -> None:
    observation = _observation(1)

    result = _run(logs=_collector(observation), metrics=_collector(observation))

    assert len(result["evidence"]) == 1
    assert result["evidence"][0]["evidence_id"] == str(observation.evidence_id)


def test_graph_detects_conflicting_evidence_with_same_id() -> None:
    first = _observation(1)
    changed = _observation(1, summary="Different observation with the same ID")

    with pytest.raises(EvidenceSnapshotConflictError, match="Conflicting evidence snapshots"):
        _run(logs=_collector(first), metrics=_collector(changed))


def test_graph_rejects_cross_incident_observation() -> None:
    foreign = _observation(1, incident_id=UUID(int=999))

    with pytest.raises(EvidenceIncidentMismatchError, match="different incident"):
        _run(logs=_collector(foreign), metrics=_collector())


def test_graph_propagates_collector_failure_without_automatic_retry() -> None:
    attempts = 0

    async def failing(_incident: IncidentSnapshot) -> list[Evidence]:
        nonlocal attempts
        attempts += 1
        raise RuntimeError("Observability unavailable")

    with pytest.raises(RuntimeError, match="Observability unavailable"):
        _run(logs=failing, metrics=_collector())

    assert attempts == 1


def test_graph_allows_empty_collector_results_without_fabricating_evidence() -> None:
    result = _run(logs=_collector(), metrics=_collector())
    assert result["evidence"] == []
    assert result["workflow_phase"] == "analyzing"


def test_graph_does_not_mutate_the_input_state() -> None:
    state = _state()
    original = deepcopy(state)

    _run(logs=_collector(_observation(1)), metrics=_collector(), state=state)

    assert state == original


def test_collectors_cannot_modify_input_incident_snapshot() -> None:
    state = _state()
    original_title = state["incident"]["title"]

    async def mutating_collector(incident: IncidentSnapshot) -> list[Evidence]:
        incident["title"] = "Overwritten by collector"
        incident["affected_services"].append("unapproved-service")
        return [_observation(1)]

    result = _run(logs=mutating_collector, metrics=_collector(), state=state)

    assert result["incident"]["title"] == original_title
    assert state["incident"]["title"] == original_title
    assert state["incident"]["affected_services"] == []


def test_graph_output_is_json_serializable() -> None:
    result = _run(logs=_collector(_observation(1)), metrics=_collector())
    assert json.loads(json.dumps(result, allow_nan=False)) == result


def test_graph_rejects_non_intake_state() -> None:
    state = _state()
    state["workflow_phase"] = "analyzing"

    with pytest.raises(ValueError, match="must be intake"):
        _run(logs=_collector(), metrics=_collector(), state=state)


def test_identical_new_invocations_have_stable_evidence_contents() -> None:
    logs = _collector(_observation(1))
    metrics = _collector(_observation(2, evidence_type=EvidenceType.METRIC))
    state = _state()

    first = _run(logs=logs, metrics=metrics, state=deepcopy(state))
    second = _run(logs=logs, metrics=metrics, state=deepcopy(state))

    assert first == second


def test_injected_planner_routes_only_to_selected_logs_collector() -> None:
    calls: list[str] = []

    async def planner(_incident: IncidentSnapshot) -> InvestigationPlanSnapshot:
        calls.append("planner")
        return InvestigationPlanSnapshot(
            sources=["logs"], rationale="Inspect request failures first."
        )

    async def logs(_incident: IncidentSnapshot) -> list[Evidence]:
        calls.append("logs")
        return []

    async def metrics(_incident: IncidentSnapshot) -> list[Evidence]:
        calls.append("metrics")
        return []

    result = _run(logs=logs, metrics=metrics, planner=planner)

    assert calls[0] == "planner"
    assert calls == ["planner", "logs"]
    assert result["investigation_plan"] == {
        "sources": ["logs"],
        "rationale": "Inspect request failures first.",
    }
    assert result["workflow_phase"] == "analyzing"


def test_injected_planner_cannot_mutate_incident_snapshot() -> None:
    state = _state()
    original = deepcopy(state)

    async def planner(incident: IncidentSnapshot) -> InvestigationPlanSnapshot:
        incident["title"] = "Untrusted replacement"
        incident["affected_services"].append("foreign-service")
        return InvestigationPlanSnapshot(
            sources=["metrics"], rationale="Investigate latency first."
        )

    result = _run(logs=_collector(), metrics=_collector(), state=state, planner=planner)

    assert result["incident"] == original["incident"]
    assert state == original


def test_graph_revalidates_injected_planner_output_before_collection() -> None:
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


def test_planner_failure_is_propagated_once_before_collection() -> None:
    attempts = 0
    calls: list[str] = []

    async def planner(_incident: IncidentSnapshot) -> InvestigationPlanSnapshot:
        nonlocal attempts
        attempts += 1
        raise RuntimeError("Planner unavailable")

    async def collector(_incident: IncidentSnapshot) -> list[Evidence]:
        calls.append("collector")
        return []

    with pytest.raises(RuntimeError, match="Planner unavailable"):
        _run(logs=collector, metrics=collector, planner=planner)

    assert attempts == 1
    assert calls == []


def test_graph_copies_planner_sources_into_state() -> None:
    sources: list[InvestigationSource] = ["metrics"]

    async def planner(_incident: IncidentSnapshot) -> InvestigationPlanSnapshot:
        return InvestigationPlanSnapshot(sources=sources, rationale="Check latency.")

    result = _run(logs=_collector(), metrics=_collector(), planner=planner)
    sources.append("logs")

    assert result["investigation_plan"] == {
        "sources": ["metrics"],
        "rationale": "Check latency.",
    }


def test_graph_rejects_prepopulated_plan_in_initial_state() -> None:
    state = _state()
    state["investigation_plan"] = InvestigationPlanSnapshot(
        sources=["logs"], rationale="Injected in caller state."
    )

    with pytest.raises(ValueError, match="plan must be unset"):
        _run(logs=_collector(), metrics=_collector(), state=state)


def test_metrics_only_plan_skips_logs_and_collects_metrics_evidence() -> None:
    calls: list[str] = []
    metric = _observation(3, evidence_type=EvidenceType.METRIC)

    async def planner(_incident: IncidentSnapshot) -> InvestigationPlanSnapshot:
        return InvestigationPlanSnapshot(sources=["metrics"], rationale="Inspect latency.")

    async def logs(_incident: IncidentSnapshot) -> list[Evidence]:
        calls.append("logs")
        raise AssertionError("Logs collector was not selected.")

    async def metrics(_incident: IncidentSnapshot) -> list[Evidence]:
        calls.append("metrics")
        return [metric]

    result = _run(logs=logs, metrics=metrics, planner=planner)

    assert calls == ["metrics"]
    assert result["workflow_phase"] == "analyzing"
    assert [item["evidence_id"] for item in result["evidence"]] == [str(metric.evidence_id)]


@pytest.mark.parametrize(
    "sources",
    [
        ["logs"],
        ["metrics"],
        ["metrics", "logs"],
    ],
)
def test_deferred_aggregation_runs_once_after_exactly_the_selected_collectors(
    sources: list[InvestigationSource],
) -> None:
    """Inspect actual node updates, not just the final workflow_phase."""

    async def planner(_incident: IncidentSnapshot) -> InvestigationPlanSnapshot:
        return InvestigationPlanSnapshot(sources=list(sources), rationale="Collect evidence.")

    async def scenario() -> list[str]:
        graph = build_incident_graph(
            collect_logs=_collector(_observation(1)),
            collect_metrics=_collector(_observation(2, evidence_type=EvidenceType.METRIC)),
            investigation_planner=planner,
        )
        executed: list[str] = []
        async for namespace, update in graph.astream(
            _state(), stream_mode="updates", subgraphs=True
        ):
            if namespace:
                # Only investigator-internal nodes; parent emits a separate
                # update named "investigator" after its child completes.
                executed.extend(update.keys())
        return executed

    executed = asyncio.run(scenario())

    assert executed.count("investigation_planner") == 1
    assert executed.count("aggregate_evidence") == 1
    assert executed[-1] == "aggregate_evidence"
    assert executed.count("collect_logs") == (1 if "logs" in sources else 0)
    assert executed.count("collect_metrics") == (1 if "metrics" in sources else 0)


def test_two_collectors_produce_stable_evidence_regardless_of_plan_order() -> None:
    async def planner(_incident: IncidentSnapshot) -> InvestigationPlanSnapshot:
        return InvestigationPlanSnapshot(
            sources=["metrics", "logs"],
            rationale="Check latency and HTTP failures.",
        )

    logs = _observation(2)
    metrics = _observation(1, evidence_type=EvidenceType.METRIC)
    result = _run(logs=_collector(logs), metrics=_collector(metrics), planner=planner)

    assert result["workflow_phase"] == "analyzing"
    assert [item["evidence_id"] for item in result["evidence"]] == [
        str(metrics.evidence_id),
        str(logs.evidence_id),
    ]
    assert result["investigation_plan"] is not None
    assert result["investigation_plan"]["sources"] == ["metrics", "logs"]


def test_coordinator_contains_a_compiled_investigator_node() -> None:
    graph = build_incident_graph(collect_logs=_collector(), collect_metrics=_collector())

    assert set(graph.get_graph().nodes) == {START, "intake", "investigator", END}
    assert "collect_logs" not in graph.get_graph().nodes
    assert "investigation_planner" not in graph.get_graph().nodes


def test_parent_preserves_hypotheses_while_investigator_updates_evidence() -> None:
    state = _state()
    hypothesis = snapshot_hypothesis(
        Hypothesis(
            hypothesis_id=UUID(int=40),
            incident_id=_INCIDENT_ID,
            statement="A deployment regression may explain the errors",
            reasoning="Errors followed the latest deployment",
            created_at=_OBSERVED_AT,
            updated_at=_OBSERVED_AT,
        )
    )
    state["hypotheses"] = [hypothesis]

    result = _run(logs=_collector(_observation(1)), metrics=_collector(), state=state)

    assert result["hypotheses"] == [hypothesis]
    assert state["hypotheses"] == [hypothesis]
    assert len(result["evidence"]) == 1


def test_parent_unions_existing_and_new_evidence_across_subgraph_boundary() -> None:
    state = _state()
    original_evidence = snapshot_evidence(_observation(10))
    state["evidence"] = [original_evidence]
    untouched = deepcopy(state)

    result = _run(
        logs=_collector(_observation(1)),
        metrics=_collector(_observation(2, evidence_type=EvidenceType.METRIC)),
        state=state,
    )

    assert [item["evidence_id"] for item in result["evidence"]] == [
        str(UUID(int=1)),
        str(UUID(int=2)),
        str(UUID(int=10)),
    ]
    assert state == untouched


def test_parent_deduplicates_preexisting_evidence_replayed_by_subgraph() -> None:
    state = _state()
    repeated = _observation(1)
    state["evidence"] = [snapshot_evidence(repeated)]

    result = _run(logs=_collector(repeated), metrics=_collector(), state=state)

    assert result["evidence"] == [snapshot_evidence(repeated)]


def test_parent_detects_conflict_with_evidence_already_in_state() -> None:
    state = _state()
    state["evidence"] = [snapshot_evidence(_observation(1))]

    with pytest.raises(EvidenceSnapshotConflictError, match="Conflicting evidence"):
        _run(
            logs=_collector(_observation(1, summary="Contradictory observation")),
            metrics=_collector(),
            state=state,
        )


def test_parent_retains_investigator_error_type_identity() -> None:
    from ai_incident_commander.orchestration.investigator_graph import (
        EvidenceIncidentMismatchError as SubgraphEvidenceIncidentMismatchError,
    )

    assert EvidenceIncidentMismatchError is SubgraphEvidenceIncidentMismatchError


def test_parent_stream_emits_one_subgraph_completion_after_aggregation() -> None:
    async def scenario() -> tuple[list[str], list[str]]:
        graph = build_incident_graph(
            collect_logs=_collector(_observation(1)),
            collect_metrics=_collector(_observation(2, evidence_type=EvidenceType.METRIC)),
        )
        parent_events: list[str] = []
        child_events: list[str] = []
        async for namespace, update in graph.astream(
            _state(), stream_mode="updates", subgraphs=True
        ):
            if namespace:
                child_events.extend(update.keys())
            else:
                parent_events.extend(update.keys())
        return parent_events, child_events

    parent, child = asyncio.run(scenario())

    assert parent == ["intake", "investigator"]
    assert child.count("investigation_planner") == 1
    assert child.count("collect_logs") == 1
    assert child.count("collect_metrics") == 1
    assert child.count("aggregate_evidence") == 1
    assert child[-1] == "aggregate_evidence"


# Phase 2.0.7.2: opt-in human review is diagnostic feedback, not authorization.


def test_analysis_review_requires_checkpointer_when_enabled() -> None:
    with pytest.raises(ValueError, match="requires a checkpointer"):
        build_incident_graph(
            collect_logs=_collector(),
            collect_metrics=_collector(),
            enable_analysis_review=True,
        )


def test_analysis_review_adds_only_one_optional_parent_node() -> None:
    graph = build_incident_graph(
        collect_logs=_collector(),
        collect_metrics=_collector(),
        enable_analysis_review=True,
        checkpointer=InMemorySaver(),
    )
    assert set(graph.get_graph().nodes) == {START, "intake", "investigator", "analysis_review", END}
    assert "collect_logs" not in graph.get_graph().nodes


@pytest.mark.parametrize(
    ("reply", "expected"),
    [
        ({"outcome": "acknowledged"}, {"outcome": "acknowledged", "note": None}),
        (
            {"outcome": "needs_follow_up", "note": "  Check recent deployments.  "},
            {"outcome": "needs_follow_up", "note": "Check recent deployments."},
        ),
    ],
)
def test_analysis_review_interrupts_then_resumes_without_recollecting_evidence(
    reply: dict[str, str], expected: dict[str, str | None]
) -> None:
    async def scenario() -> None:
        calls = {"logs": 0, "metrics": 0}

        async def logs(_incident: IncidentSnapshot) -> list[Evidence]:
            calls["logs"] += 1
            return [_observation(1)]

        async def metrics(_incident: IncidentSnapshot) -> list[Evidence]:
            calls["metrics"] += 1
            return [_observation(2, evidence_type=EvidenceType.METRIC)]

        saver = InMemorySaver()
        config = {"configurable": {"thread_id": f"analysis-review-{uuid4()}"}}
        graph = build_incident_graph(
            collect_logs=logs,
            collect_metrics=metrics,
            enable_analysis_review=True,
            checkpointer=saver,
        )
        interrupted = await graph.ainvoke(_state(), config=config)
        assert "__interrupt__" in interrupted
        assert len(interrupted["__interrupt__"]) == 1
        request = interrupted["__interrupt__"][0].value
        assert request == {
            "kind": "analysis_review",
            "incident_id": str(_INCIDENT_ID),
            "evidence_count": 2,
            "allowed_outcomes": ["acknowledged", "needs_follow_up"],
        }
        assert json.loads(json.dumps(request, allow_nan=False)) == request
        paused = await graph.aget_state(config)
        assert paused.next == ("analysis_review",)
        assert paused.values.get("analysis_review") is None
        assert paused.values["workflow_phase"] == "analyzing"
        assert calls == {"logs": 1, "metrics": 1}

        # Recompile with the same topology and saver to represent a new request.
        resumed_graph = build_incident_graph(
            collect_logs=logs,
            collect_metrics=metrics,
            enable_analysis_review=True,
            checkpointer=saver,
        )
        completed = await resumed_graph.ainvoke(Command(resume=reply), config=config)
        final = await resumed_graph.aget_state(config)
        assert final.next == ()
        assert completed["analysis_review"] == expected
        assert final.values["analysis_review"] == expected
        assert completed["workflow_phase"] == "analyzing"
        assert calls == {"logs": 1, "metrics": 1}

    asyncio.run(scenario())


@pytest.mark.parametrize(
    ("reply", "message"),
    [
        ("acknowledged", "must be an object"),
        ({"approved": True}, "invalid fields"),
        ({"outcome": "acknowledged", "approved": True}, "invalid fields"),
        ({"outcome": "approved"}, "Unsupported analysis review outcome"),
        ({"outcome": "needs_follow_up"}, "requires a note"),
    ],
)
def test_analysis_review_rejects_untrusted_resume_without_persisting_decision(
    reply: object, message: str
) -> None:
    async def scenario() -> None:
        config = {"configurable": {"thread_id": f"analysis-review-invalid-{uuid4()}"}}
        graph = build_incident_graph(
            collect_logs=_collector(),
            collect_metrics=_collector(),
            checkpointer=InMemorySaver(),
            enable_analysis_review=True,
        )
        await graph.ainvoke(_state(), config=config)
        with pytest.raises(ValueError, match=message):
            await graph.ainvoke(Command(resume=reply), config=config)
        snapshot = await graph.aget_state(config)
        assert snapshot.values.get("analysis_review") is None
        assert snapshot.next == ("analysis_review",)

    asyncio.run(scenario())


def test_coordinator_propagates_retry_policy_to_investigator_collectors() -> None:
    """Production parent must configure the nested read-only source nodes."""
    calls = {"planner": 0, "logs": 0, "metrics": 0}

    async def planner(_incident: IncidentSnapshot) -> InvestigationPlanSnapshot:
        calls["planner"] += 1
        return InvestigationPlanSnapshot(
            sources=["logs", "metrics"], rationale="Investigate both sources."
        )

    async def logs(_incident: IncidentSnapshot) -> list[Evidence]:
        calls["logs"] += 1
        if calls["logs"] == 1:
            raise TransientEvidenceCollectionError("Temporary read timeout")
        return [_observation(1)]

    async def metrics(_incident: IncidentSnapshot) -> list[Evidence]:
        calls["metrics"] += 1
        return [_observation(2, evidence_type=EvidenceType.METRIC)]

    graph = build_incident_graph(
        collect_logs=logs,
        collect_metrics=metrics,
        investigation_planner=planner,
        collector_retry_policy=RetryPolicy(
            max_attempts=3,
            initial_interval=0.001,
            max_interval=0.01,
            backoff_factor=2.0,
            jitter=False,
            retry_on=TransientEvidenceCollectionError,
        ),
    )
    result = asyncio.run(graph.ainvoke(_state()))

    assert calls == {"planner": 1, "logs": 2, "metrics": 1}
    assert result["workflow_phase"] == "analyzing"
    assert len(result["evidence"]) == 2
