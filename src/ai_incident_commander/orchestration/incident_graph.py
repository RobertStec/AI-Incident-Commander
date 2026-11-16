"""First LangGraph incident workflow: two parallel, injected evidence collectors.

This graph demonstrates orchestration only. Collectors return validated domain
Evidence; the state stores JSON-compatible snapshots. No MCP, LLM, or side effects
are implemented here. This version has no checkpointer or automatic retries.
"""

from collections.abc import Awaitable, Callable
from copy import deepcopy
from typing import TypedDict

from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledStateGraph

from ai_incident_commander.domain.evidence import Evidence
from ai_incident_commander.orchestration.incident_state import (
    EvidenceSnapshot,
    IncidentSnapshot,
    IncidentState,
    WorkflowPhase,
    snapshot_evidence,
)

# Domain evidence stays outside the graph's serialized state. A future adapter
# can satisfy this port using a real observability source.
type EvidenceCollector = Callable[[IncidentSnapshot], Awaitable[list[Evidence]]]
type IncidentGraph = CompiledStateGraph[IncidentState, None, IncidentState, IncidentState]


class EvidenceIncidentMismatchError(ValueError):
    """A collector returned evidence belonging to another incident."""


class IncidentStateUpdate(TypedDict, total=False):
    """Partial updates produced by nodes; concurrent evidence uses the reducer."""

    workflow_phase: WorkflowPhase
    evidence: list[EvidenceSnapshot]


def _snapshots_for_incident(
    incident: IncidentSnapshot, items: list[Evidence]
) -> list[EvidenceSnapshot]:
    """Preserve the incident boundary before merging external observations."""
    snapshots: list[EvidenceSnapshot] = []
    for item in items:
        if str(item.incident_id) != incident["incident_id"]:
            raise EvidenceIncidentMismatchError(
                "Collected evidence belongs to a different incident."
            )
        snapshots.append(snapshot_evidence(item))
    return snapshots


def build_incident_graph(
    *,
    collect_logs: EvidenceCollector,
    collect_metrics: EvidenceCollector,
) -> IncidentGraph:
    """Compile a fan-out/fan-in graph using caller-supplied async collectors.

    Collectors must not perform mutating operations. The graph is a diagnostic
    prototype, not a durable or authorized remediation workflow.
    """

    def intake(state: IncidentState) -> IncidentStateUpdate:
        if state["workflow_phase"] != "intake":
            raise ValueError("The initial incident workflow phase must be intake.")
        return {"workflow_phase": "collecting_evidence"}

    async def logs_node(state: IncidentState) -> IncidentStateUpdate:
        incident = state["incident"]
        observations = await collect_logs(deepcopy(incident))
        return {"evidence": _snapshots_for_incident(incident, observations)}

    async def metrics_node(state: IncidentState) -> IncidentStateUpdate:
        incident = state["incident"]
        observations = await collect_metrics(deepcopy(incident))
        return {"evidence": _snapshots_for_incident(incident, observations)}

    def aggregate_evidence(state: IncidentState) -> IncidentStateUpdate:
        # This node starts after BOTH collectors. Their updates have already
        # been merged by IncidentState.evidence's merge_evidence reducer.
        return {"workflow_phase": "analyzing"}

    builder: StateGraph[IncidentState, None, IncidentState, IncidentState] = StateGraph(
        IncidentState
    )
    builder.add_node("intake", intake)
    builder.add_node("collect_logs", logs_node)
    builder.add_node("collect_metrics", metrics_node)
    builder.add_node("aggregate_evidence", aggregate_evidence)

    builder.add_edge(START, "intake")
    builder.add_edge("intake", "collect_logs")
    builder.add_edge("intake", "collect_metrics")
    builder.add_edge(["collect_logs", "collect_metrics"], "aggregate_evidence")
    builder.add_edge("aggregate_evidence", END)
    return builder.compile()
