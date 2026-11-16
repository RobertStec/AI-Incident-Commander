"""LangGraph incident workflow with an injected planner and parallel collectors.

Collectors return domain Evidence, and the state stores JSON-compatible snapshots.
No MCP, LLM, checkpointer, mutating actions, or automatic retries are used here.
"""

from collections.abc import Awaitable, Callable
from copy import deepcopy
from typing import Literal, TypedDict

from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledStateGraph

from ai_incident_commander.domain.evidence import Evidence
from ai_incident_commander.orchestration.incident_state import (
    EvidenceSnapshot,
    IncidentSnapshot,
    IncidentState,
    InvestigationPlanSnapshot,
    InvestigationSource,
    WorkflowPhase,
    create_investigation_plan,
    snapshot_evidence,
)

# Domain evidence stays outside the graph's serialized state. A future adapter
# can satisfy this port using a real observability source.
type EvidenceCollector = Callable[[IncidentSnapshot], Awaitable[list[Evidence]]]
type InvestigationPlanner = Callable[[IncidentSnapshot], Awaitable[InvestigationPlanSnapshot]]
type IncidentGraph = CompiledStateGraph[IncidentState, None, IncidentState, IncidentState]
type CollectorNode = Literal["collect_logs", "collect_metrics"]


async def baseline_investigation_planner(
    incident: IncidentSnapshot,
) -> InvestigationPlanSnapshot:
    """Start conservatively with both read-only sources, without invoking an LLM."""
    return create_investigation_plan(
        sources=["logs", "metrics"],
        rationale=f"Collect baseline logs and metrics for incident {incident['incident_id']}.",
    )


class EvidenceIncidentMismatchError(ValueError):
    """A collector returned evidence belonging to another incident."""


class IncidentStateUpdate(TypedDict, total=False):
    """Partial updates produced by nodes; concurrent evidence uses the reducer."""

    workflow_phase: WorkflowPhase
    investigation_plan: InvestigationPlanSnapshot
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
    investigation_planner: InvestigationPlanner = baseline_investigation_planner,
) -> IncidentGraph:
    """Compile plan-driven collectors and a deferred evidence aggregation node.

    The default planner selects both read-only sources. Selected collectors
    execute in parallel, and aggregation runs once after the active branches.
    This graph does not provide durable execution or authorized remediation.
    """

    def intake(state: IncidentState) -> IncidentStateUpdate:
        if state["workflow_phase"] != "intake":
            raise ValueError("The initial incident workflow phase must be intake.")
        if state["investigation_plan"] is not None:
            raise ValueError("The initial investigation plan must be unset.")
        return {"workflow_phase": "planning"}

    async def plan_investigation(state: IncidentState) -> IncidentStateUpdate:
        if state["workflow_phase"] != "planning":
            raise ValueError("Investigation must be in the planning phase.")
        proposal = await investigation_planner(deepcopy(state["incident"]))
        # A TypedDict annotation is not runtime validation. Never trust a
        # planner's output as an executable plan without checking it.
        plan = create_investigation_plan(
            sources=proposal["sources"],
            rationale=proposal["rationale"],
        )
        return {
            "investigation_plan": plan,
            "workflow_phase": "collecting_evidence",
        }

    def route_collectors(state: IncidentState) -> list[CollectorNode]:
        """Select only planned collectors; reject missing or malformed plans."""
        if state["workflow_phase"] != "collecting_evidence":
            raise ValueError("Routing requires the collecting_evidence phase.")
        plan = state["investigation_plan"]
        if plan is None:
            raise ValueError("Cannot route investigation without a plan.")
        validated_plan = create_investigation_plan(
            sources=plan["sources"],
            rationale=plan["rationale"],
        )
        destinations: dict[InvestigationSource, CollectorNode] = {
            "logs": "collect_logs",
            "metrics": "collect_metrics",
        }
        return [destinations[source] for source in validated_plan["sources"]]

    async def logs_node(state: IncidentState) -> IncidentStateUpdate:
        incident = state["incident"]
        observations = await collect_logs(deepcopy(incident))
        return {"evidence": _snapshots_for_incident(incident, observations)}

    async def metrics_node(state: IncidentState) -> IncidentStateUpdate:
        incident = state["incident"]
        observations = await collect_metrics(deepcopy(incident))
        return {"evidence": _snapshots_for_incident(incident, observations)}

    def aggregate_evidence(state: IncidentState) -> IncidentStateUpdate:
        # Deferred execution waits for all active collectors. Their evidence
        # updates are merged by IncidentState.evidence's reducer.
        return {"workflow_phase": "analyzing"}

    builder: StateGraph[IncidentState, None, IncidentState, IncidentState] = StateGraph(
        IncidentState
    )
    builder.add_node("intake", intake)
    builder.add_node("investigation_planner", plan_investigation)
    builder.add_node("collect_logs", logs_node)
    builder.add_node("collect_metrics", metrics_node)
    builder.add_node("aggregate_evidence", aggregate_evidence, defer=True)

    builder.add_edge(START, "intake")
    builder.add_edge("intake", "investigation_planner")
    builder.add_conditional_edges(
        "investigation_planner",
        route_collectors,
        ["collect_logs", "collect_metrics"],
    )
    # Separate edges + deferred aggregation work for one or both selected paths.
    # A list-form waiting edge would deadlock if a collector was not selected.
    builder.add_edge("collect_logs", "aggregate_evidence")
    builder.add_edge("collect_metrics", "aggregate_evidence")
    builder.add_edge("aggregate_evidence", END)
    return builder.compile()
