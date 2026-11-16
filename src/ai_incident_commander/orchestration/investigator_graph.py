"""Standalone Investigator subgraph for read-only incident diagnostics.

The subgraph accepts an InvestigatorState in the planning phase. When nested
in the main Incident Graph, the coordinator owns intake and downstream state.
No LLM, MCP transport, checkpointer, retries, or mutating actions are used.
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
    InvestigationPlanSnapshot,
    InvestigationSource,
    InvestigatorState,
    WorkflowPhase,
    create_investigation_plan,
    snapshot_evidence,
)

# Canonical read-only ports and validation errors for diagnostic workflows.
# The parent graph re-exports them to preserve its existing public API.
type EvidenceCollector = Callable[[IncidentSnapshot], Awaitable[list[Evidence]]]
type InvestigationPlanner = Callable[[IncidentSnapshot], Awaitable[InvestigationPlanSnapshot]]
type InvestigatorGraph = CompiledStateGraph[
    InvestigatorState, None, InvestigatorState, InvestigatorState
]
type CollectorNode = Literal["collect_logs", "collect_metrics"]


class EvidenceIncidentMismatchError(ValueError):
    """A collector returned evidence belonging to a different incident."""


class InvestigatorStateUpdate(TypedDict, total=False):
    """Partial updates; evidence is combined by InvestigatorState's reducer."""

    workflow_phase: WorkflowPhase
    investigation_plan: InvestigationPlanSnapshot
    evidence: list[EvidenceSnapshot]


async def baseline_investigation_planner(
    incident: IncidentSnapshot,
) -> InvestigationPlanSnapshot:
    """Select both currently supported read-only observation sources."""
    return create_investigation_plan(
        sources=["logs", "metrics"],
        rationale=f"Collect baseline logs and metrics for incident {incident['incident_id']}.",
    )


def _snapshots_for_incident(
    incident: IncidentSnapshot, items: list[Evidence]
) -> list[EvidenceSnapshot]:
    snapshots: list[EvidenceSnapshot] = []
    for item in items:
        if str(item.incident_id) != incident["incident_id"]:
            raise EvidenceIncidentMismatchError(
                "Collected evidence belongs to a different incident."
            )
        snapshots.append(snapshot_evidence(item))
    return snapshots


def build_investigator_graph(
    *,
    collect_logs: EvidenceCollector,
    collect_metrics: EvidenceCollector,
    investigation_planner: InvestigationPlanner = baseline_investigation_planner,
) -> InvestigatorGraph:
    """Compile planning -> selected collectors -> deferred aggregation.

    Input must be in `planning` with no pre-existing plan. The parent graph
    will be responsible for the intake transition when composed in 2.0.5.3.
    """

    async def plan_investigation(state: InvestigatorState) -> InvestigatorStateUpdate:
        if state["workflow_phase"] != "planning":
            raise ValueError("Investigation must be in the planning phase.")
        if state["investigation_plan"] is not None:
            raise ValueError("Investigation plan must be unset before planning.")
        proposal = await investigation_planner(deepcopy(state["incident"]))
        plan = create_investigation_plan(
            sources=proposal["sources"], rationale=proposal["rationale"]
        )
        return {
            "investigation_plan": plan,
            "workflow_phase": "collecting_evidence",
        }

    def route_collectors(state: InvestigatorState) -> list[CollectorNode]:
        if state["workflow_phase"] != "collecting_evidence":
            raise ValueError("Routing requires the collecting_evidence phase.")
        plan = state["investigation_plan"]
        if plan is None:
            raise ValueError("Cannot route investigation without a plan.")
        validated_plan = create_investigation_plan(
            sources=plan["sources"], rationale=plan["rationale"]
        )
        destinations: dict[InvestigationSource, CollectorNode] = {
            "logs": "collect_logs",
            "metrics": "collect_metrics",
        }
        return [destinations[source] for source in validated_plan["sources"]]

    async def logs_node(state: InvestigatorState) -> InvestigatorStateUpdate:
        incident = state["incident"]
        observations = await collect_logs(deepcopy(incident))
        return {"evidence": _snapshots_for_incident(incident, observations)}

    async def metrics_node(state: InvestigatorState) -> InvestigatorStateUpdate:
        incident = state["incident"]
        observations = await collect_metrics(deepcopy(incident))
        return {"evidence": _snapshots_for_incident(incident, observations)}

    def aggregate_evidence(state: InvestigatorState) -> InvestigatorStateUpdate:
        # The evidence reducer has already merged all active collector updates.
        return {"workflow_phase": "analyzing"}

    builder: StateGraph[InvestigatorState, None, InvestigatorState, InvestigatorState] = StateGraph(
        InvestigatorState
    )
    builder.add_node("investigation_planner", plan_investigation)
    builder.add_node("collect_logs", logs_node)
    builder.add_node("collect_metrics", metrics_node)
    builder.add_node("aggregate_evidence", aggregate_evidence, defer=True)

    builder.add_edge(START, "investigation_planner")
    builder.add_conditional_edges(
        "investigation_planner",
        route_collectors,
        ["collect_logs", "collect_metrics"],
    )
    # Separate edges allow a single selected collector; defer waits for both
    # when both are active. List-form waiting edges would require both always.
    builder.add_edge("collect_logs", "aggregate_evidence")
    builder.add_edge("collect_metrics", "aggregate_evidence")
    builder.add_edge("aggregate_evidence", END)
    return builder.compile()
