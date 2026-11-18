"""Main LangGraph coordinator, composed with the read-only Investigator subgraph.

The coordinator owns incident intake. Planning, conditional fan-out, collection,
and evidence aggregation belong to the narrower Investigator subgraph.
No LLM, MCP transport, mutating actions, or retries are used.
Checkpointing is optional and owned by the caller.
"""

from typing import Any, TypedDict

from langgraph.checkpoint.base import BaseCheckpointSaver
from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledStateGraph

from ai_incident_commander.orchestration.incident_state import (
    EvidenceSnapshot,
    IncidentState,
    InvestigationPlanSnapshot,
    WorkflowPhase,
)
from ai_incident_commander.orchestration.investigator_graph import (
    CollectorNode as CollectorNode,
)
from ai_incident_commander.orchestration.investigator_graph import (
    EvidenceCollector,
    InvestigationPlanner,
    baseline_investigation_planner,
    build_investigator_graph,
)
from ai_incident_commander.orchestration.investigator_graph import (
    EvidenceIncidentMismatchError as EvidenceIncidentMismatchError,
)

type IncidentGraph = CompiledStateGraph[IncidentState, None, IncidentState, IncidentState]


class IncidentStateUpdate(TypedDict, total=False):
    """Coordinator node updates; retain the existing public update contract."""

    workflow_phase: WorkflowPhase
    investigation_plan: InvestigationPlanSnapshot
    evidence: list[EvidenceSnapshot]


def build_incident_graph(
    *,
    collect_logs: EvidenceCollector,
    collect_metrics: EvidenceCollector,
    investigation_planner: InvestigationPlanner = baseline_investigation_planner,
    checkpointer: BaseCheckpointSaver[Any] | None = None,
) -> IncidentGraph:
    """Compile intake -> Investigator subgraph, preserving the public builder API.

    Both state schemas share diagnostic channels. In particular, their evidence
    reducer deduplicates the final subgraph snapshot when the parent receives it.

    An optional, caller-owned checkpointer persists coordinator steps. The
    Investigator subgraph inherits it; no saver is constructed in this builder.
    Invocations using a saver must supply a unique run-specific thread_id.
    """

    def intake(state: IncidentState) -> IncidentStateUpdate:
        if state["workflow_phase"] != "intake":
            raise ValueError("The initial incident workflow phase must be intake.")
        if state["investigation_plan"] is not None:
            raise ValueError("The initial investigation plan must be unset.")
        return {"workflow_phase": "planning"}

    investigator = build_investigator_graph(
        collect_logs=collect_logs,
        collect_metrics=collect_metrics,
        investigation_planner=investigation_planner,
    )

    builder: StateGraph[IncidentState, None, IncidentState, IncidentState] = StateGraph(
        IncidentState
    )
    builder.add_node("intake", intake)
    # Shared state keys are passed automatically. Only the subgraph owns the
    # planner, collectors and aggregation; hypotheses stay in the parent.
    builder.add_node("investigator", investigator)

    builder.add_edge(START, "intake")
    builder.add_edge("intake", "investigator")
    builder.add_edge("investigator", END)
    return builder.compile(checkpointer=checkpointer)
