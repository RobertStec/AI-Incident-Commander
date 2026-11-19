"""Main LangGraph coordinator, composed with the read-only Investigator subgraph.

The coordinator owns incident intake. Planning, conditional fan-out, collection,
and evidence aggregation belong to the narrower Investigator subgraph.
No LLM, MCP transport, mutating actions, or retries are used.
Checkpointing is optional and owned by the caller.
"""

from typing import Any, TypedDict, cast

from langgraph.checkpoint.base import BaseCheckpointSaver
from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledStateGraph
from langgraph.types import interrupt
from pydantic import BaseModel, ConfigDict, model_validator

from ai_incident_commander.orchestration.incident_state import (
    AnalysisReviewOutcome,
    AnalysisReviewSnapshot,
    EvidenceSnapshot,
    IncidentState,
    InvestigationPlanSnapshot,
    WorkflowPhase,
    create_analysis_review,
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


class AnalysisReviewInput(BaseModel):
    """Strict interrupt response; validation runs before LangGraph consumes a reply.

    LangGraph can retry a schema-invalid response on the same paused task.
    The domain snapshot remains separate and has no authorization semantics.
    """

    model_config = ConfigDict(extra="forbid", strict=True)

    outcome: AnalysisReviewOutcome
    note: str | None = None

    @model_validator(mode="before")
    @classmethod
    def validate_review(cls, value: Any) -> Any:
        if not isinstance(value, dict):
            raise ValueError("Analysis review response must be an object.")
        if "outcome" not in value or not set(value) <= {"outcome", "note"}:
            raise ValueError("Analysis review response contains invalid fields.")
        outcome = value["outcome"]
        note = value.get("note")
        if not isinstance(outcome, str):
            raise ValueError("Analysis review outcome must be text.")
        if note is not None and not isinstance(note, str):
            raise ValueError("Analysis review note must be text or None.")
        create_analysis_review(outcome=cast("AnalysisReviewOutcome", outcome), note=note)
        return value


class IncidentStateUpdate(TypedDict, total=False):
    """Coordinator node updates; retain the existing public update contract."""

    workflow_phase: WorkflowPhase
    investigation_plan: InvestigationPlanSnapshot
    evidence: list[EvidenceSnapshot]
    analysis_review: AnalysisReviewSnapshot


def build_incident_graph(
    *,
    collect_logs: EvidenceCollector,
    collect_metrics: EvidenceCollector,
    investigation_planner: InvestigationPlanner = baseline_investigation_planner,
    checkpointer: BaseCheckpointSaver[Any] | None = None,
    enable_analysis_review: bool = False,
) -> IncidentGraph:
    """Compile intake -> Investigator subgraph, preserving the public builder API.

    Both state schemas share diagnostic channels. In particular, their evidence
    reducer deduplicates the final subgraph snapshot when the parent receives it.

    An optional, caller-owned checkpointer persists coordinator steps. The
    Investigator subgraph inherits it; no saver is constructed in this builder.
    Invocations using a saver must supply a unique run-specific thread_id.
    HITL is opt-in, requires a checkpointer, and must retain the same topology
    when the interrupted thread is later resumed. It is not remediation approval.
    """
    if enable_analysis_review and checkpointer is None:
        raise ValueError("Analysis review requires a checkpointer.")

    def intake(state: IncidentState) -> IncidentStateUpdate:
        if state["workflow_phase"] != "intake":
            raise ValueError("The initial incident workflow phase must be intake.")
        if state["investigation_plan"] is not None:
            raise ValueError("The initial investigation plan must be unset.")
        return {"workflow_phase": "planning"}

    def analysis_review(state: IncidentState) -> IncidentStateUpdate:
        """Collect untrusted diagnostic feedback; never authorize remediation.

        This node is read-only before interrupt() because it runs from the
        beginning again on resume. The checkpoint retains the prior investigation.
        """
        answer: AnalysisReviewInput = interrupt(
            {
                "kind": "analysis_review",
                "incident_id": state["incident"]["incident_id"],
                "evidence_count": len(state["evidence"]),
                "allowed_outcomes": ["acknowledged", "needs_follow_up"],
            },
            response_schema=AnalysisReviewInput,
        )
        return {"analysis_review": create_analysis_review(outcome=answer.outcome, note=answer.note)}

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
    if enable_analysis_review:
        builder.add_node("analysis_review", analysis_review)
        builder.add_edge("investigator", "analysis_review")
        builder.add_edge("analysis_review", END)
    else:
        builder.add_edge("investigator", END)
    return builder.compile(checkpointer=checkpointer)
