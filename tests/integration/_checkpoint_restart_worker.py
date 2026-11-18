"""Subprocess fixture for the PostgreSQL checkpoint process-restart integration test.

Execute only from the opt-in integration test, with a unique test-owned thread ID.
Never runs AsyncPostgresSaver.setup() or mutating MCP operations.
"""

import asyncio
import os
import sys
from datetime import UTC, datetime
from pathlib import Path
from uuid import NAMESPACE_URL, UUID, uuid5

from ai_incident_commander.application.checkpoint_bootstrap import (
    postgres_checkpoint_lifespan,
)
from ai_incident_commander.domain.evidence import Evidence, EvidenceType
from ai_incident_commander.domain.incident import Incident
from ai_incident_commander.infrastructure.database_config import DatabaseConfig
from ai_incident_commander.orchestration.incident_graph import build_incident_graph
from ai_incident_commander.orchestration.incident_state import (
    IncidentSnapshot,
    InvestigationPlanSnapshot,
    create_investigation_plan,
    initial_incident_state,
)

_OBSERVED_AT = datetime(2026, 11, 17, 12, 0, tzinfo=UTC)
_EXPECTED_FAILURE = "Simulated metrics failure before process restart"


def _append_event(trace_path: Path, phase: str, name: str) -> None:
    # Test-only cross-process instrumentation, not an application log.
    with trace_path.open("a", encoding="utf-8") as trace:
        trace.write(f"{phase}:{name}\n")


def _config() -> DatabaseConfig:
    if os.environ.get("RUN_DB_CHECKPOINT_TESTS") != "1":
        raise RuntimeError("Checkpoint worker requires explicit test opt-in.")
    config = DatabaseConfig.from_environment()
    if (
        config.url.host not in ("localhost", "127.0.0.1", "::1")
        or config.url.database != "incident_commander"
        or config.url.username != "incident_commander"
    ):
        raise RuntimeError("Checkpoint worker requires the local test database.")
    return config


async def _run(phase: str, thread_id: str, incident_id: UUID, trace_path: Path) -> None:
    if phase not in ("fail", "resume", "hang"):
        raise ValueError("Unknown checkpoint worker phase.")
    config = _config()
    run_config = {"configurable": {"thread_id": thread_id}}

    async def planner(_incident: IncidentSnapshot) -> InvestigationPlanSnapshot:
        _append_event(trace_path, phase, "planner")
        return create_investigation_plan(
            sources=["logs", "metrics"],
            rationale="Verify recovery after restarting the Python interpreter.",
        )

    logs_completed = asyncio.Event()

    async def logs(snapshot: IncidentSnapshot) -> list[Evidence]:
        _append_event(trace_path, phase, "logs")
        evidence_id = uuid5(NAMESPACE_URL, f"checkpoint-integration:{incident_id}")
        logs_completed.set()
        return [
            Evidence(
                evidence_id=evidence_id,
                incident_id=UUID(snapshot["incident_id"]),
                evidence_type=EvidenceType.LOG,
                source="checkpoint-restart-test",
                source_reference=f"log-{evidence_id}",
                summary="Read-only log observation",
                observed_at=_OBSERVED_AT,
                collected_at=_OBSERVED_AT,
                metadata={},
            )
        ]

    async def metrics(snapshot: IncidentSnapshot) -> list[Evidence]:
        _append_event(trace_path, phase, "metrics")
        if phase == "fail":
            await logs_completed.wait()
            await asyncio.sleep(0.02)
            raise RuntimeError(_EXPECTED_FAILURE)
        if phase == "hang":
            # Remain in a read-only node while the parent verifies that logs'
            # pending writes have been committed to PostgreSQL.
            await logs_completed.wait()
            await asyncio.Event().wait()
            raise AssertionError("Hanging collector unexpectedly resumed.")

        evidence_id = uuid5(NAMESPACE_URL, f"checkpoint-restart-metric:{incident_id}")
        return [
            Evidence(
                evidence_id=evidence_id,
                incident_id=UUID(snapshot["incident_id"]),
                evidence_type=EvidenceType.METRIC,
                source="checkpoint-restart-test",
                source_reference=f"metric-{evidence_id}",
                summary="Read-only metric observation after restart",
                observed_at=_OBSERVED_AT,
                collected_at=_OBSERVED_AT,
                metadata={},
            )
        ]

    async with postgres_checkpoint_lifespan(config=config) as saver:
        graph = build_incident_graph(
            collect_logs=logs,
            collect_metrics=metrics,
            investigation_planner=planner,
            checkpointer=saver,
        )
        if phase in ("fail", "hang"):
            incident = Incident(
                incident_id=incident_id,
                title="Process restart checkpoint test",
                description="Read-only failure then manual resume",
                created_at=_OBSERVED_AT,
                updated_at=_OBSERVED_AT,
            )
            if phase == "hang":
                # Expected to be killed by its own test parent, never to return.
                await graph.ainvoke(
                    initial_incident_state(incident),
                    config=run_config,
                    durability="sync",
                )
                raise AssertionError("Hanging graph unexpectedly completed.")

            try:
                await graph.ainvoke(
                    initial_incident_state(incident),
                    config=run_config,
                    durability="sync",
                )
            except RuntimeError as error:
                if str(error) != _EXPECTED_FAILURE:
                    raise
            else:
                raise AssertionError("Metrics collector did not fail as expected.")
            checkpoint = await graph.aget_state(run_config)
            assert checkpoint.next, "Failure must leave unfinished graph work."
        else:
            result = await graph.ainvoke(None, config=run_config, durability="sync")
            checkpoint = await graph.aget_state(run_config)
            assert result["workflow_phase"] == "analyzing"
            assert checkpoint.next == ()
            assert checkpoint.values["incident"]["incident_id"] == str(incident_id)
            assert len(result["evidence"]) == 2


def main() -> None:
    if len(sys.argv) != 5:
        raise SystemExit("Expected phase, thread_id, incident_id and trace_path.")
    phase, thread_id, incident_str, trace_str = sys.argv[1:]
    if not thread_id.startswith("checkpoint-integration-"):
        raise SystemExit("Refusing non-test checkpoint thread ID.")
    asyncio.run(_run(phase, thread_id, UUID(incident_str), Path(trace_str)))


if __name__ == "__main__":
    main()
