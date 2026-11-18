"""Opt-in PostgreSQL integration tests for the nested incident graph checkpointer.

Requires a pre-provisioned local langgraph_checkpoint schema. Tests never run
AsyncPostgresSaver.setup() and only delete checkpoints owned by their thread IDs.
"""

import asyncio
import os
from datetime import UTC, datetime
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
