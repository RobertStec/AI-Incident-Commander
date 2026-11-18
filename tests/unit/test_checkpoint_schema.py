"""Connection-free tests for explicitly requested checkpoint schema setup."""

import asyncio
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import cast

import pytest
from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver
from sqlalchemy.engine import URL

from ai_incident_commander.application import checkpoint_schema
from ai_incident_commander.infrastructure.database_config import DatabaseConfig


def _config() -> DatabaseConfig:
    return DatabaseConfig(
        url=URL.create(
            "postgresql+psycopg",
            username="checkpoint_admin",
            password="test-secret",
            host="localhost",
            database="incident_test",
        )
    )


class FakeSaver:
    def __init__(self, *, fail_setup: bool = False) -> None:
        self.setup_calls = 0
        self.fail_setup = fail_setup

    async def setup(self) -> None:
        self.setup_calls += 1
        if self.fail_setup:
            raise RuntimeError("Checkpoint migration failed")


def test_setup_requires_explicit_opt_in_before_opening_connection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entered = False

    @asynccontextmanager
    async def fake_lifespan(*, config: DatabaseConfig) -> AsyncGenerator[AsyncPostgresSaver]:
        nonlocal entered
        entered = True
        yield cast("AsyncPostgresSaver", FakeSaver())

    monkeypatch.setattr(checkpoint_schema, "postgres_checkpoint_lifespan", fake_lifespan)

    async def scenario() -> None:
        with pytest.raises(
            checkpoint_schema.CheckpointSchemaChangeNotConfirmedError,
            match="requires explicit",
        ):
            await checkpoint_schema.initialize_postgres_checkpoint_schema(config=_config())

    asyncio.run(scenario())
    assert entered is False


def test_explicit_setup_calls_migration_once_and_closes_connection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    saver = FakeSaver()
    entered = 0
    exited = 0
    observed_config: DatabaseConfig | None = None
    config = _config()

    @asynccontextmanager
    async def fake_lifespan(*, config: DatabaseConfig) -> AsyncGenerator[AsyncPostgresSaver]:
        nonlocal entered, exited, observed_config
        entered += 1
        observed_config = config
        try:
            yield cast("AsyncPostgresSaver", saver)
        finally:
            exited += 1

    monkeypatch.setattr(checkpoint_schema, "postgres_checkpoint_lifespan", fake_lifespan)

    async def scenario() -> None:
        await checkpoint_schema.initialize_postgres_checkpoint_schema(
            config=config, apply_schema_changes=True
        )

    asyncio.run(scenario())
    assert saver.setup_calls == 1
    assert entered == 1
    assert exited == 1
    assert observed_config is config


def test_setup_failure_propagates_and_closes_connection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    saver = FakeSaver(fail_setup=True)
    exited = False

    @asynccontextmanager
    async def fake_lifespan(*, config: DatabaseConfig) -> AsyncGenerator[AsyncPostgresSaver]:
        nonlocal exited
        try:
            yield cast("AsyncPostgresSaver", saver)
        finally:
            exited = True

    monkeypatch.setattr(checkpoint_schema, "postgres_checkpoint_lifespan", fake_lifespan)

    async def scenario() -> None:
        with pytest.raises(RuntimeError, match="Checkpoint migration failed"):
            await checkpoint_schema.initialize_postgres_checkpoint_schema(
                config=_config(), apply_schema_changes=True
            )

    asyncio.run(scenario())
    assert saver.setup_calls == 1
    assert exited is True
