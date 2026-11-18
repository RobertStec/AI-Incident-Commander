"""Connection-free lifecycle and security tests for the Postgres checkpointer root."""

import asyncio
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import cast

import pytest
from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver
from langgraph.checkpoint.serde.jsonplus import JsonPlusSerializer
from sqlalchemy.engine import URL

from ai_incident_commander.application import checkpoint_bootstrap
from ai_incident_commander.infrastructure.database_config import (
    DatabaseConfig,
    DatabaseConfigurationError,
)


def _config() -> DatabaseConfig:
    return DatabaseConfig(
        url=URL.create(
            "postgresql+psycopg",
            username="checkpoint_user",
            password="very-secret@word",
            host="localhost",
            port=5432,
            database="incident_db",
        )
    )


class FakeSaver:
    def __init__(self) -> None:
        self.setup_calls = 0

    async def setup(self) -> None:
        self.setup_calls += 1


def test_lifespan_opens_and_closes_without_implicit_schema_setup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    saver = FakeSaver()
    entered = 0
    exited = 0
    supplied_conninfo: str | None = None
    supplied_serializer: JsonPlusSerializer | None = None

    @asynccontextmanager
    async def fake_from_conn_string(
        conn_string: str, *, serde: JsonPlusSerializer
    ) -> AsyncGenerator[AsyncPostgresSaver]:
        nonlocal entered, exited, supplied_conninfo, supplied_serializer
        supplied_conninfo = conn_string
        supplied_serializer = serde
        entered += 1
        try:
            yield cast("AsyncPostgresSaver", saver)
        finally:
            exited += 1

    monkeypatch.setattr(AsyncPostgresSaver, "from_conn_string", fake_from_conn_string)

    async def scenario() -> None:
        async with checkpoint_bootstrap.postgres_checkpoint_lifespan(config=_config()) as result:
            assert result is saver
            assert entered == 1
            assert exited == 0
            assert saver.setup_calls == 0

    asyncio.run(scenario())

    assert entered == 1
    assert exited == 1
    assert saver.setup_calls == 0
    assert supplied_conninfo is not None
    assert supplied_conninfo.startswith("postgresql://checkpoint_user:")
    assert "very-secret%40word" in supplied_conninfo
    assert supplied_serializer is not None
    assert supplied_serializer.pickle_fallback is False
    with pytest.raises(NotImplementedError, match="pickle"):
        supplied_serializer.loads_typed(("pickle", b"untrusted bytes"))


def test_lifespan_loads_database_config_from_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: list[str] = []
    monkeypatch.setenv("DATABASE_URL", _config().url.render_as_string(hide_password=False))

    @asynccontextmanager
    async def fake_from_conn_string(
        conn_string: str, *, serde: JsonPlusSerializer
    ) -> AsyncGenerator[AsyncPostgresSaver]:
        observed.append(conn_string)
        yield cast("AsyncPostgresSaver", FakeSaver())

    monkeypatch.setattr(AsyncPostgresSaver, "from_conn_string", fake_from_conn_string)

    async def scenario() -> None:
        async with checkpoint_bootstrap.postgres_checkpoint_lifespan():
            pass

    asyncio.run(scenario())
    assert len(observed) == 1
    assert "incident_db" in observed[0]


def test_invalid_connection_configuration_fails_before_opening(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    called = False

    @asynccontextmanager
    async def fake_from_conn_string(
        conn_string: str, *, serde: JsonPlusSerializer
    ) -> AsyncGenerator[AsyncPostgresSaver]:
        nonlocal called
        called = True
        yield cast("AsyncPostgresSaver", FakeSaver())

    monkeypatch.setattr(AsyncPostgresSaver, "from_conn_string", fake_from_conn_string)
    invalid = DatabaseConfig(url=URL.create("sqlite", database="test.sqlite"))

    async def scenario() -> None:
        with pytest.raises(DatabaseConfigurationError, match="postgresql\\+psycopg"):
            async with checkpoint_bootstrap.postgres_checkpoint_lifespan(config=invalid):
                pass

    asyncio.run(scenario())
    assert called is False


def test_lifespan_closes_connection_when_caller_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    exited = False

    @asynccontextmanager
    async def fake_from_conn_string(
        conn_string: str, *, serde: JsonPlusSerializer
    ) -> AsyncGenerator[AsyncPostgresSaver]:
        nonlocal exited
        try:
            yield cast("AsyncPostgresSaver", FakeSaver())
        finally:
            exited = True

    monkeypatch.setattr(AsyncPostgresSaver, "from_conn_string", fake_from_conn_string)

    async def scenario() -> None:
        async with checkpoint_bootstrap.postgres_checkpoint_lifespan(config=_config()):
            raise RuntimeError("Caller failed")

    with pytest.raises(RuntimeError, match="Caller failed"):
        asyncio.run(scenario())
    assert exited is True


def test_connection_open_failure_propagates_without_schema_setup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    @asynccontextmanager
    async def broken_from_conn_string(
        conn_string: str, *, serde: JsonPlusSerializer
    ) -> AsyncGenerator[AsyncPostgresSaver]:
        raise RuntimeError("PostgreSQL unavailable")
        yield cast("AsyncPostgresSaver", FakeSaver())  # pragma: no cover

    monkeypatch.setattr(AsyncPostgresSaver, "from_conn_string", broken_from_conn_string)

    async def scenario() -> None:
        async with checkpoint_bootstrap.postgres_checkpoint_lifespan(config=_config()):
            pass

    with pytest.raises(RuntimeError, match="PostgreSQL unavailable"):
        asyncio.run(scenario())
