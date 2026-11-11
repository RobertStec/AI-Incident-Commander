"""Tests for the asynchronous PostgreSQL engine factory."""

import asyncio
from unittest.mock import patch

from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import AsyncEngine

from ai_incident_commander.infrastructure.database_config import DatabaseConfig
from ai_incident_commander.infrastructure.database_engine import create_database_engine


def _make_config() -> DatabaseConfig:
    """Use a non-routable database endpoint without real credentials."""
    return DatabaseConfig(
        url=make_url("postgresql+psycopg://test_user:test_password@127.0.0.1:1/test_db")
    )


def test_factory_passes_url_and_safe_engine_options() -> None:
    config = _make_config()

    with patch(
        "ai_incident_commander.infrastructure.database_engine.create_async_engine"
    ) as engine_factory:
        result = create_database_engine(config)

    engine_factory.assert_called_once_with(
        config.url,
        echo=False,
        hide_parameters=True,
        pool_pre_ping=True,
    )
    assert result is engine_factory.return_value


def test_factory_creates_async_engine_without_connecting() -> None:
    """The fake endpoint is not expected to host PostgreSQL."""
    engine = create_database_engine(_make_config())

    try:
        assert isinstance(engine, AsyncEngine)
        assert engine.dialect.name == "postgresql"
        assert engine.dialect.driver == "psycopg"
        assert engine.dialect.is_async
        assert engine.url.port == 1
    finally:
        asyncio.run(engine.dispose())
