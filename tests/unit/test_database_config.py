"""Tests for PostgreSQL database connection configuration."""

from dataclasses import FrozenInstanceError

import pytest
from sqlalchemy.engine import make_url

from ai_incident_commander.infrastructure.database_config import (
    DatabaseConfig,
    DatabaseConfigurationError,
)

VALID_URL = "postgresql+psycopg://incident_user:secret-value@127.0.0.1:5433/incident_db"


def test_reads_valid_postgresql_url_from_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("DATABASE_URL", VALID_URL)

    config = DatabaseConfig.from_environment()

    assert config.url.drivername == "postgresql+psycopg"
    assert config.url.username == "incident_user"
    assert config.url.password == "secret-value"
    assert config.url.host == "127.0.0.1"
    assert config.url.port == 5433
    assert config.url.database == "incident_db"


def test_parses_percent_encoded_password(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "DATABASE_URL",
        "postgresql+psycopg://user:p%40ss%3Aword@127.0.0.1:5433/db",
    )

    config = DatabaseConfig.from_environment()

    assert config.url.password == "p@ss:word"


@pytest.mark.parametrize("raw_url", [None, "", "  \t  "])
def test_rejects_missing_or_blank_url(
    monkeypatch: pytest.MonkeyPatch,
    raw_url: str | None,
) -> None:
    if raw_url is None:
        monkeypatch.delenv("DATABASE_URL", raising=False)
    else:
        monkeypatch.setenv("DATABASE_URL", raw_url)

    with pytest.raises(DatabaseConfigurationError, match="required"):
        DatabaseConfig.from_environment()


@pytest.mark.parametrize("raw_url", ["not-a-url", "://not-a-valid-url"])
def test_rejects_malformed_url(
    monkeypatch: pytest.MonkeyPatch,
    raw_url: str,
) -> None:
    monkeypatch.setenv("DATABASE_URL", raw_url)

    with pytest.raises(DatabaseConfigurationError, match="invalid format"):
        DatabaseConfig.from_environment()


@pytest.mark.parametrize(
    "raw_url",
    [
        "postgresql://user:secret@127.0.0.1:5433/db",
        "postgresql+asyncpg://user:secret@127.0.0.1:5433/db",
        "sqlite:///tmp/db.sqlite3",
    ],
)
def test_rejects_unsupported_driver(
    monkeypatch: pytest.MonkeyPatch,
    raw_url: str,
) -> None:
    monkeypatch.setenv("DATABASE_URL", raw_url)

    with pytest.raises(DatabaseConfigurationError, match=r"postgresql\+psycopg"):
        DatabaseConfig.from_environment()


@pytest.mark.parametrize(
    "raw_url",
    [
        "postgresql+psycopg://:secret@127.0.0.1:5433/db",
        "postgresql+psycopg://user@127.0.0.1:5433/db",
        "postgresql+psycopg://user:secret@/db",
        "postgresql+psycopg://user:secret@127.0.0.1:5433",
    ],
)
def test_requires_all_connection_components(
    monkeypatch: pytest.MonkeyPatch,
    raw_url: str,
) -> None:
    monkeypatch.setenv("DATABASE_URL", raw_url)

    with pytest.raises(DatabaseConfigurationError, match="must include"):
        DatabaseConfig.from_environment()


def test_repr_does_not_expose_database_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("DATABASE_URL", VALID_URL)

    representation = repr(DatabaseConfig.from_environment())

    assert "secret-value" not in representation
    assert VALID_URL not in representation


def test_configuration_is_frozen_and_uses_slots(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("DATABASE_URL", VALID_URL)
    config = DatabaseConfig.from_environment()

    assert not hasattr(config, "__dict__")
    with pytest.raises(FrozenInstanceError):
        field_name = "url"
        setattr(config, field_name, make_url(VALID_URL))


def test_configuration_error_does_not_reveal_secret(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = "unique-private-password-123"
    monkeypatch.setenv(
        "DATABASE_URL",
        f"postgresql+asyncpg://user:{secret}@127.0.0.1:5433/db",
    )

    with pytest.raises(DatabaseConfigurationError) as captured:
        DatabaseConfig.from_environment()

    assert secret not in str(captured.value)
