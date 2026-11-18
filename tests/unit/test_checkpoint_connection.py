"""Unit tests for checkpoint-only PostgreSQL DSN and schema isolation."""

import pytest
from sqlalchemy.engine import make_url

from ai_incident_commander.infrastructure.checkpoint_connection import (
    create_checkpoint_conninfo,
)
from ai_incident_commander.infrastructure.database_config import (
    DatabaseConfig,
    DatabaseConfigurationError,
)


def test_checkpoint_conninfo_preserves_credentials_and_url_escaping() -> None:
    original = make_url(
        "postgresql+psycopg://incident_user:p%40ss%2Fword@db.example:5434/incidents"
    )
    config = DatabaseConfig(url=original)

    conninfo = create_checkpoint_conninfo(config)
    parsed = make_url(conninfo)

    assert conninfo.startswith("postgresql://")
    assert "p%40ss%2Fword" in conninfo
    assert parsed.drivername == "postgresql"
    assert parsed.username == "incident_user"
    assert parsed.password == "p@ss/word"
    assert parsed.host == "db.example"
    assert parsed.port == 5434
    assert parsed.database == "incidents"
    assert parsed.query["options"] == "-csearch_path=langgraph_checkpoint"
    assert config.url == original  # Conversion must not mutate shared configuration.


def test_checkpoint_conninfo_preserves_connection_options() -> None:
    config = DatabaseConfig(
        url=make_url(
            "postgresql+psycopg://user:secret@localhost:5432/incidents"
            "?sslmode=require&application_name=incident_commander"
        )
    )

    parsed = make_url(create_checkpoint_conninfo(config))

    assert parsed.query == {
        "sslmode": "require",
        "application_name": "incident_commander",
        "options": "-csearch_path=langgraph_checkpoint",
    }
    assert "options" not in config.url.query


def test_checkpoint_conninfo_uses_validated_environment_configuration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://user:pass@localhost/incident_test")
    config = DatabaseConfig.from_environment()

    result = create_checkpoint_conninfo(config)

    parsed = make_url(result)
    assert parsed.set(query={}) == make_url("postgresql://user:pass@localhost/incident_test")
    assert parsed.query == {"options": "-csearch_path=langgraph_checkpoint"}


def test_checkpoint_conninfo_rejects_other_database_driver_without_leaking_secrets() -> None:
    # DatabaseConfig.from_environment() already checks the driver, but callers
    # may also construct DatabaseConfig directly; the boundary should fail closed.
    config = DatabaseConfig(
        url=make_url("postgresql+asyncpg://user:verysecret@localhost/incident_test")
    )

    with pytest.raises(DatabaseConfigurationError, match=r"postgresql\+psycopg"):
        create_checkpoint_conninfo(config)


def test_checkpoint_conninfo_rejects_existing_options_without_disclosing_secrets() -> None:
    config = DatabaseConfig(
        url=make_url(
            "postgresql+psycopg://user:highly-secret@localhost/incident_test"
            "?options=-csearch_path%3Dpublic"
        )
    )

    with pytest.raises(DatabaseConfigurationError, match="preconfigured libpq options") as exc:
        create_checkpoint_conninfo(config)

    assert "highly-secret" not in str(exc.value)


def test_checkpoint_conninfo_does_not_change_connection_configuration() -> None:
    original = make_url(
        "postgresql+psycopg://user:secret@localhost/incident_test"
        "?application_name=incident_commander&sslmode=require"
    )
    config = DatabaseConfig(url=original)

    create_checkpoint_conninfo(config)

    assert config.url == original
    assert "options" not in config.url.query
