"""Validation tests for the trusted Observability MCP client settings."""

import asyncio
from pathlib import Path

import pytest
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from pydantic import ValidationError

from ai_incident_commander.infrastructure.observability_mcp_client import (
    MAX_SECRET_BYTES,
    ObservabilityMcpClientSettings,
    _InMemoryOAuthTokenStorage,
    _read_client_secret,
)


def _settings(**overrides: object) -> ObservabilityMcpClientSettings:
    values: dict[str, object] = {
        "server_url": "https://mcp.example.test/mcp",
        "issuer_url": "https://auth.example.test/realms/incidents",
        "client_id": "incident-worker",
        "client_secret_file": Path("/run/secrets/incident-worker"),
    }
    values.update(overrides)
    return ObservabilityMcpClientSettings.model_validate(values)


def test_accepts_valid_connection_settings() -> None:
    settings = _settings()

    assert settings.server_url == "https://mcp.example.test/mcp"
    assert settings.client_id == "incident-worker"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("server_url", "\x00https://mcp.example.test/mcp"),
        ("server_url", "https://mcp.ex\x00ample.test/mcp"),
        ("issuer_url", "https://auth.ex\x7fample.test/realms/incidents"),
    ],
)
def test_rejects_control_characters_in_urls(
    field: str,
    value: str,
) -> None:
    with pytest.raises(ValidationError):
        _settings(**{field: value})


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("server_url", "http://mcp.example.test/mcp"),
        ("server_url", "https://mcp.example.test/"),
        ("server_url", "https://mcp.example.test/other"),
        ("server_url", "https://mcp.example.test/mcp?limit=100"),
        ("server_url", "https://mcp.example.test/mcp#fragment"),
        ("server_url", "https://user:secret@mcp.example.test/mcp"),
        ("server_url", "https://mcp.example.test:invalid/mcp"),
        ("server_url", "https:///mcp"),
        ("issuer_url", "http://auth.example.test/realms/incidents"),
        ("issuer_url", "https://auth.example.test/realms/incidents?x=1"),
    ],
)
def test_rejects_invalid_connection_urls(
    field: str,
    value: str,
) -> None:
    with pytest.raises(ValidationError):
        _settings(**{field: value})


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("timeout_seconds", 0),
        ("timeout_seconds", -1),
        ("timeout_seconds", 60.1),
        ("connect_timeout_seconds", 0),
        ("connect_timeout_seconds", -1),
        ("connect_timeout_seconds", 30.1),
    ],
)
def test_rejects_invalid_timeouts(
    field: str,
    value: float,
) -> None:
    with pytest.raises(ValidationError):
        _settings(**{field: value})


def test_accepts_timeout_boundaries() -> None:
    settings = _settings(
        timeout_seconds=60,
        connect_timeout_seconds=30,
    )

    assert settings.timeout_seconds == 60
    assert settings.connect_timeout_seconds == 30


def test_rejects_unknown_configuration_fields() -> None:
    with pytest.raises(ValidationError):
        _settings(allow_insecure_tls=True)


def test_settings_are_immutable() -> None:
    settings = _settings()

    with pytest.raises(ValidationError):
        settings.__setattr__("client_id", "another-client")

    assert settings.client_id == "incident-worker"


@pytest.mark.parametrize("suffix", [b"", b"\n", b"\r\n"])
def test_reads_valid_client_secret(
    tmp_path: Path,
    suffix: bytes,
) -> None:
    secret_file = tmp_path / "oauth-secret"
    secret_file.write_bytes(b"synthetic-client-secret" + suffix)

    assert _read_client_secret(secret_file) == "synthetic-client-secret"


def test_accepts_secret_at_maximum_size(tmp_path: Path) -> None:
    secret_file = tmp_path / "oauth-secret"
    secret_file.write_bytes(b"a" * MAX_SECRET_BYTES)

    value = _read_client_secret(secret_file)

    assert len(value) == MAX_SECRET_BYTES


@pytest.mark.parametrize(
    "payload",
    [
        b"",
        b"a" * (MAX_SECRET_BYTES + 1),
        b"\xff",
        b"synthetic\nsecond-line",
        b"synthetic\rsecond-line",
        b"synthetic\x00secret",
        b"synthetic\x7fsecret",
        b"\n",
    ],
)
def test_rejects_invalid_client_secrets(
    tmp_path: Path,
    payload: bytes,
) -> None:
    secret_file = tmp_path / "oauth-secret"
    secret_file.write_bytes(payload)

    with pytest.raises(ValueError):
        _read_client_secret(secret_file)


def test_rejects_missing_client_secret_file(tmp_path: Path) -> None:
    secret_file = tmp_path / "missing-oauth-secret"

    with pytest.raises(ValueError, match="cannot be read") as exc_info:
        _read_client_secret(secret_file)

    assert str(secret_file) not in str(exc_info.value)


def test_secret_validation_error_does_not_leak_sensitive_data(
    tmp_path: Path,
) -> None:
    secret_file = tmp_path / "private-client-credential"
    secret_value = "synthetic-private-credential"
    secret_file.write_bytes(secret_value.encode("utf-8") + b"\x00")

    with pytest.raises(ValueError) as exc_info:
        _read_client_secret(secret_file)

    error_message = str(exc_info.value)

    assert secret_value not in error_message
    assert str(secret_file) not in error_message


def test_oauth_token_storage_roundtrip() -> None:
    async def scenario() -> None:
        storage = _InMemoryOAuthTokenStorage()

        assert await storage.get_tokens() is None
        assert await storage.get_client_info() is None

        tokens = OAuthToken(
            access_token="synthetic-access-token",
            scope="observability:logs:read",
        )
        client_info = OAuthClientInformationFull(
            client_id="incident-worker",
        )

        await storage.set_tokens(tokens)
        await storage.set_client_info(client_info)

        assert await storage.get_tokens() == tokens
        assert await storage.get_client_info() == client_info

    asyncio.run(scenario())


def test_oauth_token_storage_isolated_between_instances() -> None:
    async def scenario() -> None:
        first = _InMemoryOAuthTokenStorage()
        second = _InMemoryOAuthTokenStorage()

        tokens = OAuthToken(access_token="synthetic-first-token")
        client_info = OAuthClientInformationFull(
            client_id="incident-worker",
        )

        await first.set_tokens(tokens)
        await first.set_client_info(client_info)

        assert await second.get_tokens() is None
        assert await second.get_client_info() is None

        other_tokens = OAuthToken(access_token="synthetic-second-token")
        await second.set_tokens(other_tokens)

        assert await first.get_tokens() == tokens
        assert await second.get_tokens() == other_tokens

    asyncio.run(scenario())
