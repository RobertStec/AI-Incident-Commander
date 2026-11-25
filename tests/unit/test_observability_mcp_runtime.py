"""Fail-closed deployment configuration and lifecycle tests for MCP runtime."""

import asyncio
import json
import time
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from pathlib import Path
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from mcp.server.auth.provider import AccessToken
from starlette.applications import Starlette

from ai_incident_commander.application.observability_mcp_runtime import (
    CONFIG_ENV,
    _load_settings,
    create_app,
    redact_structured_log,
)
from ai_incident_commander.infrastructure.oauth_introspection import (
    OAuthIntrospectionVerifier,
)


def _runtime_config(secret_file: Path) -> dict[str, object]:
    return {
        "oauth": {
            "issuer_url": "https://auth.example.test/realms/incidents",
            "resource_url": "https://mcp.example.test/mcp",
            "introspection_url": "https://auth.example.test/realms/incidents/protocol/openid-connect/token/introspect",
            "client_id": "observability-resource-server",
            "client_secret_file": str(secret_file),
        },
        "loki": {"base_url": "https://loki.example.test"},
        "http": {"allowed_hosts": ["mcp.example.test"]},
        "grants": [
            {
                "client_id": "incident-worker",
                "service_name": "checkout",
                "labels": {"service_name": "checkout", "environment": "prod"},
                "tenant_id": "tenant-1",
            }
        ],
    }


def _write_config(tmp_path: Path, payload: dict[str, object]) -> Path:
    path = tmp_path / "observability.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_runtime_refuses_missing_deployment_configuration(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(CONFIG_ENV, raising=False)
    with pytest.raises(ValueError, match="Required deployment setting"):
        create_app()


def test_runtime_refuses_empty_grants(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    secret_file = tmp_path / "oauth-secret"
    secret_file.write_text("secret", encoding="utf-8")
    config = _runtime_config(secret_file)
    config["grants"] = []
    monkeypatch.setenv(CONFIG_ENV, str(_write_config(tmp_path, config)))
    with pytest.raises(ValueError, match="cannot be empty"):
        create_app()


def test_runtime_rejects_duplicate_grants(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    secret_file = tmp_path / "oauth-secret"
    secret_file.write_text("secret", encoding="utf-8")
    config = _runtime_config(secret_file)
    existing_grants = config["grants"]
    assert isinstance(existing_grants, list)
    config["grants"] = [existing_grants[0], existing_grants[0]]
    monkeypatch.setenv(CONFIG_ENV, str(_write_config(tmp_path, config)))
    with pytest.raises(ValueError, match="Duplicate principal/service"):
        create_app()


def test_runtime_rejects_duplicate_json_keys(tmp_path: Path) -> None:
    path = tmp_path / "dup.json"
    path.write_text('{"oauth":{},"oauth":{}}', encoding="utf-8")
    with pytest.raises(ValueError, match="Duplicate key"):
        _load_settings(path)


def test_runtime_refuses_secret_missing_or_oauth_http(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    secret_file = tmp_path / "oauth-secret"
    config = _runtime_config(secret_file)
    monkeypatch.setenv(CONFIG_ENV, str(_write_config(tmp_path, config)))
    with pytest.raises(FileNotFoundError):
        create_app()
    secret_file.write_text("secret", encoding="utf-8")
    oauth_settings = config["oauth"]
    assert isinstance(oauth_settings, dict)
    oauth_settings["introspection_url"] = "http://auth.example.test/introspect"
    _write_config(tmp_path, config)
    with pytest.raises(ValueError, match="HTTPS"):
        create_app()


def test_redactor_does_not_return_free_text_or_sensitive_fields() -> None:
    source = json.dumps(
        {
            "level": "ERROR",
            "http_status": 503,
            "duration_ms": 141.5,
            "message": "token=secret API key is private",
            "authorization": "Bearer sensitive",
            "user": {"email": "person@example.test"},
            "error_code": "UPSTREAM_TIMEOUT",
        }
    )
    output = redact_structured_log(source)
    assert json.loads(output) == {
        "redacted": True,
        "level": "ERROR",
        "http_status": 503,
        "duration_ms": 141.5,
        "error_code": "UPSTREAM_TIMEOUT",
    }
    assert "secret" not in output and "Bearer" not in output and "email" not in output
    assert redact_structured_log("raw secret line") == '{"redacted":true}'


def test_runtime_lifespan_starts_mcp_and_refuses_unauthenticated_http(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    secret_file = tmp_path / "oauth-secret"
    secret_file.write_text("secret", encoding="utf-8")
    monkeypatch.setenv(CONFIG_ENV, str(_write_config(tmp_path, _runtime_config(secret_file))))
    app = create_app()
    assert isinstance(app, Starlette)

    async def scenario() -> None:
        async with app.router.lifespan_context(app):
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://mcp.example.test"
            ) as client:
                response = await client.post(
                    "/mcp",
                    headers={"Accept": "application/json, text/event-stream"},
                    json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
                )
                assert response.status_code == 401

    asyncio.run(scenario())


def test_runtime_rejects_authenticated_token_without_required_scope(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret_file = tmp_path / "oauth-secret"
    secret_file.write_text("synthetic-secret", encoding="utf-8")

    config = _runtime_config(secret_file)
    monkeypatch.setenv(CONFIG_ENV, str(_write_config(tmp_path, config)))

    async def scenario() -> None:
        with patch.object(
            OAuthIntrospectionVerifier,
            "verify_token",
            new_callable=AsyncMock,
        ) as verify_token:
            # Simulate an identity that passed token verification.
            # Only the required observability scope is missing.
            verify_token.return_value = AccessToken(
                token="synthetic-token",
                client_id="incident-worker",
                scopes=["profile"],
                resource="https://mcp.example.test/mcp",
                subject="test-service-account",
                expires_at=int(time.time()) + 3600,
                claims={
                    "iss": "https://auth.example.test/realms/incidents",
                },
            )

            app = create_app()

            async with app.router.lifespan_context(app):
                async with httpx.AsyncClient(
                    transport=httpx.ASGITransport(app=app),
                    base_url="http://mcp.example.test",
                    timeout=10.0,
                    trust_env=False,
                ) as client:
                    response = await client.post(
                        "/mcp",
                        headers={
                            "Authorization": "Bearer synthetic-token",
                            "Accept": "application/json, text/event-stream",
                            "Content-Type": "application/json",
                        },
                        json={
                            "jsonrpc": "2.0",
                            "id": 1,
                            "method": "initialize",
                            "params": {},
                        },
                    )

            verify_token.assert_awaited_once_with("synthetic-token")

            assert response.status_code == 403
            assert response.json().get("error") == "insufficient_scope"
            assert "insufficient_scope" in response.headers.get("www-authenticate", "")

    asyncio.run(scenario())


def _enable_otlp_logging(config: dict[str, object], password_file: Path) -> None:
    config["otlp_logging"] = {
        "endpoint": "http://127.0.0.1:4318/v1/logs",
        "username": "incident-collector",
        "password_file": str(password_file),
        "service_name": "observability-mcp",
        "environment": "local",
    }


def test_runtime_emits_fixed_lifecycle_events(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    oauth_secret = tmp_path / "oauth-secret"
    oauth_secret.write_text("oauth-secret", encoding="utf-8")
    otlp_secret = tmp_path / "otlp-secret"
    otlp_secret.write_text("otlp-secret", encoding="utf-8")
    config = _runtime_config(oauth_secret)
    _enable_otlp_logging(config, otlp_secret)
    monkeypatch.setenv(CONFIG_ENV, str(_write_config(tmp_path, config)))

    events: list[str] = []
    received: list[object] = []

    class RecordingEmitter:
        def emit(self, event: str) -> None:
            events.append(event)

    @asynccontextmanager
    async def fake_otlp_lifespan(settings: object) -> AsyncGenerator[RecordingEmitter]:
        received.append(settings)
        yield RecordingEmitter()

    with patch(
        "ai_incident_commander.application.observability_mcp_runtime.otlp_runtime_log_lifespan",
        fake_otlp_lifespan,
    ):
        app = create_app()

        async def scenario() -> None:
            async with app.router.lifespan_context(app):
                assert events == ["runtime_starting", "runtime_ready"]
            assert events == ["runtime_starting", "runtime_ready", "runtime_stopping"]

        asyncio.run(scenario())

    assert len(received) == 1
    settings = received[0]
    assert settings.service_name == "observability-mcp"
    assert settings.environment == "local"
    assert settings.password == "otlp-secret"


def test_runtime_emits_failure_event_when_mcp_startup_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    oauth_secret = tmp_path / "oauth-secret"
    oauth_secret.write_text("oauth-secret", encoding="utf-8")
    otlp_secret = tmp_path / "otlp-secret"
    otlp_secret.write_text("otlp-secret", encoding="utf-8")
    config = _runtime_config(oauth_secret)
    _enable_otlp_logging(config, otlp_secret)
    monkeypatch.setenv(CONFIG_ENV, str(_write_config(tmp_path, config)))

    events: list[str] = []

    class RecordingEmitter:
        def emit(self, event: str) -> None:
            events.append(event)

    @asynccontextmanager
    async def fake_otlp_lifespan(_settings: object) -> AsyncGenerator[RecordingEmitter]:
        yield RecordingEmitter()

    @asynccontextmanager
    async def broken_mcp_lifespan(_app: Starlette) -> AsyncGenerator[None]:
        raise RuntimeError("secret server failure text")
        yield

    with (
        patch(
            "ai_incident_commander.application.observability_mcp_runtime.otlp_runtime_log_lifespan",
            fake_otlp_lifespan,
        ),
        patch(
            "ai_incident_commander.application.observability_mcp_runtime.create_observability_mcp_asgi_app",
            return_value=Starlette(lifespan=broken_mcp_lifespan),
        ),
    ):
        app = create_app()

        async def scenario() -> None:
            with pytest.raises(RuntimeError, match="secret server failure text"):
                async with app.router.lifespan_context(app):
                    pass

        asyncio.run(scenario())

    assert events == ["runtime_starting", "runtime_failed"]
    assert "secret" not in repr(events)


def test_runtime_rejects_invalid_explicit_otlp_configuration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    oauth_secret = tmp_path / "oauth-secret"
    oauth_secret.write_text("oauth-secret", encoding="utf-8")
    otlp_secret = tmp_path / "otlp-secret"
    config = _runtime_config(oauth_secret)
    _enable_otlp_logging(config, otlp_secret)
    monkeypatch.setenv(CONFIG_ENV, str(_write_config(tmp_path, config)))
    with pytest.raises(FileNotFoundError):
        create_app()

    otlp_secret.write_text("otlp-secret", encoding="utf-8")
    otlp_settings = config["otlp_logging"]
    assert isinstance(otlp_settings, dict)
    otlp_settings["endpoint"] = "http://remote.invalid:4318/v1/logs"
    _write_config(tmp_path, config)
    with pytest.raises(ValueError, match="loopback"):
        create_app()
