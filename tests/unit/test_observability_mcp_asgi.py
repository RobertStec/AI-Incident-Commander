"""HTTP transport and lifecycle security tests using the real MCP ASGI app."""

import asyncio

import httpx
import pytest
from mcp.server.auth.provider import AccessToken, TokenVerifier
from mcp.server.auth.settings import AuthSettings
from pydantic import AnyHttpUrl
from starlette.applications import Starlette

from ai_incident_commander.application.observability_mcp_asgi import (
    ObservabilityMcpHttpConfig,
    create_observability_mcp_asgi_app,
)
from ai_incident_commander.application.observability_mcp_bootstrap import LokiHttpConfig
from ai_incident_commander.application.observability_mcp_server import (
    READ_LOGS_SCOPE,
    AuthorizedLokiScopes,
    ObservabilityPrincipal,
)
from ai_incident_commander.infrastructure.loki_client import LokiLogScope

RESOURCE = "https://mcp.example.test/mcp"
INITIALIZE = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "asgi-security-test", "version": "1"},
    },
}
HEADERS = {"Accept": "application/json, text/event-stream"}


class FixtureTokenVerifier(TokenVerifier):
    """An explicit test-only verifier; never used by runtime composition."""

    async def verify_token(self, token: str) -> AccessToken | None:
        if token != "valid-test-token":
            return None
        return AccessToken(
            token=token,
            client_id="incident-worker",
            scopes=[READ_LOGS_SCOPE],
            resource=RESOURCE,
        )


def make_app() -> Starlette:
    auth = AuthSettings(
        issuer_url=AnyHttpUrl("https://issuer.example.test/"),
        resource_server_url=AnyHttpUrl(RESOURCE),
        required_scopes=[READ_LOGS_SCOPE],
        validate_token_resource=True,
    )
    grants = AuthorizedLokiScopes(
        {
            ObservabilityPrincipal(client_id="incident-worker"): {
                "checkout": LokiLogScope(labels={"service_name": "checkout"})
            }
        }
    )
    return create_observability_mcp_asgi_app(
        loki=LokiHttpConfig(base_url="https://loki.example.test"),
        token_verifier=FixtureTokenVerifier(),
        auth=auth,
        grants=grants,
        redact_line=lambda line: line.replace("secret", "[REDACTED]"),
        http=ObservabilityMcpHttpConfig(
            allowed_hosts=("localhost", "localhost:*"),
        ),
    )


def test_transport_config_rejects_broad_hosts_and_invalid_limits() -> None:
    with pytest.raises(ValueError):
        ObservabilityMcpHttpConfig(allowed_hosts=())
    with pytest.raises(ValueError):
        ObservabilityMcpHttpConfig(allowed_hosts=("*",))
    with pytest.raises(ValueError):
        ObservabilityMcpHttpConfig(allowed_hosts=("*.example.test",))
    with pytest.raises(ValueError):
        ObservabilityMcpHttpConfig(allowed_hosts=("localhost",), max_request_body_bytes=0)


def test_asgi_http_denies_missing_token_and_invalid_host() -> None:
    async def scenario() -> None:
        app = make_app()
        async with app.router.lifespan_context(app):
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app),
                base_url="http://localhost",
            ) as client:
                no_token = await client.post("/mcp", json=INITIALIZE, headers=HEADERS)
                assert no_token.status_code == 401
                invalid_host = await client.post(
                    "/mcp",
                    json=INITIALIZE,
                    headers={
                        **HEADERS,
                        "Host": "evil.example.test",
                        "Authorization": "Bearer valid-test-token",
                    },
                )
                assert invalid_host.status_code == 421

    asyncio.run(scenario())


def test_asgi_http_accepts_verified_bearer_for_initialize() -> None:
    async def scenario() -> None:
        app = make_app()
        async with app.router.lifespan_context(app):
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app),
                base_url="http://localhost",
            ) as client:
                response = await client.post(
                    "/mcp",
                    json=INITIALIZE,
                    headers={**HEADERS, "Authorization": "Bearer valid-test-token"},
                )
                assert response.status_code == 200, response.text
                result = response.json()
                assert result["jsonrpc"] == "2.0"
                assert result["id"] == 1
                assert "result" in result

    asyncio.run(scenario())
