"""Resource ownership and secure defaults for the Observability MCP bootstrap."""

import asyncio
from unittest.mock import patch

import httpx
import pytest
from mcp.server import MCPServer
from mcp.server.auth.provider import AccessToken, TokenVerifier
from mcp.server.auth.settings import AuthSettings
from pydantic import AnyHttpUrl

from ai_incident_commander.application.observability_mcp_bootstrap import (
    LokiHttpConfig,
    observability_mcp_lifespan,
)
from ai_incident_commander.application.observability_mcp_server import (
    READ_LOGS_SCOPE,
    AuthorizedLokiScopes,
    ObservabilityPrincipal,
)
from ai_incident_commander.infrastructure.loki_client import LokiLogScope


class RejectAllTokens(TokenVerifier):
    async def verify_token(self, token: str) -> AccessToken | None:
        return None


def auth_settings(*, required_scopes: list[str] | None = None) -> AuthSettings:
    return AuthSettings(
        issuer_url=AnyHttpUrl("https://auth.example.test/"),
        resource_server_url=AnyHttpUrl("https://mcp.example.test/mcp"),
        required_scopes=[READ_LOGS_SCOPE] if required_scopes is None else required_scopes,
        validate_token_resource=True,
    )


def grants() -> AuthorizedLokiScopes:
    return AuthorizedLokiScopes(
        {
            ObservabilityPrincipal(client_id="incident-worker"): {
                "checkout": LokiLogScope(labels={"service_name": "checkout"}),
            }
        }
    )


def test_loki_http_config_denies_plain_http_by_default() -> None:
    with pytest.raises(ValueError, match="authorized endpoint origin"):
        LokiHttpConfig(base_url="http://loki:3100")
    assert (
        LokiHttpConfig(base_url="http://loki:3100", allow_plain_http=True).base_url
        == "http://loki:3100"
    )


@pytest.mark.parametrize(
    "base_url",
    [
        "https://user:password@loki.example.test",
        "https://loki.example.test/alternate",
        "https://loki.example.test/?query=1",
        "https://loki.example.test/#fragment",
        "file:///tmp/loki",
        "https:///",
    ],
)
def test_loki_http_config_rejects_non_origin_urls(base_url: str) -> None:
    with pytest.raises(ValueError):
        LokiHttpConfig(base_url=base_url)


@pytest.mark.parametrize("timeout", [0, -1, float("inf"), float("nan")])
def test_loki_http_config_rejects_invalid_timeout(timeout: float) -> None:
    with pytest.raises(ValueError, match="timeouts"):
        LokiHttpConfig(base_url="https://loki.example.test", timeout_seconds=timeout)


def test_lifecycle_owns_and_closes_client() -> None:
    real_async_client = httpx.AsyncClient
    created: list[httpx.AsyncClient] = []
    configs: list[dict[str, object]] = []

    def create_http_client(**kwargs: object) -> httpx.AsyncClient:
        configs.append(kwargs)
        http_client = real_async_client(
            **kwargs,  # type: ignore[arg-type]
            transport=httpx.MockTransport(lambda request: httpx.Response(200, json={})),
        )
        created.append(http_client)
        return http_client

    async def scenario() -> None:
        with patch(
            "ai_incident_commander.application.observability_mcp_bootstrap.httpx.AsyncClient",
            side_effect=create_http_client,
        ):
            async with observability_mcp_lifespan(
                loki=LokiHttpConfig(base_url="https://loki.example.test"),
                token_verifier=RejectAllTokens(),
                auth=auth_settings(),
                grants=grants(),
                redact_line=lambda line: "[REDACTED]",
            ) as server:
                assert isinstance(server, MCPServer)
                assert len(created) == 1
                assert not created[0].is_closed
                assert configs[0]["trust_env"] is False
                assert configs[0]["follow_redirects"] is False
                assert configs[0]["verify"] is True
            assert created[0].is_closed

    asyncio.run(scenario())


def test_invalid_server_configuration_still_closes_client() -> None:
    real_async_client = httpx.AsyncClient
    created: list[httpx.AsyncClient] = []

    def create_http_client(**kwargs: object) -> httpx.AsyncClient:
        client = real_async_client(
            **kwargs,  # type: ignore[arg-type]
            transport=httpx.MockTransport(lambda request: httpx.Response(200, json={})),
        )
        created.append(client)
        return client

    async def scenario() -> None:
        invalid_auth = AuthSettings(
            issuer_url=AnyHttpUrl("https://auth.example.test/"),
            resource_server_url=AnyHttpUrl("https://mcp.example.test/mcp"),
            required_scopes=None,
            validate_token_resource=True,
        )
        with patch(
            "ai_incident_commander.application.observability_mcp_bootstrap.httpx.AsyncClient",
            side_effect=create_http_client,
        ):
            with pytest.raises(ValueError, match="require log read scope"):
                async with observability_mcp_lifespan(
                    loki=LokiHttpConfig(base_url="https://loki.example.test"),
                    token_verifier=RejectAllTokens(),
                    auth=invalid_auth,
                    grants=grants(),
                    redact_line=lambda line: "[REDACTED]",
                ):
                    pytest.fail("Server should reject missing auth scope.")
        assert len(created) == 1
        assert created[0].is_closed

    asyncio.run(scenario())
