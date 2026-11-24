"""Security and MCP protocol tests for the read-only Loki resource server."""

import asyncio
from datetime import UTC, datetime
from json import dumps
from unittest.mock import patch

import httpx
import pytest
from mcp import Client, MCPError
from mcp.server.auth.provider import AccessToken, TokenVerifier
from mcp.server.auth.settings import AuthSettings
from pydantic import AnyHttpUrl

from ai_incident_commander.application.observability_mcp_server import (
    READ_LOGS_SCOPE,
    AuthorizedLokiScopes,
    ObservabilityPrincipal,
    create_observability_mcp_server,
)
from ai_incident_commander.infrastructure.loki_client import LokiLogScope, LokiReadClient

START = datetime(2026, 11, 19, 9, 0, tzinfo=UTC)
END = datetime(2026, 11, 19, 9, 10, tzinfo=UTC)
RESOURCE = "https://mcp.example.test/mcp"


class RejectAllTokens(TokenVerifier):
    async def verify_token(self, token: str) -> AccessToken | None:
        return None


def auth_settings() -> AuthSettings:
    return AuthSettings(
        issuer_url=AnyHttpUrl("https://auth.example.test/"),
        resource_server_url=AnyHttpUrl(RESOURCE),
        required_scopes=[READ_LOGS_SCOPE],
        validate_token_resource=True,
    )


def allowed_token(*, subject: str | None = None) -> AccessToken:
    return AccessToken(
        token="not-a-real-token",
        client_id="incident-worker",
        subject=subject,
        scopes=[READ_LOGS_SCOPE],
        resource=RESOURCE,
    )


def acl() -> AuthorizedLokiScopes:
    return AuthorizedLokiScopes(
        {
            ObservabilityPrincipal(client_id="incident-worker"): {
                "checkout": LokiLogScope(
                    labels={"service_name": "checkout", "environment": "prod"},
                    tenant_id="tenant-1",
                )
            }
        }
    )


def tool_arguments(*, service: str = "checkout") -> dict[str, object]:
    return {
        "service_name": service,
        "start": START.isoformat(),
        "end": END.isoformat(),
        "limit": 2,
    }


def test_acl_is_exact_match_and_copies_mutable_input() -> None:
    services = {"checkout": LokiLogScope(labels={"app": "checkout"})}
    bindings = {ObservabilityPrincipal(client_id="incident-worker"): services}
    policy = AuthorizedLokiScopes(bindings)
    services.clear()
    assert policy.resolve(allowed_token(), "checkout").labels["app"] == "checkout"
    with pytest.raises(MCPError, match="OBS_ACCESS_DENIED"):
        policy.resolve(allowed_token(), "payments")
    with pytest.raises(MCPError, match="OBS_ACCESS_DENIED"):
        policy.resolve(allowed_token(subject="human-1"), "checkout")


def test_acl_matches_service_account_subject_exactly() -> None:
    subject = "00000000-0000-4000-8000-000000000001"
    other_subject = "00000000-0000-4000-8000-000000000002"
    service = "aic-otlp-ingestion-probe"

    policy = AuthorizedLokiScopes(
        {
            ObservabilityPrincipal(
                client_id="incident-worker",
                subject=subject,
            ): {
                service: LokiLogScope(
                    labels={
                        "service_name": service,
                        "deployment_environment_name": "local",
                    },
                    tenant_id="tenant-1",
                )
            }
        }
    )

    authorized_scope = policy.resolve(
        allowed_token(subject=subject),
        service,
    )

    assert authorized_scope.tenant_id == "tenant-1"
    assert authorized_scope.labels == {
        "service_name": service,
        "deployment_environment_name": "local",
    }

    wrong_client = AccessToken(
        token="not-a-real-token",
        client_id="other-worker",
        subject=subject,
        scopes=[READ_LOGS_SCOPE],
        resource=RESOURCE,
    )

    for denied_token in (
        allowed_token(),
        allowed_token(subject=other_subject),
        wrong_client,
    ):
        with pytest.raises(MCPError, match="OBS_ACCESS_DENIED"):
            policy.resolve(denied_token, service)


def test_acl_requires_verified_identity_and_scope() -> None:
    with pytest.raises(MCPError, match="OBS_ACCESS_DENIED"):
        acl().resolve(None, "checkout")
    unscoped = AccessToken(
        token="not-a-real-token", client_id="incident-worker", scopes=[], resource=RESOURCE
    )
    with pytest.raises(MCPError, match="OBS_ACCESS_DENIED"):
        acl().resolve(unscoped, "checkout")


def test_acl_rejects_empty_and_invalid_bindings() -> None:
    with pytest.raises(ValueError):
        AuthorizedLokiScopes({})
    with pytest.raises(ValueError):
        AuthorizedLokiScopes(
            {ObservabilityPrincipal(client_id="worker"): {"": LokiLogScope(labels={"app": "x"})}}
        )


def test_server_rejects_auth_without_audience_check() -> None:
    async def scenario() -> None:
        async with httpx.AsyncClient(base_url="https://loki.example.test") as http:
            invalid_auth = AuthSettings(
                issuer_url=AnyHttpUrl("https://auth.example.test/"),
                resource_server_url=AnyHttpUrl(RESOURCE),
                required_scopes=[READ_LOGS_SCOPE],
                validate_token_resource=False,
            )
            with pytest.raises(ValueError, match="validate token audience"):
                create_observability_mcp_server(
                    loki_client=LokiReadClient(http),
                    token_verifier=RejectAllTokens(),
                    auth=invalid_auth,
                    grants=acl(),
                    redact_line=lambda line: line.replace("secret", "[REDACTED]"),
                )

    asyncio.run(scenario())


def test_server_rejects_missing_required_scopes() -> None:
    async def scenario() -> None:
        async with httpx.AsyncClient(base_url="https://loki.example.test") as http:
            invalid_auth = AuthSettings(
                issuer_url=AnyHttpUrl("https://auth.example.test/"),
                resource_server_url=AnyHttpUrl(RESOURCE),
                required_scopes=None,
                validate_token_resource=True,
            )

            with pytest.raises(ValueError, match="require log read scope"):
                create_observability_mcp_server(
                    loki_client=LokiReadClient(http),
                    token_verifier=RejectAllTokens(),
                    auth=invalid_auth,
                    grants=acl(),
                    redact_line=lambda line: line.replace("secret", "[REDACTED]"),
                )

    asyncio.run(scenario())


def test_mcp_protocol_denies_in_process_without_authenticated_http_context() -> None:
    async def scenario() -> None:
        calls: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            calls.append(request)
            return httpx.Response(200, json={})

        async with httpx.AsyncClient(
            base_url="https://loki.example.test", transport=httpx.MockTransport(handler)
        ) as http:
            server = create_observability_mcp_server(
                loki_client=LokiReadClient(http),
                token_verifier=RejectAllTokens(),
                auth=auth_settings(),
                grants=acl(),
                redact_line=lambda line: line.replace("secret", "[REDACTED]"),
            )
            async with Client(server) as client:
                tools = await client.list_tools()
                assert [item.name for item in tools.tools] == ["search_service_logs"]
                with pytest.raises(MCPError, match="OBS_ACCESS_DENIED"):
                    await client.call_tool("search_service_logs", tool_arguments())
            assert calls == []

    asyncio.run(scenario())


def test_mcp_protocol_scopes_request_and_redacts_log_data() -> None:
    async def scenario() -> None:
        captured: list[httpx.Request] = []
        timestamp_ns = int(START.timestamp()) * 1_000_000_000

        def handler(request: httpx.Request) -> httpx.Response:
            captured.append(request)
            return httpx.Response(
                200,
                content=dumps(
                    {
                        "status": "success",
                        "data": {
                            "resultType": "streams",
                            "result": [
                                {
                                    "stream": {
                                        "service_name": "checkout",
                                        "environment": "prod",
                                        "pod": "p1",
                                    },
                                    "values": [[str(timestamp_ns), "failed with secret=abc"]],
                                }
                            ],
                        },
                    }
                ).encode(),
            )

        async with httpx.AsyncClient(
            base_url="https://loki.example.test", transport=httpx.MockTransport(handler)
        ) as http:
            server = create_observability_mcp_server(
                loki_client=LokiReadClient(http),
                token_verifier=RejectAllTokens(),
                auth=auth_settings(),
                grants=acl(),
                redact_line=lambda line: line.replace("secret=abc", "secret=[REDACTED]"),
            )
            with patch(
                "ai_incident_commander.application.observability_mcp_server.get_access_token",
                return_value=allowed_token(),
            ):
                async with Client(server) as client:
                    result = await client.call_tool("search_service_logs", tool_arguments())
            assert result.is_error is not True
            assert result.structured_content is not None
            entry = result.structured_content["entries"][0]
            assert entry["line"] == "failed with secret=[REDACTED]"
            assert "tenant-1" not in str(result.structured_content)
            assert "pod" not in str(result.structured_content)
            assert len(captured) == 1
            assert captured[0].headers["X-Scope-OrgID"] == "tenant-1"
            assert captured[0].url.params["query"] == '{environment="prod",service_name="checkout"}'

    asyncio.run(scenario())


def test_mcp_protocol_transient_failure_is_machine_readable() -> None:
    async def scenario() -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(503)

        async with httpx.AsyncClient(
            base_url="https://loki.example.test", transport=httpx.MockTransport(handler)
        ) as http:
            server = create_observability_mcp_server(
                loki_client=LokiReadClient(http),
                token_verifier=RejectAllTokens(),
                auth=auth_settings(),
                grants=acl(),
                redact_line=lambda line: "[REDACTED]",
            )
            with patch(
                "ai_incident_commander.application.observability_mcp_server.get_access_token",
                return_value=allowed_token(),
            ):
                async with Client(server) as client:
                    with pytest.raises(MCPError, match="OBS_BACKEND_TRANSIENT"):
                        await client.call_tool("search_service_logs", tool_arguments())

    asyncio.run(scenario())
