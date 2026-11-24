"""Real HTTP protocol contracts and denial paths for OAuth token introspection."""

import asyncio
from datetime import UTC, datetime
from unittest.mock import Mock

import httpx
import pytest

from ai_incident_commander.infrastructure.oauth_introspection import (
    MAX_INTROSPECTION_RESPONSE_BYTES,
    OAuthIntrospectionVerifier,
)

ENDPOINT = "https://auth.example.test/realms/incidents/protocol/openid-connect/token/introspect"
ISSUER = "https://auth.example.test/realms/incidents"
RESOURCE = "https://mcp.example.test/mcp"


def valid_response() -> dict[str, object]:
    return {
        "active": True,
        "iss": ISSUER,
        "aud": ["some-other-resource", RESOURCE],
        "client_id": "incident-worker",
        "sub": "operator-1",
        "scope": "observability:logs:read incident:read",
        "exp": int(datetime.now(UTC).timestamp()) + 300,
        "token_type": "Bearer",
    }


def make_verifier(http_client: httpx.AsyncClient, **overrides: str) -> OAuthIntrospectionVerifier:
    config = dict(
        introspection_url=ENDPOINT,
        issuer_url=ISSUER,
        resource_url=RESOURCE,
        client_id="introspection-rs",
        client_secret="configured-secret",
    )
    config.update(overrides)
    return OAuthIntrospectionVerifier(http_client=http_client, **config)


def test_valid_token_is_verified_at_fixed_endpoint_and_scoped_to_resource() -> None:
    async def scenario() -> None:
        requests: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            requests.append(request)
            return httpx.Response(200, json=valid_response())

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            identity = await make_verifier(http).verify_token("opaque-token")
        assert identity is not None
        assert identity.client_id == "incident-worker"
        assert identity.subject == "operator-1"
        assert identity.resource == RESOURCE
        assert identity.scopes == ["observability:logs:read", "incident:read"]
        assert len(requests) == 1
        assert requests[0].method == "POST"
        assert str(requests[0].url) == ENDPOINT
        assert requests[0].headers["Authorization"].startswith("Basic ")
        assert b"token=opaque-token" in requests[0].content
        assert b"token_type_hint=access_token" in requests[0].content

    asyncio.run(scenario())


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("active", False),
        ("active", "true"),
        ("iss", "https://evil.example.test"),
        ("aud", "https://another-resource.example.test/mcp"),
        ("aud", None),
        ("aud", [RESOURCE, 9]),
        ("client_id", ""),
        ("scope", ""),
        ("exp", 0),
        ("exp", None),
        ("exp", True),
        ("nbf", 4_000_000_000),
        ("token_type", "refresh_token"),
        ("sub", 100),
    ],
)
def test_untrusted_introspection_claims_are_denied(field: str, value: object) -> None:
    async def scenario() -> None:
        payload = valid_response()
        payload[field] = value
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(lambda _: httpx.Response(200, json=payload))
        ) as http:
            assert await make_verifier(http).verify_token("opaque-token") is None

    asyncio.run(scenario())


@pytest.mark.parametrize("status", [301, 400, 401, 429, 500, 503])
def test_introspection_denies_non_200_without_following_redirects(status: int) -> None:
    async def scenario() -> None:
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(
                lambda _: httpx.Response(status, headers={"Location": "https://evil.example"})
            )
        ) as http:
            assert await make_verifier(http).verify_token("opaque-token") is None

    asyncio.run(scenario())


def test_introspection_denies_oversized_or_malformed_responses() -> None:
    async def scenario() -> None:
        for content in (b"{" + b" " * MAX_INTROSPECTION_RESPONSE_BYTES, b"not-json"):
            async with httpx.AsyncClient(
                transport=httpx.MockTransport(
                    lambda _, response_body=content: httpx.Response(200, content=response_body)
                )
            ) as http:
                assert await make_verifier(http).verify_token("opaque-token") is None

    asyncio.run(scenario())


def test_network_failure_denies_without_leaking_token() -> None:
    async def scenario() -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ReadTimeout("network down", request=request)

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            assert await make_verifier(http).verify_token("sensitive-token") is None

    asyncio.run(scenario())


def test_invalid_token_is_denied_without_network_request() -> None:
    async def scenario() -> None:
        handler = Mock(return_value=httpx.Response(200, json=valid_response()))
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            verifier = make_verifier(http)
            for token in ("", "with spaces", "ą", "x" * 8193):
                assert await verifier.verify_token(token) is None
        handler.assert_not_called()

    asyncio.run(scenario())


def test_configuration_refuses_http_userinfo_and_missing_credentials() -> None:
    async def scenario() -> None:
        async with httpx.AsyncClient() as http:
            with pytest.raises(ValueError):
                make_verifier(http, introspection_url="http://auth.example.test/introspect")
            with pytest.raises(ValueError):
                make_verifier(http, introspection_url="https://user:pass@auth.example.test/i")
            with pytest.raises(ValueError):
                make_verifier(http, resource_url="http://mcp.example.test/mcp")
            with pytest.raises(ValueError):
                make_verifier(http, client_secret="")

    asyncio.run(scenario())
