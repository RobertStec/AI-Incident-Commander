"""Lifecycle tests for the authenticated Observability MCP client."""

import asyncio
import base64
import ssl
from pathlib import Path
from typing import cast
from unittest.mock import AsyncMock, patch
from urllib.parse import parse_qs

import httpx2
import pytest
from mcp.client.auth.exceptions import OAuthFlowError
from mcp.client.auth.extensions.client_credentials import (
    ClientCredentialsOAuthProvider,
)
from mcp.shared.auth import OAuthMetadata

from ai_incident_commander.infrastructure.observability_mcp_client import (
    ObservabilityMcpClientSettings,
    OutboundRequestSecurityError,
    _InMemoryOAuthTokenStorage,
    _OutboundRequestPolicy,
    observability_mcp_client_lifespan,
)


def test_lifespan_configures_dependencies_and_closes_clients(
    tmp_path: Path,
) -> None:
    secret_file = tmp_path / "worker-secret"
    secret_file.write_text("synthetic-secret\n", encoding="utf-8")

    settings = ObservabilityMcpClientSettings(
        server_url="https://mcp.example.test/mcp",
        issuer_url="https://auth.example.test/realms/incidents",
        client_id="incident-worker",
        client_secret_file=secret_file,
        timeout_seconds=10.0,
        connect_timeout_seconds=2.0,
    )

    async def scenario() -> None:
        with (
            patch(
                "ai_incident_commander.infrastructure.observability_mcp_client."
                "ClientCredentialsOAuthProvider"
            ) as oauth_factory,
            patch(
                "ai_incident_commander.infrastructure.observability_mcp_client.httpx2.AsyncClient"
            ) as http_factory,
            patch(
                "ai_incident_commander.infrastructure.observability_mcp_client."
                "streamable_http_client"
            ) as transport_factory,
            patch(
                "ai_incident_commander.infrastructure.observability_mcp_client.Client"
            ) as mcp_factory,
        ):
            http_client = http_factory.return_value
            http_client.__aenter__.return_value = http_client

            mcp_client = mcp_factory.return_value
            mcp_client.__aenter__.return_value = mcp_client

            async with observability_mcp_client_lifespan(settings) as client:
                assert client is mcp_client

            oauth_factory.assert_called_once()
            oauth_args = oauth_factory.call_args.kwargs

            assert oauth_args["issuer"] == settings.issuer_url
            assert oauth_args["server_url"] == settings.server_url
            assert oauth_args["client_id"] == "incident-worker"
            assert oauth_args["client_secret"] == "synthetic-secret"
            assert oauth_args["scope"] == "observability:logs:read"
            assert isinstance(oauth_args["storage"], _InMemoryOAuthTokenStorage)

            http_factory.assert_called_once()
            http_args = http_factory.call_args.kwargs

            assert http_args["auth"] is oauth_factory.return_value
            assert http_args["verify"] is True
            assert http_args["trust_env"] is False
            assert http_args["follow_redirects"] is False

            request_hooks = http_args["event_hooks"]["request"]

            assert len(request_hooks) == 1
            assert isinstance(request_hooks[0], _OutboundRequestPolicy)

            timeout = http_args["timeout"]
            assert isinstance(timeout, httpx2.Timeout)
            assert timeout.read == 10.0
            assert timeout.connect == 2.0

            transport_factory.assert_called_once_with(
                settings.server_url,
                http_client=http_client,
            )
            mcp_factory.assert_called_once_with(transport_factory.return_value)

            http_client.__aenter__.assert_awaited_once()
            http_client.__aexit__.assert_awaited_once()
            cast(AsyncMock, mcp_client.__aenter__).assert_awaited_once()
            cast(AsyncMock, mcp_client.__aexit__).assert_awaited_once()

    asyncio.run(scenario())


def test_lifespan_closes_clients_after_consumer_exception(
    tmp_path: Path,
) -> None:
    secret_file = tmp_path / "worker-secret"
    secret_file.write_text("synthetic-secret\n", encoding="utf-8")

    settings = ObservabilityMcpClientSettings(
        server_url="https://mcp.example.test/mcp",
        issuer_url="https://auth.example.test/realms/incidents",
        client_id="incident-worker",
        client_secret_file=secret_file,
    )

    async def scenario() -> None:
        with (
            patch(
                "ai_incident_commander.infrastructure.observability_mcp_client."
                "ClientCredentialsOAuthProvider"
            ),
            patch(
                "ai_incident_commander.infrastructure.observability_mcp_client.httpx2.AsyncClient"
            ) as http_factory,
            patch(
                "ai_incident_commander.infrastructure.observability_mcp_client."
                "streamable_http_client"
            ),
            patch(
                "ai_incident_commander.infrastructure.observability_mcp_client.Client"
            ) as mcp_factory,
        ):
            http_client = http_factory.return_value
            http_client.__aenter__.return_value = http_client

            mcp_client = mcp_factory.return_value
            mcp_client.__aenter__.return_value = mcp_client

            with pytest.raises(
                RuntimeError,
                match="synthetic investigation failure",
            ):
                async with observability_mcp_client_lifespan(settings):
                    raise RuntimeError("synthetic investigation failure")

            http_exit = http_client.__aexit__
            mcp_exit = cast(AsyncMock, mcp_client.__aexit__)

            http_exit.assert_awaited_once()
            mcp_exit.assert_awaited_once()

            assert http_exit.await_args is not None
            assert http_exit.await_args.args[0] is RuntimeError

            assert mcp_exit.await_args is not None
            assert mcp_exit.await_args.args[0] is RuntimeError

    asyncio.run(scenario())


def test_lifespan_closes_http_when_mcp_startup_fails(
    tmp_path: Path,
) -> None:
    secret_file = tmp_path / "worker-secret"
    secret_file.write_text("synthetic-secret\n", encoding="utf-8")

    settings = ObservabilityMcpClientSettings(
        server_url="https://mcp.example.test/mcp",
        issuer_url="https://auth.example.test/realms/incidents",
        client_id="incident-worker",
        client_secret_file=secret_file,
    )

    async def scenario() -> None:
        with (
            patch(
                "ai_incident_commander.infrastructure.observability_mcp_client."
                "ClientCredentialsOAuthProvider"
            ),
            patch(
                "ai_incident_commander.infrastructure.observability_mcp_client.httpx2.AsyncClient"
            ) as http_factory,
            patch(
                "ai_incident_commander.infrastructure.observability_mcp_client."
                "streamable_http_client"
            ),
            patch(
                "ai_incident_commander.infrastructure.observability_mcp_client.Client"
            ) as mcp_factory,
        ):
            http_client = http_factory.return_value
            http_client.__aenter__.return_value = http_client

            mcp_client = mcp_factory.return_value
            mcp_enter = cast(AsyncMock, mcp_client.__aenter__)
            mcp_exit = cast(AsyncMock, mcp_client.__aexit__)

            mcp_enter.side_effect = RuntimeError("synthetic MCP startup failure")

            with pytest.raises(
                RuntimeError,
                match="synthetic MCP startup failure",
            ):
                async with observability_mcp_client_lifespan(settings):
                    pytest.fail("MCP client must not be yielded")

            mcp_enter.assert_awaited_once()
            mcp_exit.assert_not_awaited()

            http_client.__aenter__.assert_awaited_once()
            http_client.__aexit__.assert_awaited_once()

            assert http_client.__aexit__.await_args is not None
            assert http_client.__aexit__.await_args.args[0] is RuntimeError

    asyncio.run(scenario())


def test_lifespan_does_not_start_mcp_when_http_startup_fails(
    tmp_path: Path,
) -> None:
    secret_file = tmp_path / "worker-secret"
    secret_file.write_text("synthetic-secret\n", encoding="utf-8")

    settings = ObservabilityMcpClientSettings(
        server_url="https://mcp.example.test/mcp",
        issuer_url="https://auth.example.test/realms/incidents",
        client_id="incident-worker",
        client_secret_file=secret_file,
    )

    async def scenario() -> None:
        with (
            patch(
                "ai_incident_commander.infrastructure.observability_mcp_client."
                "ClientCredentialsOAuthProvider"
            ) as oauth_factory,
            patch(
                "ai_incident_commander.infrastructure.observability_mcp_client.httpx2.AsyncClient"
            ) as http_factory,
            patch(
                "ai_incident_commander.infrastructure.observability_mcp_client."
                "streamable_http_client"
            ) as transport_factory,
            patch(
                "ai_incident_commander.infrastructure.observability_mcp_client.Client"
            ) as mcp_factory,
        ):
            http_client = http_factory.return_value

            http_enter = http_client.__aenter__
            http_exit = http_client.__aexit__

            http_enter.side_effect = RuntimeError("synthetic HTTP startup failure")

            with pytest.raises(
                RuntimeError,
                match="synthetic HTTP startup failure",
            ):
                async with observability_mcp_client_lifespan(settings):
                    pytest.fail("MCP client must not be yielded")

            oauth_factory.assert_called_once()
            http_factory.assert_called_once()

            http_enter.assert_awaited_once()
            http_exit.assert_not_awaited()

            transport_factory.assert_not_called()
            mcp_factory.assert_not_called()

    asyncio.run(scenario())


def test_lifespan_passes_custom_ca_context_to_http_client(
    tmp_path: Path,
) -> None:
    secret_file = tmp_path / "worker-secret"
    secret_file.write_text("synthetic-secret\n", encoding="utf-8")

    ca_file = tmp_path / "custom-ca.pem"

    settings = ObservabilityMcpClientSettings(
        server_url="https://mcp.example.test/mcp",
        issuer_url="https://auth.example.test/realms/incidents",
        client_id="incident-worker",
        client_secret_file=secret_file,
        ca_bundle_file=ca_file,
    )

    # Real SSLContext object; no network or certificate loading.
    tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

    async def scenario() -> None:
        with (
            patch(
                "ai_incident_commander.infrastructure.observability_mcp_client."
                "ssl.create_default_context",
                return_value=tls_context,
            ) as tls_factory,
            patch(
                "ai_incident_commander.infrastructure.observability_mcp_client."
                "ClientCredentialsOAuthProvider"
            ),
            patch(
                "ai_incident_commander.infrastructure.observability_mcp_client.httpx2.AsyncClient"
            ) as http_factory,
            patch(
                "ai_incident_commander.infrastructure.observability_mcp_client."
                "streamable_http_client"
            ),
            patch(
                "ai_incident_commander.infrastructure.observability_mcp_client.Client"
            ) as mcp_factory,
        ):
            http_client = http_factory.return_value
            http_client.__aenter__.return_value = http_client

            mcp_client = mcp_factory.return_value
            mcp_client.__aenter__.return_value = mcp_client

            async with observability_mcp_client_lifespan(settings) as client:
                assert client is mcp_client

            tls_factory.assert_called_once_with(cafile=str(ca_file))

            http_factory.assert_called_once()
            http_args = http_factory.call_args.kwargs

            assert http_args["verify"] is tls_context
            assert http_args["trust_env"] is False
            assert http_args["follow_redirects"] is False

            http_client.__aexit__.assert_awaited_once()
            cast(
                AsyncMock,
                mcp_client.__aexit__,
            ).assert_awaited_once()

    asyncio.run(scenario())


def test_lifespan_rejects_invalid_ca_before_starting_clients(
    tmp_path: Path,
) -> None:
    secret_file = tmp_path / "worker-secret"
    secret_file.write_text("synthetic-secret\n", encoding="utf-8")

    ca_file = tmp_path / "invalid-ca.pem"
    ca_file.write_text(
        "This is not a valid PEM certificate",
        encoding="utf-8",
    )

    settings = ObservabilityMcpClientSettings(
        server_url="https://mcp.example.test/mcp",
        issuer_url="https://auth.example.test/realms/incidents",
        client_id="incident-worker",
        client_secret_file=secret_file,
        ca_bundle_file=ca_file,
    )

    async def scenario() -> None:
        with (
            patch(
                "ai_incident_commander.infrastructure.observability_mcp_client."
                "ClientCredentialsOAuthProvider"
            ) as oauth_factory,
            patch(
                "ai_incident_commander.infrastructure.observability_mcp_client.httpx2.AsyncClient"
            ) as http_factory,
            patch(
                "ai_incident_commander.infrastructure.observability_mcp_client."
                "streamable_http_client"
            ) as transport_factory,
            patch(
                "ai_incident_commander.infrastructure.observability_mcp_client.Client"
            ) as mcp_factory,
        ):
            with pytest.raises(ssl.SSLError):
                async with observability_mcp_client_lifespan(settings):
                    pytest.fail("Invalid CA must prevent client startup")

            oauth_factory.assert_not_called()
            http_factory.assert_not_called()
            transport_factory.assert_not_called()
            mcp_factory.assert_not_called()

    asyncio.run(scenario())


def test_oauth_provider_rejects_untrusted_issuer_before_token_request() -> None:
    provider = ClientCredentialsOAuthProvider(
        server_url="https://mcp.example.test/mcp",
        issuer="https://auth.example.test/realms/incidents",
        client_id="incident-worker",
        client_secret="synthetic-secret",
        scope="observability:logs:read",
        storage=_InMemoryOAuthTokenStorage(),
    )

    provider.context.oauth_metadata = OAuthMetadata.model_validate(
        {
            "issuer": "https://untrusted.example.test",
            "authorization_endpoint": ("https://untrusted.example.test/authorize"),
            "token_endpoint": "https://untrusted.example.test/token",
        }
    )

    async def scenario() -> None:
        with (
            patch.object(
                type(provider.context),
                "prepare_token_auth",
            ) as prepare_auth,
            patch(
                "mcp.client.auth.extensions.client_credentials.httpx2.Request"
            ) as request_factory,
        ):
            with pytest.raises(
                OAuthFlowError,
                match="Authorization server metadata issuer mismatch",
            ):
                await provider._exchange_token_client_credentials()

            prepare_auth.assert_not_called()
            request_factory.assert_not_called()

        assert provider.context.oauth_metadata is None

    asyncio.run(scenario())


def test_oauth_discovery_does_not_send_credentials_to_untrusted_endpoint(
    tmp_path: Path,
) -> None:
    server_url = "https://mcp.example.test/mcp"
    issuer_url = "https://auth.example.test/realms/incidents"
    untrusted_token_url = "https://untrusted.example.test/token"

    secret_file = tmp_path / "worker-secret"
    secret_file.write_text("synthetic-secret\n", encoding="utf-8")

    settings = ObservabilityMcpClientSettings(
        server_url=server_url,
        issuer_url=issuer_url,
        client_id="incident-worker",
        client_secret_file=secret_file,
    )

    provider = ClientCredentialsOAuthProvider(
        server_url=server_url,
        issuer=issuer_url,
        client_id="incident-worker",
        client_secret="synthetic-secret",
        scope="observability:logs:read",
        storage=_InMemoryOAuthTokenStorage(),
    )

    requests: list[tuple[str, str]] = []
    metadata_served = False

    def handler(request: httpx2.Request) -> httpx2.Response:
        nonlocal metadata_served

        url = str(request.url)
        requests.append((request.method, url))

        if url == server_url:
            return httpx2.Response(
                401,
                headers={
                    "WWW-Authenticate": (
                        'Bearer resource_metadata="'
                        "https://mcp.example.test/"
                        '.well-known/oauth-protected-resource/mcp"'
                    ),
                },
            )

        if (
            request.method == "GET"
            and request.url.host == "mcp.example.test"
            and request.url.path.startswith("/.well-known/oauth-protected-resource")
        ):
            return httpx2.Response(
                200,
                json={
                    "resource": server_url,
                    "authorization_servers": [issuer_url],
                    "scopes_supported": [
                        "observability:logs:read",
                    ],
                },
            )

        if (
            request.method == "GET"
            and request.url.host == "auth.example.test"
            and "/.well-known/" in request.url.path
        ):
            metadata_served = True

            return httpx2.Response(
                200,
                json={
                    "issuer": issuer_url,
                    "authorization_endpoint": (f"{issuer_url}/protocol/openid-connect/auth"),
                    "token_endpoint": untrusted_token_url,
                    "grant_types_supported": [
                        "client_credentials",
                    ],
                    "token_endpoint_auth_methods_supported": [
                        "client_secret_basic",
                        "client_secret_post",
                    ],
                    "scopes_supported": [
                        "observability:logs:read",
                    ],
                    "response_types_supported": ["code"],
                },
            )

        if url == untrusted_token_url:
            pytest.fail("OAuth attempted to contact an untrusted token endpoint")

        pytest.fail(f"Unexpected HTTP request: {request.method} {url}")

    async def scenario() -> None:
        async with httpx2.AsyncClient(
            auth=provider,
            transport=httpx2.MockTransport(handler),
            follow_redirects=False,
            trust_env=False,
            event_hooks={
                "request": [_OutboundRequestPolicy(settings)],
            },
        ) as client:
            with pytest.raises(
                OutboundRequestSecurityError,
                match="Outbound request destination or method is not allowed",
            ):
                await client.post(server_url, json={})

        assert metadata_served
        assert all(url != untrusted_token_url for _, url in requests)

    asyncio.run(scenario())


def test_oauth_discovery_allows_trusted_client_credentials_flow(
    tmp_path: Path,
) -> None:
    server_url = "https://mcp.example.test/mcp"
    issuer_url = "https://auth.example.test/realms/incidents"
    token_url = f"{issuer_url}/protocol/openid-connect/token"

    client_id = "incident-worker"
    client_secret = "synthetic-secret"
    access_token = "synthetic-access-token"
    scope = "observability:logs:read"

    secret_file = tmp_path / "worker-secret"
    secret_file.write_text(
        f"{client_secret}\n",
        encoding="utf-8",
    )

    settings = ObservabilityMcpClientSettings(
        server_url=server_url,
        issuer_url=issuer_url,
        client_id=client_id,
        client_secret_file=secret_file,
    )

    provider = ClientCredentialsOAuthProvider(
        server_url=server_url,
        issuer=issuer_url,
        client_id=client_id,
        client_secret=client_secret,
        scope=scope,
        storage=_InMemoryOAuthTokenStorage(),
    )

    events: list[str] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        url = str(request.url)
        authorization = request.headers.get("authorization")

        if request.method == "POST" and url == server_url:
            assert client_secret.encode() not in request.content

            if authorization is None:
                events.append("mcp_unauthenticated")

                return httpx2.Response(
                    401,
                    headers={
                        "WWW-Authenticate": (
                            'Bearer resource_metadata="'
                            "https://mcp.example.test/"
                            '.well-known/oauth-protected-resource/mcp"'
                        ),
                    },
                )

            assert authorization == f"Bearer {access_token}"
            events.append("mcp_authenticated")

            return httpx2.Response(
                200,
                json={"authenticated": True},
            )

        if (
            request.method == "GET"
            and request.url.host == "mcp.example.test"
            and request.url.path.startswith("/.well-known/oauth-protected-resource")
        ):
            assert authorization is None
            assert not request.content
            events.append("protected_resource_metadata")

            return httpx2.Response(
                200,
                json={
                    "resource": server_url,
                    "authorization_servers": [issuer_url],
                    "scopes_supported": [scope],
                },
            )

        if (
            request.method == "GET"
            and request.url.host == "auth.example.test"
            and "/.well-known/" in request.url.path
        ):
            assert authorization is None
            assert not request.content
            events.append("authorization_server_metadata")

            return httpx2.Response(
                200,
                json={
                    "issuer": issuer_url,
                    "authorization_endpoint": (f"{issuer_url}/protocol/openid-connect/auth"),
                    "token_endpoint": token_url,
                    "grant_types_supported": ["client_credentials"],
                    "token_endpoint_auth_methods_supported": [
                        "client_secret_basic",
                        "client_secret_post",
                    ],
                    "scopes_supported": [scope],
                    "response_types_supported": ["code"],
                },
            )

        if request.method == "POST" and url == token_url:
            events.append("token_exchange")

            form = parse_qs(
                request.content.decode("utf-8"),
                strict_parsing=True,
            )

            assert form["grant_type"] == ["client_credentials"]
            assert form["scope"] == [scope]

            if authorization is not None:
                expected_credentials = base64.b64encode(
                    f"{client_id}:{client_secret}".encode()
                ).decode("ascii")

                assert authorization == f"Basic {expected_credentials}"
                assert "client_secret" not in form
            else:
                assert form["client_id"] == [client_id]
                assert form["client_secret"] == [client_secret]

            return httpx2.Response(
                200,
                json={
                    "access_token": access_token,
                    "token_type": "Bearer",
                    "expires_in": 300,
                    "scope": scope,
                },
            )

        pytest.fail("Unexpected HTTP request during trusted OAuth flow")

    async def scenario() -> None:
        async with httpx2.AsyncClient(
            auth=provider,
            transport=httpx2.MockTransport(handler),
            follow_redirects=False,
            trust_env=False,
            event_hooks={
                "request": [_OutboundRequestPolicy(settings)],
            },
        ) as client:
            response = await client.post(server_url, json={})

        assert response.status_code == 200
        assert response.json() == {"authenticated": True}

        assert events == [
            "mcp_unauthenticated",
            "protected_resource_metadata",
            "authorization_server_metadata",
            "token_exchange",
            "mcp_authenticated",
        ]

    asyncio.run(scenario())


@pytest.mark.parametrize(
    ("redirect_url", "expected_error"),
    [
        pytest.param(
            "https://untrusted.example.test/token",
            OAuthFlowError,
            id="cross-origin",
        ),
        pytest.param(
            "http://auth.example.test/realms/incidents/protocol/openid-connect/token",
            OAuthFlowError,
            id="https-downgrade",
        ),
        pytest.param(
            "https://auth.example.test/untrusted-endpoint",
            OutboundRequestSecurityError,
            id="same-origin-untrusted-path",
        ),
    ],
)
def test_oauth_token_exchange_rejects_unsafe_redirects(
    tmp_path: Path,
    redirect_url: str,
    expected_error: type[Exception],
) -> None:
    server_url = "https://mcp.example.test/mcp"
    issuer_url = "https://auth.example.test/realms/incidents"
    token_url = f"{issuer_url}/protocol/openid-connect/token"
    scope = "observability:logs:read"

    secret_file = tmp_path / "worker-secret"
    secret_file.write_text(
        "synthetic-secret\n",
        encoding="utf-8",
    )

    settings = ObservabilityMcpClientSettings(
        server_url=server_url,
        issuer_url=issuer_url,
        client_id="incident-worker",
        client_secret_file=secret_file,
    )

    provider = ClientCredentialsOAuthProvider(
        server_url=server_url,
        issuer=issuer_url,
        client_id="incident-worker",
        client_secret="synthetic-secret",
        scope=scope,
        storage=_InMemoryOAuthTokenStorage(),
    )

    events: list[str] = []
    requests: list[tuple[str, str]] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        url = str(request.url)
        requests.append((request.method, url))

        if url == redirect_url:
            pytest.fail("OAuth attempted to follow an unsafe token redirect")

        if request.method == "POST" and url == server_url:
            assert "authorization" not in request.headers
            events.append("mcp_unauthenticated")

            return httpx2.Response(
                401,
                headers={
                    "WWW-Authenticate": (
                        'Bearer resource_metadata="'
                        "https://mcp.example.test/"
                        '.well-known/oauth-protected-resource/mcp"'
                    ),
                },
            )

        if (
            request.method == "GET"
            and request.url.host == "mcp.example.test"
            and request.url.path.startswith("/.well-known/oauth-protected-resource")
        ):
            assert "authorization" not in request.headers
            events.append("protected_resource_metadata")

            return httpx2.Response(
                200,
                json={
                    "resource": server_url,
                    "authorization_servers": [issuer_url],
                    "scopes_supported": [scope],
                },
            )

        if (
            request.method == "GET"
            and request.url.host == "auth.example.test"
            and "/.well-known/" in request.url.path
        ):
            assert "authorization" not in request.headers
            events.append("authorization_server_metadata")

            return httpx2.Response(
                200,
                json={
                    "issuer": issuer_url,
                    "authorization_endpoint": (f"{issuer_url}/protocol/openid-connect/auth"),
                    "token_endpoint": token_url,
                    "grant_types_supported": ["client_credentials"],
                    "token_endpoint_auth_methods_supported": [
                        "client_secret_basic",
                        "client_secret_post",
                    ],
                    "scopes_supported": [scope],
                    "response_types_supported": ["code"],
                },
            )

        if request.method == "POST" and url == token_url:
            events.append("token_redirect")

            form = parse_qs(
                request.content.decode("utf-8"),
                strict_parsing=True,
            )

            assert form["grant_type"] == ["client_credentials"]
            assert form["scope"] == [scope]

            authorization = request.headers.get("authorization")

            if authorization is not None:
                expected_credentials = base64.b64encode(b"incident-worker:synthetic-secret").decode(
                    "ascii"
                )

                assert authorization == f"Basic {expected_credentials}"
                assert "client_secret" not in form
            else:
                assert form["client_id"] == ["incident-worker"]
                assert form["client_secret"] == ["synthetic-secret"]

            return httpx2.Response(
                307,
                headers={"Location": redirect_url},
            )

        pytest.fail("Unexpected HTTP request during OAuth redirect test")

    async def scenario() -> None:
        async with httpx2.AsyncClient(
            auth=provider,
            transport=httpx2.MockTransport(handler),
            follow_redirects=False,
            trust_env=False,
            event_hooks={
                "request": [_OutboundRequestPolicy(settings)],
            },
        ) as client:
            with pytest.raises(expected_error):
                await client.post(server_url, json={})

        assert events == [
            "mcp_unauthenticated",
            "protected_resource_metadata",
            "authorization_server_metadata",
            "token_redirect",
        ]

        assert all(url != redirect_url for _, url in requests)

    asyncio.run(scenario())


def test_oauth_scope_escalation_does_not_request_untrusted_scope(
    tmp_path: Path,
) -> None:
    server_url = "https://mcp.example.test/mcp"
    issuer_url = "https://auth.example.test/realms/incidents"
    token_url = f"{issuer_url}/protocol/openid-connect/token"

    allowed_scope = "observability:logs:read"
    untrusted_scope = "observability:logs:write"
    access_token = "synthetic-access-token"

    secret_file = tmp_path / "worker-secret"
    secret_file.write_text(
        "synthetic-secret\n",
        encoding="utf-8",
    )

    settings = ObservabilityMcpClientSettings(
        server_url=server_url,
        issuer_url=issuer_url,
        client_id="incident-worker",
        client_secret_file=secret_file,
    )

    provider = ClientCredentialsOAuthProvider(
        server_url=server_url,
        issuer=issuer_url,
        client_id="incident-worker",
        client_secret="synthetic-secret",
        scope=allowed_scope,
        storage=_InMemoryOAuthTokenStorage(),
    )

    events: list[str] = []
    requested_scopes: list[frozenset[str]] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        url = str(request.url)
        authorization = request.headers.get("authorization")

        if request.method == "POST" and url == server_url:
            if authorization is None:
                events.append("mcp_unauthenticated")

                return httpx2.Response(
                    401,
                    headers={
                        "WWW-Authenticate": (
                            'Bearer resource_metadata="'
                            "https://mcp.example.test/"
                            '.well-known/oauth-protected-resource/mcp"'
                        ),
                    },
                )

            assert authorization == f"Bearer {access_token}"

            if "mcp_authenticated" not in events:
                events.append("mcp_authenticated")

                return httpx2.Response(
                    200,
                    json={"authenticated": True},
                )

            events.append("mcp_scope_escalation")

            return httpx2.Response(
                403,
                headers={
                    "WWW-Authenticate": (
                        f'Bearer error="insufficient_scope", scope="{untrusted_scope}"'
                    ),
                },
            )

        if (
            request.method == "GET"
            and request.url.host == "mcp.example.test"
            and request.url.path.startswith("/.well-known/oauth-protected-resource")
        ):
            assert authorization is None
            events.append("protected_resource_metadata")

            return httpx2.Response(
                200,
                json={
                    "resource": server_url,
                    "authorization_servers": [issuer_url],
                    "scopes_supported": [allowed_scope],
                },
            )

        if (
            request.method == "GET"
            and request.url.host == "auth.example.test"
            and "/.well-known/" in request.url.path
        ):
            assert authorization is None
            events.append("authorization_server_metadata")

            return httpx2.Response(
                200,
                json={
                    "issuer": issuer_url,
                    "authorization_endpoint": (f"{issuer_url}/protocol/openid-connect/auth"),
                    "token_endpoint": token_url,
                    "grant_types_supported": ["client_credentials"],
                    "token_endpoint_auth_methods_supported": [
                        "client_secret_basic",
                        "client_secret_post",
                    ],
                    "scopes_supported": [
                        allowed_scope,
                        untrusted_scope,
                    ],
                    "response_types_supported": ["code"],
                },
            )

        if request.method == "POST" and url == token_url:
            form = parse_qs(
                request.content.decode("utf-8"),
                strict_parsing=True,
            )

            assert form["grant_type"] == ["client_credentials"]

            scopes = frozenset(scope for value in form.get("scope", []) for scope in value.split())

            requested_scopes.append(scopes)

            if scopes != frozenset({allowed_scope}):
                pytest.fail("OAuth attempted to request scopes outside the trusted scope policy")

            events.append("token_exchange")

            return httpx2.Response(
                200,
                json={
                    "access_token": access_token,
                    "token_type": "Bearer",
                    "expires_in": 300,
                    "scope": allowed_scope,
                },
            )

        pytest.fail("Unexpected HTTP request during OAuth scope escalation test")

    async def scenario() -> None:
        async with httpx2.AsyncClient(
            auth=provider,
            transport=httpx2.MockTransport(handler),
            follow_redirects=False,
            trust_env=False,
            event_hooks={
                "request": [_OutboundRequestPolicy(settings)],
            },
        ) as client:
            response = await client.post(server_url, json={})

            assert response.status_code == 200
            assert response.json() == {"authenticated": True}

            with pytest.raises(
                OutboundRequestSecurityError,
                match="OAuth scope violates the trusted policy",
            ):
                await client.post(server_url, json={})

        assert events == [
            "mcp_unauthenticated",
            "protected_resource_metadata",
            "authorization_server_metadata",
            "token_exchange",
            "mcp_authenticated",
            "mcp_scope_escalation",
        ]

        assert requested_scopes == [
            frozenset({allowed_scope}),
        ]

    asyncio.run(scenario())


@pytest.mark.parametrize(
    ("body", "expected_error"),
    [
        pytest.param(
            b"grant_type=client_credentials&scope=observability%3Alogs%3Aread",
            None,
            id="valid-token-request",
        ),
        pytest.param(
            b"grant_type=client_credentials",
            "OAuth scope violates the trusted policy",
            id="missing-scope",
        ),
        pytest.param(
            b"grant_type=client_credentials&scope=",
            "OAuth scope violates the trusted policy",
            id="empty-scope",
        ),
        pytest.param(
            b"grant_type=client_credentials"
            b"&scope=observability:logs:read"
            b"&scope=observability:logs:read",
            "OAuth scope violates the trusted policy",
            id="duplicate-scope",
        ),
        pytest.param(
            b"grant_type=client_credentials&scope=observability:logs:read+observability:logs:write",
            "OAuth scope violates the trusted policy",
            id="additional-scope",
        ),
        pytest.param(
            b"scope=observability:logs:read",
            "OAuth grant type violates the trusted policy",
            id="missing-grant-type",
        ),
        pytest.param(
            b"grant_type=password&scope=observability:logs:read",
            "OAuth grant type violates the trusted policy",
            id="untrusted-grant-type",
        ),
        pytest.param(
            b"grant_type=client_credentials"
            b"&grant_type=client_credentials"
            b"&scope=observability:logs:read",
            "OAuth grant type violates the trusted policy",
            id="duplicate-grant-type",
        ),
        pytest.param(
            b"grant_type=client_credentials&scope=observability:logs:read&malformed",
            "Invalid OAuth token request form",
            id="malformed-form",
        ),
        pytest.param(
            b"grant_type=client_credentials&scope=observability:logs:read" + b"&extra=value" * 15,
            "Invalid OAuth token request form",
            id="too-many-fields",
        ),
        pytest.param(
            b"grant_type=client_credentials&scope=\xff",
            "Invalid OAuth token request form",
            id="invalid-utf8",
        ),
        pytest.param(
            b"grant_type=client_credentials&scope=%FF",
            "Invalid OAuth token request form",
            id="invalid-percent-encoded-utf8",
        ),
    ],
)
def test_outbound_policy_validates_oauth_token_request_form(
    tmp_path: Path,
    body: bytes,
    expected_error: str | None,
) -> None:
    issuer_url = "https://auth.example.test/realms/incidents"

    settings = ObservabilityMcpClientSettings(
        server_url="https://mcp.example.test/mcp",
        issuer_url=issuer_url,
        client_id="incident-worker",
        client_secret_file=tmp_path / "worker-secret",
    )

    policy = _OutboundRequestPolicy(settings)

    request = httpx2.Request(
        "POST",
        f"{issuer_url}/protocol/openid-connect/token",
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
        },
        content=body,
    )

    async def scenario() -> None:
        if expected_error is None:
            await policy(request)
        else:
            with pytest.raises(
                OutboundRequestSecurityError,
                match=expected_error,
            ):
                await policy(request)

    asyncio.run(scenario())
