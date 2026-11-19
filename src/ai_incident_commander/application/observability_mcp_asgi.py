"""ASGI entry point for the authenticated, read-only Observability MCP server.

The ASGI host owns both lifecycles: trusted Loki dependencies and MCP's
Streamable HTTP session manager. No mock identity, global client or HTTP server
configuration is created at import time.
"""

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from ssl import SSLContext

import httpx
from mcp.server.auth.provider import TokenVerifier
from mcp.server.auth.settings import AuthSettings
from mcp.server.transport_security import TransportSecuritySettings
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Mount
from starlette.types import ASGIApp, Receive, Scope, Send

from ai_incident_commander.application.observability_mcp_bootstrap import (
    LokiHttpConfig,
    observability_mcp_lifespan,
)
from ai_incident_commander.application.observability_mcp_server import (
    AuthorizedLokiScopes,
    LogLineRedactor,
)


@dataclass(frozen=True, slots=True, kw_only=True)
class ObservabilityMcpHttpConfig:
    """Trusted HTTP deployment policy, independent of tool arguments.

    Allowed hosts are exact Host headers; `hostname:*` permits a variable port,
    never a wildcard hostname. Browser origins are optional and must be explicit.
    """

    allowed_hosts: tuple[str, ...]
    allowed_origins: tuple[str, ...] = ()
    max_request_body_bytes: int = 65_536

    def __post_init__(self) -> None:
        if not self.allowed_hosts:
            raise ValueError("At least one authorized MCP Host header is required.")
        for host in self.allowed_hosts:
            if (
                not isinstance(host, str)
                or not host
                or any(char in host for char in "/\\\r\n\t ")
                or ("*" in host and not (host.endswith(":*") and host.count("*") == 1))
            ):
                raise ValueError("Invalid or overly broad MCP Host allowlist entry.")
        for origin in self.allowed_origins:
            if (
                not isinstance(origin, str)
                or not origin.startswith(("https://", "http://"))
                or any(char in origin for char in "\\\r\n\t ")
                or ("*" in origin and not (origin.endswith(":*") and origin.count("*") == 1))
            ):
                raise ValueError("Invalid or overly broad MCP Origin allowlist entry.")
        if (
            type(self.max_request_body_bytes) is not int
            or not 1 <= self.max_request_body_bytes <= 1_048_576
        ):
            raise ValueError("MCP request body limit must be between 1 and 1048576 bytes.")


class _McpAppSlot:
    """Stable ASGI mount; the concrete MCP app exists only during lifespan."""

    def __init__(self) -> None:
        self.app: ASGIApp | None = None

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        target = self.app
        if target is None:
            await PlainTextResponse("Service unavailable", status_code=503)(scope, receive, send)
            return
        await target(scope, receive, send)


def create_observability_mcp_asgi_app(
    *,
    loki: LokiHttpConfig,
    token_verifier: TokenVerifier,
    auth: AuthSettings,
    grants: AuthorizedLokiScopes,
    redact_line: LogLineRedactor,
    http: ObservabilityMcpHttpConfig,
    loki_auth: httpx.Auth | None = None,
    tls_context: SSLContext | None = None,
) -> Starlette:
    """Build the ASGI host without starting network activity or bypassing OAuth.

    Uvicorn (or another ASGI server) must enable lifespan. Bind TLS and listener
    addresses in deployment configuration, not MCP tool parameters. The SDK owns
    Host/Origin checks; the tool's verified-principal ACL remains authoritative.
    """
    slot = _McpAppSlot()

    @asynccontextmanager
    async def lifespan(_app: Starlette) -> AsyncGenerator[None]:
        async with observability_mcp_lifespan(
            loki=loki,
            token_verifier=token_verifier,
            auth=auth,
            grants=grants,
            redact_line=redact_line,
            loki_auth=loki_auth,
            tls_context=tls_context,
        ) as server:
            # The SDK session manager is initialized by streamable_http_app().
            slot.app = server.streamable_http_app(
                streamable_http_path="/mcp",
                json_response=True,
                stateless_http=True,
                max_request_body_size=http.max_request_body_bytes,
                transport_security=TransportSecuritySettings(
                    enable_dns_rebinding_protection=True,
                    allowed_hosts=list(http.allowed_hosts),
                    allowed_origins=list(http.allowed_origins),
                ),
            )
            try:
                # A mounted ASGI app's own lifespan does not run in Starlette.
                async with server.session_manager.run():
                    yield
            finally:
                slot.app = None

    return Starlette(routes=[Mount("/", app=slot)], lifespan=lifespan)
