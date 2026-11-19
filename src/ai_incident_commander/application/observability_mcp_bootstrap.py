"""Lifecycle wiring for the read-only Observability MCP resource server.

This is deliberately independent of remediation approvals and PostgreSQL.
The caller must supply trusted OAuth verification, exact service grants, redaction,
and endpoint credentials. HTTP transport startup belongs to the ASGI host.
"""

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from math import isfinite
from ssl import SSLContext

import httpx
from mcp.server import MCPServer
from mcp.server.auth.provider import TokenVerifier
from mcp.server.auth.settings import AuthSettings

from ai_incident_commander.application.observability_mcp_server import (
    AuthorizedLokiScopes,
    LogLineRedactor,
    create_observability_mcp_server,
)
from ai_incident_commander.infrastructure.loki_client import LokiReadClient


@dataclass(frozen=True, slots=True, kw_only=True)
class LokiHttpConfig:
    """Trusted process configuration, never arguments from an MCP tool or LLM.

    HTTPS is mandatory by default. Plain HTTP is a deliberate opt-in for an
    isolated local/container network, not a production security default.
    """

    base_url: str
    allow_plain_http: bool = False
    timeout_seconds: float = 10.0
    connect_timeout_seconds: float = 3.0
    max_connections: int = 20

    def __post_init__(self) -> None:
        if not isinstance(self.base_url, str):
            raise ValueError("Loki base URL must be a string.")
        try:
            url = httpx.URL(self.base_url)
        except (httpx.InvalidURL, ValueError):
            raise ValueError("Invalid Loki base URL.") from None
        if (
            not url.host
            or url.scheme not in ("http", "https")
            or (url.scheme == "http" and not self.allow_plain_http)
            or url.username
            or url.password
            or url.path != "/"
            or url.query
            or url.fragment
        ):
            raise ValueError("Loki base URL must be an authorized endpoint origin.")
        if (
            type(self.timeout_seconds) not in (int, float)
            or not isfinite(self.timeout_seconds)
            or self.timeout_seconds <= 0
            or type(self.connect_timeout_seconds) not in (int, float)
            or not isfinite(self.connect_timeout_seconds)
            or self.connect_timeout_seconds <= 0
            or self.connect_timeout_seconds > self.timeout_seconds
        ):
            raise ValueError("Loki timeouts must be positive, finite and consistent.")
        if type(self.max_connections) is not int or not 1 <= self.max_connections <= 100:
            raise ValueError("Loki max_connections must be between 1 and 100.")


@asynccontextmanager
async def observability_mcp_lifespan(
    *,
    loki: LokiHttpConfig,
    token_verifier: TokenVerifier,
    auth: AuthSettings,
    grants: AuthorizedLokiScopes,
    redact_line: LogLineRedactor,
    loki_auth: httpx.Auth | None = None,
    tls_context: SSLContext | None = None,
) -> AsyncGenerator[MCPServer]:
    """Own Loki HTTP resources for one MCP server process lifecycle.

    The hosting ASGI server must enter its *own* MCP transport lifespan while
    this context remains open. Do not create this context per tool invocation.
    Proxy/environment credentials are disabled; redirects are never followed.
    """
    timeout = httpx.Timeout(
        timeout=loki.timeout_seconds,
        connect=loki.connect_timeout_seconds,
    )
    limits = httpx.Limits(
        max_connections=loki.max_connections,
        max_keepalive_connections=min(loki.max_connections, 10),
    )
    async with httpx.AsyncClient(
        base_url=loki.base_url,
        auth=loki_auth,
        verify=tls_context if tls_context is not None else True,
        trust_env=False,
        timeout=timeout,
        limits=limits,
        follow_redirects=False,
    ) as http_client:
        server = create_observability_mcp_server(
            loki_client=LokiReadClient(http_client),
            token_verifier=token_verifier,
            auth=auth,
            grants=grants,
            redact_line=redact_line,
        )
        yield server
