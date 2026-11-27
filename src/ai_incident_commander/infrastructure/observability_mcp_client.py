"""Trusted configuration for the read-only Observability MCP client."""

import ssl
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import httpx2
from mcp import Client
from mcp.client.auth.extensions.client_credentials import ClientCredentialsOAuthProvider
from mcp.client.streamable_http import streamable_http_client
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from pydantic import BaseModel, ConfigDict, Field, field_validator

MAX_SECRET_BYTES = 8192

OBSERVABILITY_OAUTH_SCOPE = "observability:logs:read"


class OutboundRequestSecurityError(RuntimeError):
    """An outbound request violated the trusted MCP connection policy."""


class ObservabilityMcpClientSettings(BaseModel):
    """Immutable, fail-closed connection settings supplied by a trusted caller."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    server_url: str
    issuer_url: str
    client_id: str
    client_secret_file: Path
    ca_bundle_file: Path | None = None
    timeout_seconds: float = Field(default=10.0, gt=0, le=60)
    connect_timeout_seconds: float = Field(default=3.0, gt=0, le=30)

    @field_validator("server_url", "issuer_url")
    @classmethod
    def validate_https_url(cls, value: str) -> str:

        # Reject ASCII control characters before urlsplit() can normalize them.
        if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
            raise ValueError("MCP client URL contains control characters.")

        try:
            parsed = urlsplit(value)
            _ = parsed.port
        except ValueError:
            raise ValueError("Invalid MCP client URL.") from None

        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or "?" in value
            or "#" in value
            or any(character.isspace() for character in value)
        ):
            raise ValueError(
                "MCP client URLs must use HTTPS without credentials, query parameters or fragments."
            )
        return value

    @field_validator("server_url")
    @classmethod
    def validate_server_path(cls, value: str) -> str:
        if urlsplit(value).path != "/mcp":
            raise ValueError("Observability MCP endpoint must use /mcp.")
        return value

    @field_validator("client_id")
    @classmethod
    def validate_client_id(cls, value: str) -> str:
        if not value or value != value.strip():
            raise ValueError("OAuth client_id must be nonempty and trimmed.")
        return value


def _read_client_secret(path: Path) -> str:
    """Read a bounded deployment-managed OAuth secret without exposing its value."""
    try:
        with path.open("rb") as secret_file:
            raw = secret_file.read(MAX_SECRET_BYTES + 1)
    except OSError:
        raise ValueError("OAuth client secret file cannot be read.") from None

    if not raw or len(raw) > MAX_SECRET_BYTES:
        raise ValueError("OAuth client secret size is invalid.")

    try:
        value = raw.decode("utf-8").rstrip("\r\n")
    except UnicodeDecodeError:
        raise ValueError("OAuth client secret must contain UTF-8 text.") from None

    if not value or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        raise ValueError("OAuth client secret contains an invalid value.")

    return value


class _InMemoryOAuthTokenStorage:
    """Ephemeral OAuth storage scoped to one managed MCP client."""

    def __init__(self) -> None:
        self._tokens: OAuthToken | None = None
        self._client_info: OAuthClientInformationFull | None = None

    async def get_tokens(self) -> OAuthToken | None:
        return self._tokens

    async def set_tokens(self, tokens: OAuthToken) -> None:
        self._tokens = tokens

    async def get_client_info(self) -> OAuthClientInformationFull | None:
        return self._client_info

    async def set_client_info(
        self,
        client_info: OAuthClientInformationFull,
    ) -> None:
        self._client_info = client_info


class _OutboundRequestPolicy:
    """Restrict outbound HTTP requests to trusted MCP and OAuth endpoints."""

    def __init__(
        self,
        settings: ObservabilityMcpClientSettings,
    ) -> None:
        self._server_url = httpx2.URL(settings.server_url)

        server = urlsplit(settings.server_url)
        issuer = urlsplit(settings.issuer_url)

        server_origin = f"{server.scheme}://{server.netloc}"
        issuer_origin = f"{issuer.scheme}://{issuer.netloc}"
        issuer_path = issuer.path.rstrip("/")

        self._token_url = httpx2.URL(
            f"{settings.issuer_url.rstrip('/')}/protocol/openid-connect/token"
        )

        self._discovery_urls = frozenset(
            {
                httpx2.URL(f"{server_origin}/.well-known/oauth-protected-resource"),
                httpx2.URL(f"{server_origin}/.well-known/oauth-protected-resource{server.path}"),
                httpx2.URL(f"{issuer_origin}/.well-known/oauth-authorization-server{issuer_path}"),
                httpx2.URL(f"{issuer_origin}/.well-known/openid-configuration{issuer_path}"),
                httpx2.URL(f"{issuer_origin}{issuer_path}/.well-known/openid-configuration"),
            }
        )

    @staticmethod
    def _validate_token_request(request: httpx2.Request) -> None:
        """Enforce the read-only OAuth token request contract."""
        try:
            form = parse_qs(
                request.content.decode("utf-8"),
                keep_blank_values=True,
                strict_parsing=True,
                errors="strict",
                max_num_fields=16,
            )
        except (ValueError, httpx2.RequestNotRead):
            raise OutboundRequestSecurityError("Invalid OAuth token request form.") from None

        if form.get("grant_type") != ["client_credentials"]:
            raise OutboundRequestSecurityError("OAuth grant type violates the trusted policy.")

        if form.get("scope") != [OBSERVABILITY_OAUTH_SCOPE]:
            raise OutboundRequestSecurityError("OAuth scope violates the trusted policy.")

    async def __call__(self, request: httpx2.Request) -> None:
        if request.url.scheme != "https":
            raise OutboundRequestSecurityError("Outbound request must use HTTPS.")

        authorization = request.headers.get("authorization", "")
        auth_scheme = authorization.partition(" ")[0].lower()

        content_type = request.headers.get("content-type", "").partition(";")[0].strip().lower()

        if request.method == "GET" and request.url in self._discovery_urls:
            if "authorization" in request.headers:
                raise OutboundRequestSecurityError(
                    "OAuth discovery must not carry authorization credentials."
                )
            return

        if request.method == "POST" and request.url == self._token_url:
            if auth_scheme not in ("", "basic"):
                raise OutboundRequestSecurityError("Invalid token endpoint authorization scheme.")

            if content_type != "application/x-www-form-urlencoded":
                raise OutboundRequestSecurityError("Invalid token endpoint content type.")

            self._validate_token_request(request)
            return

        if request.url == self._server_url and request.method in ("GET", "POST", "DELETE"):
            if auth_scheme not in ("", "bearer"):
                raise OutboundRequestSecurityError("Invalid MCP authorization scheme.")

            if request.method == "POST" and content_type != "application/json":
                raise OutboundRequestSecurityError("Invalid MCP request content type.")
            return

        raise OutboundRequestSecurityError("Outbound request destination or method is not allowed.")


@asynccontextmanager
async def observability_mcp_client_lifespan(
    settings: ObservabilityMcpClientSettings,
) -> AsyncGenerator[Client]:
    """Manage a trusted OAuth-authenticated MCP connection."""

    tls_context = (
        ssl.create_default_context(cafile=str(settings.ca_bundle_file))
        if settings.ca_bundle_file is not None
        else True
    )

    client_secret = _read_client_secret(settings.client_secret_file)

    oauth = ClientCredentialsOAuthProvider(
        server_url=settings.server_url,
        issuer=settings.issuer_url,
        client_id=settings.client_id,
        client_secret=client_secret,
        scope=OBSERVABILITY_OAUTH_SCOPE,
        storage=_InMemoryOAuthTokenStorage(),
    )

    timeout = httpx2.Timeout(
        settings.timeout_seconds,
        connect=settings.connect_timeout_seconds,
    )

    async with httpx2.AsyncClient(
        auth=oauth,
        verify=tls_context,
        timeout=timeout,
        follow_redirects=False,
        trust_env=False,
        event_hooks={
            "request": [_OutboundRequestPolicy(settings)],
        },
    ) as http_client:
        transport = streamable_http_client(
            settings.server_url,
            http_client=http_client,
        )
        async with Client(transport) as client:
            yield client
