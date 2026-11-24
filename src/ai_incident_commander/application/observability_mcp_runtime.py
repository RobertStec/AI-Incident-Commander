"""Uvicorn factory for the authenticated Observability MCP resource server.

Run with ``uvicorn ai_incident_commander.application.observability_mcp_runtime:create_app --factory``.
The deployment supplies a trusted JSON config path and secret files; there are no
fallback identities, service grants, or raw-log redaction bypasses.
"""

import json
import os
import re
import ssl
from collections.abc import AsyncGenerator
from contextlib import AsyncExitStack, asynccontextmanager
from math import isfinite
from pathlib import Path
from typing import Any

import httpx
from mcp.server.auth.settings import AuthSettings
from pydantic import AnyHttpUrl, BaseModel, ConfigDict, Field
from starlette.applications import Starlette
from starlette.routing import Mount

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
from ai_incident_commander.infrastructure.oauth_introspection import OAuthIntrospectionVerifier
from ai_incident_commander.infrastructure.otlp_runtime_logging import (
    OtlpRuntimeLogSettings,
    RuntimeLogEmitter,
    otlp_runtime_log_lifespan,
)

CONFIG_ENV = "AIC_OBSERVABILITY_MCP_CONFIG"
MAX_CONFIG_BYTES = 131_072
MAX_SECRET_BYTES = 8192


class _OAuthSettings(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    issuer_url: str
    resource_url: str
    introspection_url: str
    client_id: str
    client_secret_file: Path
    ca_bundle_file: Path | None = None
    timeout_seconds: float = Field(default=5.0, gt=0, le=30)


class _LokiSettings(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    base_url: str
    allow_plain_http: bool = False
    timeout_seconds: float = Field(default=10.0, gt=0, le=60)
    connect_timeout_seconds: float = Field(default=3.0, gt=0, le=60)
    max_connections: int = Field(default=20, ge=1, le=100)
    ca_bundle_file: Path | None = None
    username: str | None = None
    password_file: Path | None = None


class _HttpSettings(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    allowed_hosts: tuple[str, ...]
    allowed_origins: tuple[str, ...] = ()
    max_request_body_bytes: int = 65_536


class _GrantSettings(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    client_id: str
    subject: str | None = None
    service_name: str
    labels: dict[str, str]
    tenant_id: str | None = None


class _OtlpLoggingSettings(BaseModel):
    """Explicit lifecycle telemetry configuration; no implicit environment secrets."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    endpoint: str
    username: str
    password_file: Path
    service_name: str
    environment: str
    timeout_seconds: float = Field(default=5.0, gt=0, le=30)
    ca_bundle_file: Path | None = None


class _RuntimeSettings(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    oauth: _OAuthSettings
    loki: _LokiSettings
    http: _HttpSettings
    grants: tuple[_GrantSettings, ...]
    # Existing deployments remain valid; production environments explicitly opt in.
    otlp_logging: _OtlpLoggingSettings | None = None


def _unique_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate key in observability runtime configuration.")
        result[key] = value
    return result


def _load_settings(path: Path) -> _RuntimeSettings:
    with path.open("rb") as config_file:
        raw = config_file.read(MAX_CONFIG_BYTES + 1)
    if not raw or len(raw) > MAX_CONFIG_BYTES:
        raise ValueError("Observability runtime configuration size is invalid.")
    try:
        payload = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_keys)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ValueError("Invalid observability runtime configuration JSON.") from None
    return _RuntimeSettings.model_validate(payload)


def _read_secret(path: Path) -> str:
    # Read from a deployment-managed mount, never from a tool argument or config JSON.
    with path.open("rb") as secret_file:
        raw = secret_file.read(MAX_SECRET_BYTES + 1)
    if not raw or len(raw) > MAX_SECRET_BYTES:
        raise ValueError("Secret file must contain a bounded nonempty value.")
    try:
        value = raw.decode("utf-8").rstrip("\r\n")
    except UnicodeDecodeError:
        raise ValueError("Secret file must contain UTF-8 text.") from None
    if not value or "\r" in value or "\n" in value:
        raise ValueError("Secret file contains an invalid value.")
    return value


def _authorized_scopes(grants: tuple[_GrantSettings, ...]) -> AuthorizedLokiScopes:
    bindings: dict[ObservabilityPrincipal, dict[str, LokiLogScope]] = {}
    for grant in grants:
        principal = ObservabilityPrincipal(client_id=grant.client_id, subject=grant.subject)
        services = bindings.setdefault(principal, {})
        if grant.service_name in services:
            raise ValueError("Duplicate principal/service observability grant.")
        services[grant.service_name] = LokiLogScope(labels=grant.labels, tenant_id=grant.tenant_id)
    return AuthorizedLokiScopes(bindings)


def redact_structured_log(line: str) -> str:
    """Allowlist diagnostic JSON fields, never reveal free-text log messages.

    This is deliberately restrictive. Unknown, unstructured, and sensitive fields
    are replaced by a constant marker rather than returned to an LLM.
    """
    try:
        item = json.loads(line)
    except (ValueError, TypeError):
        return '{"redacted":true}'
    if not isinstance(item, dict):
        return '{"redacted":true}'

    safe: dict[str, str | int | float | bool] = {"redacted": True}
    level = item.get("level")
    if isinstance(level, str) and level in {
        "TRACE",
        "DEBUG",
        "INFO",
        "WARN",
        "WARNING",
        "ERROR",
        "FATAL",
        "CRITICAL",
    }:
        safe["level"] = level
    status = item.get("http_status")
    if type(status) is int and 100 <= status <= 599:
        safe["http_status"] = status
    duration = item.get("duration_ms")
    if (type(duration) is int and 0 <= duration <= 3_600_000) or (
        type(duration) is float and isfinite(duration) and 0 <= duration <= 3_600_000
    ):
        safe["duration_ms"] = duration
    # Only known diagnostic error categories; never leak arbitrary string fields.
    code = item.get("error_code")
    if isinstance(code, str) and code in {
        "UPSTREAM_TIMEOUT",
        "DEPENDENCY_FAILURE",
        "SERVICE_UNAVAILABLE",
        "RATE_LIMITED",
        "INTERNAL_ERROR",
    }:
        safe["error_code"] = code
    trace_id = item.get("trace_id")
    if isinstance(trace_id, str) and re.fullmatch(r"[0-9a-f]{32}", trace_id):
        safe["trace_id"] = trace_id
    return json.dumps(safe, separators=(",", ":"), sort_keys=True)


def create_app() -> Starlette:
    """Construct one ASGI app per process using explicitly trusted settings.

    No HTTP requests happen at import time or during factory construction. The
    outer lifespan owns introspection HTTP; the nested lifespan owns Loki and MCP.
    """
    config_path = os.environ.get(CONFIG_ENV)
    if not config_path:
        raise ValueError(f"Required deployment setting {CONFIG_ENV} is missing.")
    settings = _load_settings(Path(config_path))
    grants = _authorized_scopes(settings.grants)

    loki = LokiHttpConfig(
        base_url=settings.loki.base_url,
        allow_plain_http=settings.loki.allow_plain_http,
        timeout_seconds=settings.loki.timeout_seconds,
        connect_timeout_seconds=settings.loki.connect_timeout_seconds,
        max_connections=settings.loki.max_connections,
    )
    http_policy = ObservabilityMcpHttpConfig(
        allowed_hosts=settings.http.allowed_hosts,
        allowed_origins=settings.http.allowed_origins,
        max_request_body_bytes=settings.http.max_request_body_bytes,
    )
    if (settings.loki.username is None) != (settings.loki.password_file is None):
        raise ValueError("Loki Basic authentication requires username and password file.")
    if settings.loki.username is not None and settings.loki.base_url.startswith("http://"):
        raise ValueError("Loki Basic authentication requires HTTPS.")
    loki_auth = (
        httpx.BasicAuth(settings.loki.username, _read_secret(settings.loki.password_file))
        if settings.loki.username is not None and settings.loki.password_file is not None
        else None
    )
    loki_tls = (
        ssl.create_default_context(cafile=str(settings.loki.ca_bundle_file))
        if settings.loki.ca_bundle_file is not None
        else None
    )
    oauth_tls = (
        ssl.create_default_context(cafile=str(settings.oauth.ca_bundle_file))
        if settings.oauth.ca_bundle_file is not None
        else True
    )
    # Validate telemetry and read its deployment-managed credential before starting
    # any network resources. A missing/invalid explicit configuration fails closed.
    logging_settings: OtlpRuntimeLogSettings | None = None
    if settings.otlp_logging is not None:
        telemetry = settings.otlp_logging
        logging_settings = OtlpRuntimeLogSettings(
            endpoint=telemetry.endpoint,
            username=telemetry.username,
            password=_read_secret(telemetry.password_file),
            service_name=telemetry.service_name,
            environment=telemetry.environment,
            timeout_seconds=telemetry.timeout_seconds,
            ca_bundle_file=telemetry.ca_bundle_file,
        )

    oauth_secret = _read_secret(settings.oauth.client_secret_file)
    oauth_http = httpx.AsyncClient(
        verify=oauth_tls,
        trust_env=False,
        follow_redirects=False,
        timeout=httpx.Timeout(settings.oauth.timeout_seconds),
        limits=httpx.Limits(max_connections=20, max_keepalive_connections=10),
    )
    verifier = OAuthIntrospectionVerifier(
        http_client=oauth_http,
        introspection_url=settings.oauth.introspection_url,
        issuer_url=settings.oauth.issuer_url,
        resource_url=settings.oauth.resource_url,
        client_id=settings.oauth.client_id,
        client_secret=oauth_secret,
    )
    auth = AuthSettings(
        issuer_url=AnyHttpUrl(settings.oauth.issuer_url),
        resource_server_url=AnyHttpUrl(settings.oauth.resource_url),
        required_scopes=[READ_LOGS_SCOPE],
        validate_token_resource=True,
    )
    mcp_app = create_observability_mcp_asgi_app(
        loki=loki,
        token_verifier=verifier,
        auth=auth,
        grants=grants,
        redact_line=redact_structured_log,
        http=http_policy,
        loki_auth=loki_auth,
        tls_context=loki_tls,
    )

    @asynccontextmanager
    async def lifespan(_app: Starlette) -> AsyncGenerator[None]:
        # Enter the private telemetry provider first so startup failures are
        # observable; exit it last so the bounded queue flushes on shutdown.
        async with AsyncExitStack() as stack:
            emitter: RuntimeLogEmitter | None = None
            if logging_settings is not None:
                emitter = await stack.enter_async_context(
                    otlp_runtime_log_lifespan(logging_settings)
                )
                emitter.emit("runtime_starting")

            try:
                await stack.enter_async_context(oauth_http)
                # A mounted Starlette app does not receive lifespan automatically.
                await stack.enter_async_context(mcp_app.router.lifespan_context(mcp_app))
                if emitter is not None:
                    emitter.emit("runtime_ready")
                yield
            except Exception:
                if emitter is not None:
                    emitter.emit("runtime_failed")
                raise
            else:
                if emitter is not None:
                    emitter.emit("runtime_stopping")

    return Starlette(routes=[Mount("/", app=mcp_app)], lifespan=lifespan)
