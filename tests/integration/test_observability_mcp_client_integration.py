"""Opt-in integration tests for the production Observability MCP client."""

import asyncio
import json
import os
import re
import socket
import ssl
import sys
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

import httpx2
import pytest
from mcp import MCPError
from mcp.types import TextContent

from ai_incident_commander.infrastructure.observability_mcp_client import (
    ObservabilityMcpClientSettings,
    observability_mcp_client_lifespan,
)

MCP_TEST_URL = "https://observability-mcp:8000/mcp"
OAUTH_TEST_ISSUER = "https://auth.aic.test:8443/realms/incidents"
MAX_TEST_SECRET_BYTES = 8192
PROBE_SERVICE_NAME = "aic-otlp-ingestion-probe"
PROBE_CANARY = "AIC_SYNTHETIC_TEST_ONLY"
UNAUTHORIZED_SERVICE_NAME = "unauthorized-probe"
ACCESS_DENIED_CODE = -32070
ACCESS_DENIED_MESSAGE = "OBS_ACCESS_DENIED"


def _find_certificate_verification_error(
    error: BaseException,
) -> ssl.SSLCertVerificationError | None:
    """Find a certificate verification error wrapped by the MCP transport."""
    pending: list[BaseException] = [error]
    visited: set[int] = set()

    while pending:
        current = pending.pop()

        if id(current) in visited:
            continue

        visited.add(id(current))

        if isinstance(current, ssl.SSLCertVerificationError):
            return current

        if isinstance(current, BaseExceptionGroup):
            pending.extend(current.exceptions)

        if current.__cause__ is not None:
            pending.append(current.__cause__)

        if current.__context__ is not None:
            pending.append(current.__context__)

    return None


@pytest.fixture(scope="module")
def mcp_client_settings() -> Iterator[ObservabilityMcpClientSettings]:
    if os.environ.get("RUN_OBSERVABILITY_MCP_CLIENT_TESTS") != "1":
        pytest.skip(
            "Set RUN_OBSERVABILITY_MCP_CLIENT_TESTS=1 to enable MCP client integration tests"
        )

    if os.environ.get("AIC_TEST_MCP_URL") != MCP_TEST_URL:
        pytest.fail("MCP client tests require the private local endpoint")

    if os.environ.get("AIC_TEST_OAUTH_ISSUER_URL") != OAUTH_TEST_ISSUER:
        pytest.fail("MCP client tests require the trusted local OAuth issuer")

    ca_file = os.environ.get("AIC_TEST_MCP_CA_FILE")

    if not ca_file or not Path(ca_file).is_file():
        pytest.fail("A valid MCP test CA file is required")

    raw_secret = sys.stdin.buffer.read(MAX_TEST_SECRET_BYTES + 1)

    if not raw_secret or len(raw_secret) > MAX_TEST_SECRET_BYTES:
        pytest.fail("Missing or oversized OAuth client secret on stdin")

    with TemporaryDirectory(
        prefix="aic-mcp-client-",
        dir="/tmp",
    ) as directory:
        secret_file = Path(directory) / "worker-secret"

        secret_file.touch(mode=0o600, exist_ok=False)
        secret_file.write_bytes(raw_secret)

        del raw_secret

        yield ObservabilityMcpClientSettings(
            server_url=MCP_TEST_URL,
            issuer_url=OAUTH_TEST_ISSUER,
            client_id="incident-worker",
            client_secret_file=secret_file,
            ca_bundle_file=Path(ca_file),
            timeout_seconds=15.0,
            connect_timeout_seconds=5.0,
        )


def test_mcp_client_authenticates_and_lists_tools(
    mcp_client_settings: ObservabilityMcpClientSettings,
) -> None:
    async def scenario() -> None:
        async with observability_mcp_client_lifespan(mcp_client_settings) as client:
            result = await client.list_tools()

            tool_names = {tool.name for tool in result.tools}

            assert "search_service_logs" in tool_names

    asyncio.run(scenario())


@pytest.mark.parametrize(
    ("use_default_ca", "use_ip_address", "expected_codes"),
    [
        pytest.param(
            True,
            False,
            frozenset({2, 18, 19, 20, 21}),
            id="untrusted-ca",
        ),
        pytest.param(
            False,
            True,
            frozenset({62, 64}),
            id="certificate-identity-mismatch",
        ),
    ],
)
def test_mcp_client_rejects_invalid_tls_identity(
    mcp_client_settings: ObservabilityMcpClientSettings,
    tmp_path: Path,
    use_default_ca: bool,
    use_ip_address: bool,
    expected_codes: frozenset[int],
) -> None:
    server_url = MCP_TEST_URL

    if use_ip_address:
        server_ip = socket.gethostbyname("observability-mcp")
        server_url = f"https://{server_ip}:8000/mcp"

    secret_file = tmp_path / "synthetic-worker-secret"
    secret_file.touch(mode=0o600, exist_ok=False)
    secret_file.write_text(
        "synthetic-secret\n",
        encoding="utf-8",
    )

    settings = ObservabilityMcpClientSettings.model_validate(
        {
            **mcp_client_settings.model_dump(),
            "server_url": server_url,
            "client_secret_file": secret_file,
            "ca_bundle_file": (None if use_default_ca else mcp_client_settings.ca_bundle_file),
        }
    )

    async def scenario() -> None:
        try:
            async with observability_mcp_client_lifespan(settings) as client:
                await client.list_tools()

        except Exception as error:
            tls_error = _find_certificate_verification_error(error)

            if tls_error is None:
                raise

            assert tls_error.verify_code in expected_codes, (
                f"Unexpected TLS verification code: {tls_error.verify_code}"
            )

            print(
                "TLS certificate rejected. Verification code:",
                tls_error.verify_code,
            )

        else:
            pytest.fail("MCP client accepted an invalid TLS certificate identity")

    asyncio.run(scenario())


def test_mcp_client_aborts_oauth_discovery_on_tls_failure(
    mcp_client_settings: ObservabilityMcpClientSettings,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret_file = tmp_path / "synthetic-worker-secret"
    secret_file.touch(mode=0o600, exist_ok=False)
    secret_file.write_text(
        "synthetic-secret\n",
        encoding="utf-8",
    )

    settings = ObservabilityMcpClientSettings.model_validate(
        {
            **mcp_client_settings.model_dump(),
            "client_secret_file": secret_file,
        }
    )

    events: list[str] = []
    issuer_tls_errors: list[ssl.SSLCertVerificationError] = []

    async def record_request(request: httpx2.Request) -> None:
        if request.url == httpx2.URL(MCP_TEST_URL):
            assert "authorization" not in request.headers

    async def record_response(response: httpx2.Response) -> None:
        if response.request.url == httpx2.URL(MCP_TEST_URL) and response.status_code == 401:
            events.append("mcp_unauthorized")

    class UntrustedIssuerTransport(httpx2.AsyncHTTPTransport):
        async def handle_async_request(
            self,
            request: httpx2.Request,
        ) -> httpx2.Response:
            assert request.url.host == "auth.aic.test"
            assert "mcp_unauthorized" in events
            assert request.method == "GET"
            assert "/.well-known/" in request.url.path
            assert "authorization" not in request.headers

            events.append("oauth_discovery_attempted")

            try:
                response = await super().handle_async_request(request)

            except httpx2.ConnectError as error:
                tls_error = _find_certificate_verification_error(error)

                if tls_error is not None:
                    issuer_tls_errors.append(tls_error)
                    events.append("oauth_tls_rejected")

                raise

            await response.aclose()

            pytest.fail("OAuth discovery unexpectedly succeeded without a trusted CA")

    class IssuerTlsFailureClient(httpx2.AsyncClient):
        def __init__(self, **kwargs: Any) -> None:
            untrusted_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

            assert untrusted_context.check_hostname
            assert untrusted_context.verify_mode == ssl.CERT_REQUIRED
            assert not untrusted_context.get_ca_certs()

            super().__init__(
                **kwargs,
                mounts={
                    "https://auth.aic.test:8443": UntrustedIssuerTransport(
                        verify=untrusted_context,
                        trust_env=False,
                        retries=0,
                    ),
                },
            )

            self.event_hooks["request"].append(record_request)
            self.event_hooks["response"].append(record_response)

    monkeypatch.setattr(
        httpx2,
        "AsyncClient",
        IssuerTlsFailureClient,
    )

    async def scenario() -> None:
        try:
            async with observability_mcp_client_lifespan(settings) as client:
                await client.list_tools()

        except Exception as error:
            tls_error = _find_certificate_verification_error(error)

            if tls_error is None:
                raise

            assert tls_error.verify_code in {2, 18, 19, 20, 21}
            assert tls_error in issuer_tls_errors

        else:
            pytest.fail("MCP client continued authentication despite OAuth discovery TLS failure")

        assert events == [
            "mcp_unauthorized",
            "oauth_discovery_attempted",
            "oauth_tls_rejected",
        ]

        print("OAuth discovery TLS failure: correctly rejected")
        print("Authentication aborted before token exchange")

    asyncio.run(scenario())


def test_mcp_client_reads_and_redacts_controlled_log(
    mcp_client_settings: ObservabilityMcpClientSettings,
) -> None:
    trace_id = os.environ.get("AIC_TEST_MCP_PROBE_TRACE_ID", "")

    if re.fullmatch(r"[0-9a-f]{32}", trace_id) is None:
        pytest.fail("A valid controlled OTLP probe trace ID is required")

    allowed_fields = {
        "redacted",
        "level",
        "http_status",
        "duration_ms",
        "error_code",
        "trace_id",
    }

    async def scenario() -> None:
        async with observability_mcp_client_lifespan(mcp_client_settings) as client:
            start = datetime.now(UTC) - timedelta(minutes=5)

            for attempt in range(20):
                end = datetime.now(UTC)

                result = await client.call_tool(
                    "search_service_logs",
                    arguments={
                        "service_name": PROBE_SERVICE_NAME,
                        "start": start.isoformat(),
                        "end": end.isoformat(),
                        "limit": 100,
                    },
                )

                if result.is_error:
                    pytest.fail("MCP log search returned a tool error")

                if PROBE_CANARY in result.model_dump_json():
                    pytest.fail("MCP result leaked the synthetic canary")

                data = result.structured_content

                assert isinstance(data, dict)
                assert data.get("service_name") == PROBE_SERVICE_NAME

                entries = data.get("entries")
                assert isinstance(entries, list)

                matching_entries = []

                for entry in entries:
                    assert isinstance(entry, dict)

                    line = entry.get("line")
                    assert isinstance(line, str)

                    sanitized = json.loads(line)

                    assert isinstance(sanitized, dict)
                    assert sanitized.get("redacted") is True
                    assert set(sanitized).issubset(allowed_fields)

                    if sanitized.get("trace_id") == trace_id:
                        matching_entries.append(sanitized)

                if matching_entries:
                    assert len(matching_entries) == 1

                    assert matching_entries[0] == {
                        "redacted": True,
                        "trace_id": trace_id,
                    }

                    print("Authenticated MCP tool call: PASSED")
                    print("Controlled Loki log retrieval: PASSED")
                    print("Controlled log redaction: PASSED")
                    return

                if attempt < 19:
                    await asyncio.sleep(1)

            pytest.fail("Controlled OTLP probe was not found in MCP results")

    asyncio.run(scenario())


def test_mcp_client_enforces_service_acl(
    mcp_client_settings: ObservabilityMcpClientSettings,
) -> None:
    async def scenario() -> None:
        end = datetime.now(UTC)
        start = end - timedelta(minutes=5)

        common_arguments = {
            "start": start.isoformat(),
            "end": end.isoformat(),
            "limit": 10,
        }

        async with observability_mcp_client_lifespan(mcp_client_settings) as client:
            try:
                denied = await client.call_tool(
                    "search_service_logs",
                    arguments={
                        **common_arguments,
                        "service_name": UNAUTHORIZED_SERVICE_NAME,
                    },
                )

            except MCPError as error:
                assert error.code == ACCESS_DENIED_CODE
                assert error.message == ACCESS_DENIED_MESSAGE

                print("ACL denial received as MCP protocol error")

            else:
                assert denied.is_error is True

                assert any(
                    isinstance(item, TextContent) and ACCESS_DENIED_MESSAGE in item.text
                    for item in denied.content
                )

                assert denied.structured_content is None

                print("ACL denial received as MCP tool error")

            print("Unauthorized service access: DENIED")

            allowed = await client.call_tool(
                "search_service_logs",
                arguments={
                    **common_arguments,
                    "service_name": PROBE_SERVICE_NAME,
                },
            )

            assert allowed.is_error is False

            data = allowed.structured_content

            assert isinstance(data, dict)
            assert data.get("service_name") == PROBE_SERVICE_NAME
            assert isinstance(data.get("entries"), list)

            print("Authorized service access: ALLOWED")
            print("MCP session remains usable after ACL denial")

    asyncio.run(scenario())
