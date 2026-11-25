"""Opt-in HTTP integration tests for the private Observability MCP service."""

import json
import os
import secrets
import ssl
import sys
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest

MCP_TEST_URL = "https://observability-mcp:8000/mcp"


def test_mcp_rejects_unauthenticated_http_request() -> None:
    if os.environ.get("RUN_OBSERVABILITY_MCP_HTTP_TESTS") != "1":
        pytest.skip("Set RUN_OBSERVABILITY_MCP_HTTP_TESTS=1 to enable MCP HTTP integration tests")

    url = os.environ.get("AIC_TEST_MCP_URL")
    ca_file = os.environ.get("AIC_TEST_MCP_CA_FILE")

    if url != MCP_TEST_URL:
        pytest.fail("MCP integration test requires the private local test endpoint")

    if not ca_file or not Path(ca_file).is_file():
        pytest.fail("A valid MCP test CA file is required")

    tls_context = ssl.create_default_context(cafile=ca_file)

    with httpx.Client(
        verify=tls_context,
        timeout=10.0,
        trust_env=False,
        follow_redirects=False,
    ) as client:
        response = client.get(
            url,
            headers={
                "Accept": "application/json, text/event-stream",
            },
        )

    assert response.status_code == 401


def test_mcp_authenticated_tools_enforce_allow_and_deny_acl() -> None:
    if os.environ.get("RUN_OBSERVABILITY_MCP_AUTH_TESTS") != "1":
        pytest.skip(
            "Set RUN_OBSERVABILITY_MCP_AUTH_TESTS=1 to enable authenticated MCP integration tests"
        )

    url = os.environ.get("AIC_TEST_MCP_URL")
    ca_file = os.environ.get("AIC_TEST_MCP_CA_FILE")

    if url != MCP_TEST_URL:
        pytest.fail("Authenticated MCP test requires the private local endpoint")

    if not ca_file or not Path(ca_file).is_file():
        pytest.fail("A valid MCP test CA file is required")

    # Credentials are supplied exclusively through stdin.
    # Pytest must run with -s for authenticated integration tests.
    redaction_test = os.environ.get("RUN_OBSERVABILITY_MCP_REDACTION_TESTS") == "1"

    otlp_password: str | None = None

    if redaction_test:
        if os.environ.get("AIC_TEST_OTLP_URL") != ("http://alloy:4318/v1/logs"):
            pytest.fail("Redaction E2E requires the private local OTLP endpoint")

        raw_credentials = sys.stdin.read(16385)

        if len(raw_credentials) > 16384:
            pytest.fail("E2E credentials input exceeds size limit")

        try:
            credentials = json.loads(raw_credentials)
        except json.JSONDecodeError:
            pytest.fail("Invalid E2E credentials input")

        if not isinstance(credentials, dict):
            pytest.fail("E2E credentials must be a JSON object")

        token = credentials.get("access_token")
        otlp_password = credentials.get("otlp_password")

        if (
            not isinstance(otlp_password, str)
            or not 0 < len(otlp_password) <= 512
            or any(char in otlp_password for char in "\r\n")
        ):
            pytest.fail("Missing or invalid OTLP test credentials")

    else:
        token = sys.stdin.read(8193).strip()

    if (
        not isinstance(token, str)
        or not token
        or len(token) > 8192
        or any(char.isspace() for char in token)
    ):
        pytest.fail("Missing or invalid bearer token on stdin")

    # The test creates its own unique correlation identifier.
    probe_trace_id = secrets.token_hex(16) if redaction_test else None

    tls_context = ssl.create_default_context(cafile=ca_file)

    request = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {
                "name": "aic-integration-test",
                "version": "0.1.0",
            },
        },
    }

    def read_result(response: httpx.Response, request_id: int) -> dict:
        assert response.status_code == 200
        assert len(response.content) <= 65536

        content_type = response.headers.get("content-type", "").split(";")[0].strip()

        if content_type == "application/json":
            messages = [response.json()]
        elif content_type == "text/event-stream":
            messages = [
                json.loads(line[5:].strip())
                for line in response.text.splitlines()
                if line.startswith("data:")
            ]
        else:
            pytest.fail("Unexpected MCP response content type")

        results = [
            message["result"]
            for message in messages
            if isinstance(message, dict)
            and message.get("id") == request_id
            and isinstance(message.get("result"), dict)
        ]

        assert len(results) == 1
        return results[0]

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
    }

    with httpx.Client(
        verify=tls_context,
        timeout=15.0,
        trust_env=False,
        follow_redirects=False,
    ) as client:
        response = client.post(
            url,
            headers=headers,
            json=request,
        )

        initialized = read_result(response, 1)

        assert initialized.get("protocolVersion") == "2025-11-25"
        assert isinstance(initialized.get("serverInfo"), dict)

        session_id = response.headers.get("mcp-session-id")
        if session_id:
            headers["Mcp-Session-Id"] = session_id

        headers["MCP-Protocol-Version"] = initialized["protocolVersion"]

        notification = client.post(
            url,
            headers=headers,
            json={
                "jsonrpc": "2.0",
                "method": "notifications/initialized",
            },
        )

        assert notification.status_code in (202, 204)

        response = client.post(
            url,
            headers=headers,
            json={
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/list",
                "params": {},
            },
        )

        listed = read_result(response, 2)

        # Use a rolling window, not an expiring historical log fixture.
        end = datetime.now(UTC)
        start = end - timedelta(minutes=15)

        response = client.post(
            url,
            headers=headers,
            json={
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "search_service_logs",
                    "arguments": {
                        "service_name": "aic-otlp-ingestion-probe",
                        "start": start.isoformat(),
                        "end": end.isoformat(),
                        "limit": 10,
                    },
                },
            },
        )

        called = read_result(response, 3)

        assert called.get("isError") is not True

        data = called.get("structuredContent")
        assert isinstance(data, dict)
        assert data.get("service_name") == "aic-otlp-ingestion-probe"

        entries = data.get("entries")
        assert isinstance(entries, list)

        allowed_fields = {
            "redacted",
            "level",
            "http_status",
            "duration_ms",
            "error_code",
            "trace_id",
        }

        for entry in entries:
            assert isinstance(entry, dict)

            line = entry.get("line")
            assert isinstance(line, str)

            sanitized = json.loads(line)
            assert isinstance(sanitized, dict)
            assert sanitized.get("redacted") is True
            assert set(sanitized).issubset(allowed_fields)

        # A valid OAuth token must not authorize services outside its ACL.
        response = client.post(
            url,
            headers=headers,
            json={
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {
                    "name": "search_service_logs",
                    "arguments": {
                        "service_name": "unauthorized-probe",
                        "start": start.isoformat(),
                        "end": end.isoformat(),
                        "limit": 10,
                    },
                },
            },
        )

        assert response.status_code == 200
        assert len(response.content) <= 65536

        content_type = response.headers.get("content-type", "").split(";")[0].strip()

        if content_type == "application/json":
            messages = [response.json()]
        elif content_type == "text/event-stream":
            messages = [
                json.loads(line[5:].strip())
                for line in response.text.splitlines()
                if line.startswith("data:")
            ]
        else:
            pytest.fail("Unexpected MCP response content type")

        matching = [
            message for message in messages if isinstance(message, dict) and message.get("id") == 4
        ]

        assert len(matching) == 1
        denied = matching[0]

        error = denied.get("error")
        result = denied.get("result")

        jsonrpc_denied = (
            isinstance(error, dict)
            and error.get("code") == -32070
            and error.get("message") == "OBS_ACCESS_DENIED"
        )

        tool_denied = (
            isinstance(result, dict)
            and result.get("isError") is True
            and isinstance(result.get("content"), list)
            and any(
                isinstance(item, dict)
                and item.get("type") == "text"
                and "OBS_ACCESS_DENIED" in str(item.get("text", ""))
                for item in result["content"]
            )
        )

        assert jsonrpc_denied or tool_denied, "MCP must explicitly deny services outside the ACL"

        if probe_trace_id is not None:
            assert isinstance(otlp_password, str)

            # Create a synthetic log with a unique correlation identifier.
            # No real credentials or sensitive application data are emitted.
            probe_body = {
                "event": "redaction_probe",
                "trace_id": probe_trace_id,
                "synthetic_canary": "AIC_SYNTHETIC_TEST_ONLY",
            }

            otlp_payload = {
                "resourceLogs": [
                    {
                        "resource": {
                            "attributes": [
                                {
                                    "key": "service.name",
                                    "value": {"stringValue": "aic-otlp-ingestion-probe"},
                                },
                                {
                                    "key": "deployment.environment.name",
                                    "value": {"stringValue": "local"},
                                },
                            ]
                        },
                        "scopeLogs": [
                            {
                                "scope": {"name": "aic-redaction-integration"},
                                "logRecords": [
                                    {
                                        "timeUnixNano": str(time.time_ns()),
                                        "severityNumber": 9,
                                        "severityText": "INFO",
                                        "body": {"stringValue": json.dumps(probe_body)},
                                    }
                                ],
                            }
                        ],
                    }
                ]
            }

            # This URL was strictly validated before reading credentials.
            otlp_response = client.post(
                os.environ["AIC_TEST_OTLP_URL"],
                auth=httpx.BasicAuth(
                    "incident-collector",
                    otlp_password,
                ),
                json=otlp_payload,
            )

            assert otlp_response.status_code == 200, (
                f"OTLP ingestion rejected the probe: HTTP {otlp_response.status_code}"
            )

            print("Controlled OTLP log submission: ACCEPTED")

            matching_probe_entries = []

            # Allow bounded time for asynchronous Alloy -> Loki ingestion.
            for _ in range(20):
                probe_end = datetime.now(UTC)
                probe_start = probe_end - timedelta(minutes=5)

                response = client.post(
                    url,
                    headers=headers,
                    json={
                        "jsonrpc": "2.0",
                        "id": 5,
                        "method": "tools/call",
                        "params": {
                            "name": "search_service_logs",
                            "arguments": {
                                "service_name": "aic-otlp-ingestion-probe",
                                "start": probe_start.isoformat(),
                                "end": probe_end.isoformat(),
                                "limit": 100,
                            },
                        },
                    },
                )

                probe_result = read_result(response, 5)
                assert probe_result.get("isError") is not True

                # Verify that no MCP response field exposes the synthetic secret.
                assert "AIC_SYNTHETIC_TEST_ONLY" not in response.text, (
                    "MCP response leaked the synthetic canary"
                )

                probe_data = probe_result.get("structuredContent")
                assert isinstance(probe_data, dict)

                probe_entries = probe_data.get("entries")
                assert isinstance(probe_entries, list)

                matching_probe_entries = []

                for entry in probe_entries:
                    assert isinstance(entry, dict)
                    line = entry.get("line")
                    assert isinstance(line, str)

                    sanitized = json.loads(line)
                    assert isinstance(sanitized, dict)

                    if sanitized.get("trace_id") == probe_trace_id:
                        matching_probe_entries.append(sanitized)

                if matching_probe_entries:
                    break

                time.sleep(1)

            assert len(matching_probe_entries) == 1, (
                "Expected exactly one controlled OTLP probe entry"
            )

            assert matching_probe_entries[0] == {
                "redacted": True,
                "trace_id": probe_trace_id,
            }

            print("Controlled OTLP log redaction: PASSED")

    tools = listed.get("tools")
    assert isinstance(tools, list)

    names = [
        tool["name"]
        for tool in tools
        if isinstance(tool, dict) and isinstance(tool.get("name"), str)
    ]

    assert "search_service_logs" in names
