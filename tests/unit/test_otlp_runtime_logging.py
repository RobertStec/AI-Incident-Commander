"""OTLP Runtime log export tests: security, lifecycle and actual HTTP/protobuf."""

import asyncio
import base64
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from opentelemetry.proto.collector.logs.v1.logs_service_pb2 import ExportLogsServiceRequest

from ai_incident_commander.infrastructure.otlp_runtime_logging import (
    OtlpRuntimeLogSettings,
    otlp_runtime_log_lifespan,
)


def settings(*, endpoint: str = "http://127.0.0.1:4318/v1/logs") -> OtlpRuntimeLogSettings:
    return OtlpRuntimeLogSettings(
        endpoint=endpoint,
        username="incident-collector",
        password="private-secret",
        service_name="ai-incident-commander-mcp",
        environment="local",
    )


@pytest.mark.parametrize(
    "endpoint",
    [
        "http://alloy:4318/v1/logs",
        "http://example.test:4318/v1/logs",
        "https://example.test:4318/v1/traces",
        "http://127.0.0.1:4318/v1/logs?token=secret",
        "https://alice:password@example.test:4318/v1/logs",
        "http://127.0.0.1/v1/logs",
    ],
)
def test_rejects_untrusted_or_wrong_otlp_endpoint(endpoint: str) -> None:
    with pytest.raises(ValueError):
        settings(endpoint=endpoint)


def test_requires_safe_configuration_and_never_repr_secrets() -> None:
    config = settings()
    assert "private-secret" not in repr(config)
    with pytest.raises(ValueError):
        OtlpRuntimeLogSettings(
            endpoint=config.endpoint,
            username="incident-collector",
            password="secret\nheader",
            service_name=config.service_name,
            environment=config.environment,
        )
    with pytest.raises(ValueError):
        OtlpRuntimeLogSettings(
            endpoint=config.endpoint,
            username=config.username,
            password="valid",
            service_name="bad service name",
            environment=config.environment,
        )


def test_accepts_remote_https_and_optional_trusted_ca_path() -> None:
    config = OtlpRuntimeLogSettings(
        endpoint="https://alloy.example.test:443/v1/logs",
        username="collector",
        password="secret",
        service_name="mcp-runtime",
        environment="prod",
        ca_bundle_file=Path("/etc/ssl/custom-ca.pem"),
    )
    assert config.ca_bundle_file == Path("/etc/ssl/custom-ca.pem")


def test_sends_only_fixed_events_via_authenticated_otlp_protobuf() -> None:
    captured: list[tuple[str | None, bytes]] = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            captured.append(
                (
                    self.headers.get("Authorization"),
                    self.rfile.read(int(self.headers["Content-Length"])),
                )
            )
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, _format: str, *_args: object) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    endpoint = f"http://127.0.0.1:{server.server_address[1]}/v1/logs"

    async def scenario() -> None:
        async with otlp_runtime_log_lifespan(settings(endpoint=endpoint)) as events:
            events.emit("runtime_ready")
            events.emit("runtime_failed")
            with pytest.raises(ValueError, match="Unsupported runtime"):
                events.emit("token=secret")

    try:
        asyncio.run(scenario())
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    assert captured
    authorization, content = captured[0]
    assert (
        authorization == "Basic " + base64.b64encode(b"incident-collector:private-secret").decode()
    )
    logs = ExportLogsServiceRequest()
    logs.ParseFromString(content)
    resources = logs.resource_logs
    assert len(resources) == 1
    attributes = {item.key: item.value.string_value for item in resources[0].resource.attributes}
    assert attributes["service.name"] == "ai-incident-commander-mcp"
    assert attributes["deployment.environment.name"] == "local"
    events = [
        record.body.string_value
        for group in resources[0].scope_logs
        for record in group.log_records
    ]
    assert events == ['{"event":"runtime_ready"}', '{"event":"runtime_failed"}']
    assert "private-secret" not in str(logs)
