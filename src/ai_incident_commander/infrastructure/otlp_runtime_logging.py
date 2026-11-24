"""Bounded, authenticated OTLP log export for the Observability MCP runtime.

Only trusted, fixed lifecycle events are emitted via a private OTel provider:
no global Python logger, root handler, token, request body, or free-form
exception message is exported.
"""

import asyncio
from base64 import b64encode
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from math import isfinite
from pathlib import Path
from re import fullmatch
from urllib.parse import urlsplit

import requests
from opentelemetry._logs import Logger, SeverityNumber
from opentelemetry.exporter.otlp.proto.http._log_exporter import OTLPLogExporter
from opentelemetry.sdk._logs import LoggerProvider
from opentelemetry.sdk._logs.export import BatchLogRecordProcessor
from opentelemetry.sdk.resources import Resource

_ALLOWED_EVENTS = frozenset(
    {"runtime_starting", "runtime_ready", "runtime_stopping", "runtime_failed"}
)


@dataclass(frozen=True, slots=True, kw_only=True)
class OtlpRuntimeLogSettings:
    """Trusted deployment settings, never constructed from MCP tool arguments."""

    endpoint: str
    username: str
    password: str = field(repr=False)
    service_name: str
    environment: str
    timeout_seconds: float = 5.0
    ca_bundle_file: Path | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.endpoint, str):
            raise ValueError("OTLP log endpoint must be an absolute URL.")
        try:
            url = urlsplit(self.endpoint)
            port = url.port
        except ValueError:
            raise ValueError("Invalid OTLP log endpoint.") from None
        if (
            url.scheme not in ("http", "https")
            or not url.hostname
            or port is None
            or not 1 <= port <= 65535
            or url.path != "/v1/logs"
            or url.query
            or url.fragment
            or url.username is not None
            or url.password is not None
        ):
            raise ValueError("OTLP log endpoint must be an explicit /v1/logs URL.")
        if url.scheme == "http" and url.hostname not in {"localhost", "127.0.0.1", "::1"}:
            raise ValueError("Plain HTTP OTLP logging is permitted only on loopback.")
        if (
            not isinstance(self.username, str)
            or fullmatch(r"[A-Za-z0-9_.-]{1,128}", self.username) is None
        ):
            raise ValueError("Invalid OTLP Basic Auth user name.")
        if (
            not isinstance(self.password, str)
            or not self.password
            or any(char in self.password for char in "\r\n")
        ):
            raise ValueError("OTLP Basic Auth password must be present and single-line.")
        for name, value in (("service_name", self.service_name), ("environment", self.environment)):
            if (
                not isinstance(value, str)
                or fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", value) is None
            ):
                raise ValueError(f"Invalid OTLP {name}.")
        if (
            type(self.timeout_seconds) not in (int, float)
            or not isfinite(self.timeout_seconds)
            or not 0 < self.timeout_seconds <= 30
        ):
            raise ValueError("OTLP export timeout must be between 0 and 30 seconds.")
        if self.ca_bundle_file is not None and not isinstance(self.ca_bundle_file, Path):
            raise ValueError("OTLP TLS CA bundle must be a path.")


class RuntimeLogEmitter:
    """Safe lifecycle log API: no arbitrary text, attributes or external payloads."""

    def __init__(self, logger: Logger) -> None:
        self._logger = logger

    def emit(self, event: str) -> None:
        if event not in _ALLOWED_EVENTS:
            raise ValueError("Unsupported runtime telemetry event.")
        level = SeverityNumber.ERROR if event == "runtime_failed" else SeverityNumber.INFO
        # JSON body is stable and Loki-readable; event_name is semantic OTLP metadata.
        self._logger.emit(
            severity_number=level,
            severity_text="ERROR" if event == "runtime_failed" else "INFO",
            event_name=event,
            body=f'{{"event":"{event}"}}',
        )


@asynccontextmanager
async def otlp_runtime_log_lifespan(
    config: OtlpRuntimeLogSettings,
) -> AsyncGenerator[RuntimeLogEmitter]:
    """Own isolated OTel logging resources for one ASGI process lifespan.

    Export happens on a bounded background queue; shutdown is offloaded from the
    event loop. No application-wide logging configuration is changed.
    """
    auth_value = b64encode(f"{config.username}:{config.password}".encode()).decode("ascii")
    with requests.Session() as session:
        session.trust_env = False  # No ambient proxies or credentials.
        session.verify = str(config.ca_bundle_file) if config.ca_bundle_file is not None else True
        exporter = OTLPLogExporter(
            endpoint=config.endpoint,
            headers={"Authorization": f"Basic {auth_value}"},
            timeout=config.timeout_seconds,
            session=session,
        )
        provider = LoggerProvider(
            resource=Resource(
                {
                    "service.name": config.service_name,
                    "deployment.environment.name": config.environment,
                }
            ),
            shutdown_on_exit=False,
        )
        provider.add_log_record_processor(
            BatchLogRecordProcessor(
                exporter,
                max_queue_size=128,
                max_export_batch_size=16,
                schedule_delay_millis=500,
            )
        )
        # Private provider, no global OTel provider or Python logging handler.
        logger = provider.get_logger("ai_incident_commander.observability_runtime")
        try:
            yield RuntimeLogEmitter(logger)
        finally:
            await asyncio.to_thread(provider.shutdown)
