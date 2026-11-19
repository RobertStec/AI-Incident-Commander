"""Bounded, read-only Loki HTTP adapter for the Observability MCP server.

The caller injects an AsyncClient configured with a trusted Loki endpoint,
credentials, TLS verification and timeouts. Scope labels and tenant identity must
come from trusted service bindings/authorization, never directly from an LLM or
an MCP tool argument. This module does not authorize callers on its own.
"""

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from json import JSONDecodeError, dumps, loads
from re import fullmatch
from types import MappingProxyType
from typing import Any

import httpx

MAX_QUERY_WINDOW = timedelta(hours=1)
MAX_QUERY_ENTRIES = 100
MAX_RESPONSE_BYTES = 1_000_000
MAX_LOG_LINE_LENGTH = 8192
MAX_STREAM_LABELS = 32


class LokiError(RuntimeError):
    """Base error for the read-only Loki adapter."""


class LokiTransientError(LokiError):
    """A read-only request failed transiently; the caller may apply retry policy."""


class LokiQueryError(LokiError):
    """Permanent request, authorization, or configuration error."""


class LokiResponseError(LokiError):
    """Malformed, unsafe or unexpectedly large Loki response; never retry blindly."""


@dataclass(frozen=True, slots=True, kw_only=True)
class LokiLogScope:
    """Trusted, service-bound Loki selectors; not an MCP-facing input model."""

    labels: Mapping[str, str]
    tenant_id: str | None = None

    def __post_init__(self) -> None:
        if not self.labels or len(self.labels) > 8:
            raise ValueError("Loki scope requires 1-8 trusted label matchers.")
        for key, value in self.labels.items():
            if not isinstance(key, str) or fullmatch(r"[a-zA-Z_][a-zA-Z0-9_]{0,63}", key) is None:
                raise ValueError("Invalid Loki scope label name.")
            if (
                not isinstance(value, str)
                or not value
                or len(value) > 256
                or any(c in value for c in "\r\n\x00")
            ):
                raise ValueError("Invalid Loki scope label value.")
        if self.tenant_id is not None and (
            fullmatch(r"[a-zA-Z0-9_.-]{1,128}", self.tenant_id) is None
        ):
            raise ValueError("Invalid single-tenant Loki identifier.")
        object.__setattr__(self, "labels", MappingProxyType(dict(self.labels)))


@dataclass(frozen=True, slots=True, kw_only=True)
class LokiLogEntry:
    timestamp_ns: int
    line: str
    labels: Mapping[str, str]


@dataclass(frozen=True, slots=True, kw_only=True)
class LokiLogBatch:
    entries: tuple[LokiLogEntry, ...]
    # Reaching the requested limit means the response cannot prove completeness.
    limit_reached: bool


def _unix_ns(timestamp: datetime) -> int:
    delta = timestamp - datetime(1970, 1, 1, tzinfo=UTC)
    return (delta.days * 86_400 + delta.seconds) * 1_000_000_000 + delta.microseconds * 1_000


def _validate_window(start: datetime, end: datetime, limit: int) -> tuple[int, int]:
    if start.utcoffset() != timedelta(0) or end.utcoffset() != timedelta(0):
        raise ValueError("Loki query timestamps must be UTC-aware.")
    if not start < end or end - start > MAX_QUERY_WINDOW:
        raise ValueError("Loki query window must be positive and at most one hour.")
    if type(limit) is not int or not 1 <= limit <= MAX_QUERY_ENTRIES:
        raise ValueError("Loki query limit must be an integer between 1 and 100.")
    return _unix_ns(start), _unix_ns(end)


def _query_selector(scope: LokiLogScope) -> str:
    # json.dumps escapes quotes and backslashes in trusted label values.
    return (
        "{"
        + ",".join(
            f"{key}={dumps(value, ensure_ascii=True)}"
            for key, value in sorted(scope.labels.items())
        )
        + "}"
    )


def _decode_loki_response(
    raw: bytes, *, scope: LokiLogScope, start_ns: int, end_ns: int, limit: int
) -> LokiLogBatch:
    try:
        response: Any = loads(raw)
    except (JSONDecodeError, UnicodeDecodeError):
        raise LokiResponseError("Loki returned invalid JSON.") from None
    if not isinstance(response, dict) or response.get("status") != "success":
        raise LokiResponseError("Loki returned an unsuccessful response envelope.")
    data = response.get("data")
    if not isinstance(data, dict) or data.get("resultType") != "streams":
        raise LokiResponseError("Loki returned an unexpected result type.")
    streams = data.get("result")
    if not isinstance(streams, list):
        raise LokiResponseError("Loki response is missing streams.")

    entries: list[LokiLogEntry] = []
    for stream in streams:
        if not isinstance(stream, dict):
            raise LokiResponseError("Malformed Loki stream.")
        labels = stream.get("stream")
        values = stream.get("values")
        if (
            not isinstance(labels, dict)
            or len(labels) > MAX_STREAM_LABELS
            or not all(
                isinstance(key, str)
                and isinstance(value, str)
                and len(key) <= 128
                and len(value) <= 1024
                for key, value in labels.items()
            )
            or not isinstance(values, list)
        ):
            raise LokiResponseError("Malformed Loki stream labels or entries.")
        if any(labels.get(key) != value for key, value in scope.labels.items()):
            raise LokiResponseError("Loki returned a stream outside the authorized selector.")
        for value in values:
            if (
                not isinstance(value, list)
                or len(value) != 2
                or not isinstance(value[0], str)
                or not value[0].isascii()
                or not value[0].isdecimal()
                or len(value[0]) > 20
                or not isinstance(value[1], str)
                or len(value[1]) > MAX_LOG_LINE_LENGTH
            ):
                raise LokiResponseError("Malformed or oversized Loki log entry.")
            timestamp_ns = int(value[0])
            if not start_ns <= timestamp_ns < end_ns:
                raise LokiResponseError("Loki returned a log outside the requested window.")
            entries.append(
                LokiLogEntry(
                    timestamp_ns=timestamp_ns,
                    line=value[1],
                    labels=MappingProxyType(dict(labels)),
                )
            )
            if len(entries) > limit:
                raise LokiResponseError("Loki returned more entries than requested.")
    entries.sort(
        key=lambda item: (item.timestamp_ns, sorted(item.labels.items()), item.line),
        reverse=True,
    )
    return LokiLogBatch(entries=tuple(entries), limit_reached=len(entries) == limit)


class LokiReadClient:
    """Read a fixed Loki endpoint using an injected, lifecycle-managed HTTP client.

    Authentication, URL allowlisting, and trusted scope resolution belong to
    the composition root/MCP authorization boundary. There is deliberately no
    generic query API and no HTTP POST/redirect handling.
    """

    def __init__(self, http_client: httpx.AsyncClient) -> None:
        if http_client.base_url.scheme not in ("http", "https") or not http_client.base_url.host:
            raise ValueError("Loki HTTP client requires a configured trusted base URL.")
        if "X-Scope-OrgID" in http_client.headers:
            raise ValueError("Loki tenant header must be scoped per authorized request.")
        self._http = http_client

    async def query_logs(
        self,
        *,
        scope: LokiLogScope,
        start: datetime,
        end: datetime,
        limit: int = 100,
    ) -> LokiLogBatch:
        """Fetch logs from Loki without accepting raw LogQL or user-provided URLs."""
        start_ns, end_ns = _validate_window(start, end, limit)
        headers = {"X-Scope-OrgID": scope.tenant_id} if scope.tenant_id else None
        params = {
            "query": _query_selector(scope),
            "start": str(start_ns),
            "end": str(end_ns),
            "limit": str(limit),
            "direction": "backward",
        }
        try:
            async with self._http.stream(
                "GET",
                "/loki/api/v1/query_range",
                params=params,
                headers=headers,
                follow_redirects=False,
            ) as response:
                if response.status_code in (408, 429, 500, 502, 503, 504):
                    raise LokiTransientError("Loki read temporarily unavailable.")
                if response.status_code != 200:
                    raise LokiQueryError("Loki read was rejected or returned an HTTP error.")
                body = bytearray()
                async for chunk in response.aiter_bytes():
                    if len(body) + len(chunk) > MAX_RESPONSE_BYTES:
                        raise LokiResponseError("Loki response exceeds the configured byte limit.")
                    body.extend(chunk)
        except (
            httpx.TimeoutException,
            httpx.ConnectError,
            httpx.ReadError,
            httpx.RemoteProtocolError,
        ):
            raise LokiTransientError("Loki transport temporarily unavailable.") from None
        except httpx.RequestError:
            raise LokiQueryError("Loki HTTP client configuration or request failed.") from None
        return _decode_loki_response(
            bytes(body), scope=scope, start_ns=start_ns, end_ns=end_ns, limit=limit
        )
