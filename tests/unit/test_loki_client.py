"""Contract and security tests for the actual Loki HTTP read adapter."""

import asyncio
from datetime import UTC, datetime, timedelta
from json import dumps

import httpx
import pytest

from ai_incident_commander.infrastructure.loki_client import (
    MAX_RESPONSE_BYTES,
    LokiLogScope,
    LokiQueryError,
    LokiReadClient,
    LokiResponseError,
    LokiTransientError,
)

START = datetime(2026, 11, 19, 9, 0, tzinfo=UTC)
END = START + timedelta(minutes=30)
TIMESTAMP_NS = str(int(START.timestamp()) * 1_000_000_000)


def _response(*, values: list[list[str]] | None = None) -> dict[str, object]:
    return {
        "status": "success",
        "data": {
            "resultType": "streams",
            "result": [
                {
                    "stream": {"app": "orders", "environment": "prod"},
                    "values": values if values is not None else [[TIMESTAMP_NS, "http 500"]],
                }
            ],
        },
    }


def test_real_http_range_query_uses_trusted_selector_tenant_and_bounded_parameters() -> None:
    seen: list[httpx.Request] = []

    def respond(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        result = _response()
        data = result["data"]
        assert isinstance(data, dict)
        streams = data["result"]
        assert isinstance(streams, list)
        streams[0]["stream"]["app"] = 'orders"} |= "secret'
        return httpx.Response(200, json=result)

    async def run() -> None:
        async with httpx.AsyncClient(
            base_url="http://loki.internal:3100", transport=httpx.MockTransport(respond)
        ) as client:
            adapter = LokiReadClient(client)
            batch = await adapter.query_logs(
                scope=LokiLogScope(
                    labels={"app": 'orders"} |= "secret', "environment": "prod"},
                    tenant_id="tenant-A",
                ),
                start=START,
                end=END,
                limit=5,
            )
            assert len(batch.entries) == 1
            assert batch.entries[0].line == "http 500"
            assert batch.limit_reached is False

    asyncio.run(run())
    assert len(seen) == 1
    request = seen[0]
    assert request.method == "GET"
    assert request.url.path == "/loki/api/v1/query_range"
    assert request.headers["X-Scope-OrgID"] == "tenant-A"
    assert request.url.params["query"] == '{app="orders\\"} |= \\"secret",environment="prod"}'
    assert request.url.params["start"] == TIMESTAMP_NS
    assert request.url.params["end"] == str(int(END.timestamp()) * 1_000_000_000)
    assert request.url.params["limit"] == "5"


@pytest.mark.parametrize("status", [408, 429, 500, 502, 503, 504])
def test_transient_upstream_status_is_distinct_from_permanent_errors(status: int) -> None:
    async def run() -> None:
        async with httpx.AsyncClient(
            base_url="http://loki.internal",
            transport=httpx.MockTransport(lambda _: httpx.Response(status)),
        ) as client:
            with pytest.raises(LokiTransientError):
                await LokiReadClient(client).query_logs(
                    scope=LokiLogScope(labels={"app": "orders"}), start=START, end=END
                )

    asyncio.run(run())


@pytest.mark.parametrize("status", [301, 400, 401, 403, 404])
def test_auth_denial_and_redirect_are_not_retried(status: int) -> None:
    async def run() -> None:
        async with httpx.AsyncClient(
            base_url="http://loki.internal",
            follow_redirects=True,
            transport=httpx.MockTransport(
                lambda _: httpx.Response(status, headers={"Location": "http://evil.example"})
            ),
        ) as client:
            with pytest.raises(LokiQueryError):
                await LokiReadClient(client).query_logs(
                    scope=LokiLogScope(labels={"app": "orders"}), start=START, end=END
                )

    asyncio.run(run())


def test_query_scope_is_immutable_and_rejects_broad_invalid_scope() -> None:
    with pytest.raises(ValueError):
        LokiLogScope(labels={})
    with pytest.raises(ValueError):
        LokiLogScope(labels={"app": "orders"}, tenant_id="tenant-1|tenant-2")
    with pytest.raises(ValueError):
        LokiLogScope(labels={"app": ""})
    labels = {"app": "orders"}
    scope = LokiLogScope(labels=labels)
    labels["app"] = "attacker"
    assert scope.labels["app"] == "orders"
    with pytest.raises(TypeError):
        scope.labels["app"] = "attacker"  # type: ignore[index]


@pytest.mark.parametrize(
    "start,end,limit",
    [
        (START, START, 1),
        (START, END + timedelta(hours=2), 10),
        (START, END, 0),
        (START, END, 101),
        (START.replace(tzinfo=None), END, 1),
    ],
)
def test_invalid_window_or_limit_fails_before_network(
    start: datetime, end: datetime, limit: int
) -> None:
    def never_called(_: httpx.Request) -> httpx.Response:
        raise AssertionError("Invalid arguments must not reach Loki")

    async def run() -> None:
        async with httpx.AsyncClient(
            base_url="http://loki.internal", transport=httpx.MockTransport(never_called)
        ) as client:
            with pytest.raises(ValueError):
                await LokiReadClient(client).query_logs(
                    scope=LokiLogScope(labels={"app": "orders"}), start=start, end=end, limit=limit
                )

    asyncio.run(run())


@pytest.mark.parametrize(
    "payload",
    [
        b"not json",
        dumps({"status": "success", "data": {"resultType": "matrix", "result": []}}).encode(),
        dumps(_response(values=[[TIMESTAMP_NS, "x" * 8193]])).encode(),
        dumps(_response(values=[["1", "out of requested window"]])).encode(),
        dumps(_response(values=[[TIMESTAMP_NS, "ok"], [TIMESTAMP_NS, "extra"]])).encode(),
    ],
)
def test_malformed_or_out_of_bounds_response_fails_closed(payload: bytes) -> None:
    async def run() -> None:
        async with httpx.AsyncClient(
            base_url="http://loki.internal",
            transport=httpx.MockTransport(lambda _: httpx.Response(200, content=payload)),
        ) as client:
            with pytest.raises(LokiResponseError):
                await LokiReadClient(client).query_logs(
                    scope=LokiLogScope(labels={"app": "orders"}), start=START, end=END, limit=1
                )

    asyncio.run(run())


def test_unexpected_stream_selector_fails_closed() -> None:
    async def run() -> None:
        async with httpx.AsyncClient(
            base_url="http://loki.internal",
            transport=httpx.MockTransport(lambda _: httpx.Response(200, json=_response())),
        ) as client:
            with pytest.raises(LokiResponseError, match="outside the authorized selector"):
                await LokiReadClient(client).query_logs(
                    scope=LokiLogScope(labels={"app": "other-service"}),
                    start=START,
                    end=END,
                )

    asyncio.run(run())


def test_response_byte_cap_enforced_before_json_decode() -> None:
    async def run() -> None:
        async with httpx.AsyncClient(
            base_url="http://loki.internal",
            transport=httpx.MockTransport(
                lambda _: httpx.Response(200, content=b"x" * (MAX_RESPONSE_BYTES + 1))
            ),
        ) as client:
            with pytest.raises(LokiResponseError, match="byte limit"):
                await LokiReadClient(client).query_logs(
                    scope=LokiLogScope(labels={"app": "orders"}), start=START, end=END
                )

    asyncio.run(run())


def test_timeout_is_transient() -> None:
    def timeout(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("test timeout", request=request)

    async def run() -> None:
        async with httpx.AsyncClient(
            base_url="http://loki.internal", transport=httpx.MockTransport(timeout)
        ) as client:
            with pytest.raises(LokiTransientError):
                await LokiReadClient(client).query_logs(
                    scope=LokiLogScope(labels={"app": "orders"}), start=START, end=END
                )

    asyncio.run(run())


def test_shared_client_cannot_preconfigure_tenant_header() -> None:
    async def run() -> None:
        async with httpx.AsyncClient(
            base_url="http://loki.internal",
            headers={"X-Scope-OrgID": "tenant-A"},
            transport=httpx.MockTransport(lambda _: httpx.Response(200)),
        ) as client:
            with pytest.raises(ValueError, match="tenant header"):
                LokiReadClient(client)

    asyncio.run(run())
