"""Tests for the system UTC clock adapter."""

from datetime import UTC, datetime, timedelta
from unittest.mock import patch

from ai_incident_commander.application.clock import Clock
from ai_incident_commander.infrastructure.system_clock import SystemClock


def test_system_clock_implements_clock_port() -> None:
    """SystemClock must satisfy the application Clock protocol."""
    clock: Clock = SystemClock()

    result = clock.now()

    assert isinstance(result, datetime)


def test_system_clock_returns_timezone_aware_utc() -> None:
    """The real clock must return an aware datetime in UTC."""
    result = SystemClock().now()

    assert result.tzinfo is UTC
    assert result.utcoffset() == timedelta(0)


def test_system_clock_reads_current_time_using_utc() -> None:
    """Verify the clock source without depending on wall-clock timing."""
    expected = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)

    with patch("ai_incident_commander.infrastructure.system_clock.datetime") as datetime_mock:
        datetime_mock.now.return_value = expected

        result = SystemClock().now()

    datetime_mock.now.assert_called_once_with(UTC)
    assert result is expected
