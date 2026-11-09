"""Tests for the application clock port."""

import inspect
from datetime import UTC, datetime, timedelta

from ai_incident_commander.application.clock import Clock


class FakeClock:
    """Controllable clock for deterministic application tests."""

    def __init__(self, current_time: datetime) -> None:
        self.current_time = current_time

    def now(self) -> datetime:
        """Return the configured time without reading the system clock."""
        return self.current_time


def test_clock_accepts_structural_implementation() -> None:
    expected = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
    fake = FakeClock(expected)

    clock: Clock = fake

    assert clock.now() is expected


def test_clock_contract_is_synchronous() -> None:
    assert not inspect.iscoroutinefunction(Clock.now)
    assert not inspect.iscoroutinefunction(FakeClock.now)


def test_fake_clock_supports_deterministic_time_advancement() -> None:
    initial_time = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
    fake = FakeClock(initial_time)
    clock: Clock = fake

    assert clock.now() == initial_time

    fake.current_time += timedelta(minutes=15)

    assert clock.now() == initial_time + timedelta(minutes=15)
    assert clock.now().utcoffset() == timedelta(0)
