"""System clock adapter providing the current UTC time."""

from datetime import UTC, datetime


class SystemClock:
    """Read the current system time as a timezone-aware UTC datetime."""

    def now(self) -> datetime:
        """Return the current UTC time."""
        return datetime.now(UTC)
