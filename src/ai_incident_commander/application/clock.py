"""Application port for accessing the current trusted UTC time."""

from datetime import datetime
from typing import Protocol


class Clock(Protocol):
    """Provide the current UTC time to application services."""

    def now(self) -> datetime:
        """Return a timezone-aware datetime with a zero UTC offset."""
        ...
