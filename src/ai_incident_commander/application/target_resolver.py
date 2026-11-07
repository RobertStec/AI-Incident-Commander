"""Application port for authoritative remediation target resolution."""

from typing import Protocol

from ai_incident_commander.domain.target_identity import ResolvedTarget


class TargetResolutionError(Exception):
    """Base error for unsuccessful target resolution."""


class TargetNotFoundError(TargetResolutionError):
    """Raised when the requested target cannot be found."""


class AmbiguousTargetError(TargetResolutionError):
    """Raised when the requested target is not uniquely identifiable."""


class TargetSourceUnavailableError(TargetResolutionError):
    """Raised when the authoritative inventory cannot be queried."""


class TargetResolver(Protocol):
    """Resolve remediation targets using an authoritative inventory."""

    async def resolve(
        self,
        *,
        target: str,
        environment: str,
    ) -> ResolvedTarget:
        """Return the unique canonical identity for the requested target."""
        ...
