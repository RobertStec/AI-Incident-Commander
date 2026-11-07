"""Application service for verifying remediation target identity."""

from ai_incident_commander.application.target_resolver import (
    TargetResolutionError,
    TargetResolver,
)
from ai_incident_commander.domain.remediation import RemediationStep
from ai_incident_commander.domain.target_identity import ResolvedTarget


class TargetIdentityMismatchError(TargetResolutionError):
    """Raised when resolved identity conflicts with the proposed step."""


class InvalidResolvedTargetError(TargetResolutionError):
    """Raised when a resolver returns an invalid identity object."""


async def verify_remediation_target(
    step: RemediationStep,
    resolver: TargetResolver,
) -> ResolvedTarget:
    """Verify a proposed target against an authoritative inventory."""
    resolved = await resolver.resolve(
        target=step.target,
        environment=step.environment,
    )

    if not isinstance(resolved, ResolvedTarget):
        raise InvalidResolvedTargetError("Target resolver returned an invalid identity.")

    if resolved.target != step.target or resolved.environment != step.environment:
        raise TargetIdentityMismatchError(
            "Resolved target identity does not match the remediation step."
        )

    return resolved
