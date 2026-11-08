"""Application preflight checks for proposed remediation actions."""

from dataclasses import dataclass, field

from ai_incident_commander.application.target_resolver import TargetResolver
from ai_incident_commander.application.target_verification import (
    verify_remediation_target,
)
from ai_incident_commander.domain.action_catalog import (
    ActionCatalog,
    ActionDefinition,
    validate_remediation_step,
)
from ai_incident_commander.domain.remediation import RemediationStep
from ai_incident_commander.domain.target_identity import ResolvedTarget


@dataclass(frozen=True, slots=True, kw_only=True)
class RemediationPreflightResult:
    """Validated action and target; not an execution authorization."""

    action: ActionDefinition
    target: ResolvedTarget
    step_snapshot: RemediationStep | None = field(
        default=None,
        repr=False,
        compare=False,
    )


async def validate_remediation_preflight(
    step: RemediationStep,
    catalog: ActionCatalog,
    resolver: TargetResolver,
) -> RemediationPreflightResult:
    """Validate an action before resolving its authoritative target."""
    definition = validate_remediation_step(step, catalog)

    resolved_target = await verify_remediation_target(
        step,
        resolver,
    )

    return RemediationPreflightResult(
        action=definition,
        target=resolved_target,
        step_snapshot=step,
    )
