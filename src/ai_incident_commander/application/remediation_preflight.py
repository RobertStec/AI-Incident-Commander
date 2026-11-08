"""Application preflight checks for proposed remediation actions."""

from dataclasses import dataclass, field

from ai_incident_commander.application.action_policy_version import (
    create_action_policy_version,
)
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
    policy_version: str | None = None


async def validate_remediation_preflight(
    step: RemediationStep,
    catalog: ActionCatalog,
    resolver: TargetResolver,
) -> RemediationPreflightResult:
    """Validate an action and capture its trusted policy version."""
    definition = validate_remediation_step(step, catalog)

    policy_version = create_action_policy_version(catalog)

    resolved_target = await verify_remediation_target(
        step,
        resolver,
    )

    return RemediationPreflightResult(
        action=definition,
        target=resolved_target,
        step_snapshot=step,
        policy_version=policy_version,
    )
