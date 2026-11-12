"""Check whether a persisted human approval matches a current remediation step.

A successful check is not an execution claim or permission to invoke MCP.
"""

from dataclasses import dataclass
from uuid import UUID

from ai_incident_commander.application.action_fingerprint import create_action_fingerprint
from ai_incident_commander.application.approval_repository import ApprovalRepository
from ai_incident_commander.application.remediation_preflight import (
    validate_remediation_preflight,
)
from ai_incident_commander.application.target_resolver import TargetResolver
from ai_incident_commander.domain.action_catalog import ActionCatalog
from ai_incident_commander.domain.approval_decision_rules import (
    ApprovalDecisionOutsideWindowError,
    ApprovalDecisionRequestMismatchError,
    validate_approval_decision_for_request,
)
from ai_incident_commander.domain.remediation import RemediationStep
from ai_incident_commander.domain.remediation_approval import RemediationApprovalOutcome


class ApprovalExecutionDeniedError(ValueError):
    """The persisted approval does not authorize the proposed action scope."""


class ApprovalExecutionScopeMismatchError(ApprovalExecutionDeniedError):
    """The proposed action differs from the scope recorded for approval."""


@dataclass(frozen=True, slots=True, kw_only=True)
class VerifiedExecutionScope:
    """Scope verified against trusted preflight and persisted approval.

    This is not an execution token; only claim_once() may reserve execution.
    """

    request_id: UUID
    plan_id: UUID
    step_id: UUID
    action_fingerprint: str
    policy_version: str


class ApprovalExecutionGuard:
    """Validate approval eligibility; do not reserve or perform execution."""

    def __init__(
        self,
        *,
        repository: ApprovalRepository,
        catalog: ActionCatalog,
        resolver: TargetResolver,
    ) -> None:
        self._repository = repository
        self._catalog = catalog
        self._resolver = resolver

    async def validate_for_step(self, *, request_id: UUID, step: RemediationStep) -> None:
        """Retain the existing validation-only API (returns None on success)."""
        await self.verify_scope_for_step(request_id=request_id, step=step)

    async def verify_scope_for_step(
        self, *, request_id: UUID, step: RemediationStep
    ) -> VerifiedExecutionScope:
        """Return the freshly verified scope; never accept a caller-provided snapshot."""
        request = await self._repository.get_request(request_id)
        if request is None:
            raise ApprovalExecutionDeniedError("Approval request does not exist.")

        decision = await self._repository.get_decision(request_id)
        if decision is None:
            raise ApprovalExecutionDeniedError("Approval decision does not exist.")
        if decision.outcome is not RemediationApprovalOutcome.APPROVED:
            raise ApprovalExecutionDeniedError("Remediation has not been approved.")

        try:
            validate_approval_decision_for_request(request, decision)
        except (
            ApprovalDecisionRequestMismatchError,
            ApprovalDecisionOutsideWindowError,
        ) as exc:
            raise ApprovalExecutionDeniedError(
                "Persisted approval decision is inconsistent."
            ) from exc

        if request.plan_id != step.plan_id or request.step_id != step.step_id:
            raise ApprovalExecutionScopeMismatchError("Remediation step identity differs.")

        # Re-run trusted checks: do not accept a caller-provided preflight snapshot.
        preflight = await validate_remediation_preflight(step, self._catalog, self._resolver)
        if preflight.policy_version != request.policy_version:
            raise ApprovalExecutionScopeMismatchError("Action policy version has changed.")
        fingerprint = create_action_fingerprint(step, preflight)
        if fingerprint != request.action_fingerprint:
            raise ApprovalExecutionScopeMismatchError("Remediation action fingerprint has changed.")

        return VerifiedExecutionScope(
            request_id=request.request_id,
            plan_id=step.plan_id,
            step_id=step.step_id,
            action_fingerprint=fingerprint,
            policy_version=request.policy_version,
        )
