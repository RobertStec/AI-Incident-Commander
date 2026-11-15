"""Check whether a persisted human approval matches a current remediation step.

A successful check is not an execution claim or permission to invoke MCP.
"""

from dataclasses import dataclass
from uuid import UUID

from ai_incident_commander.application.action_fingerprint import create_action_fingerprint
from ai_incident_commander.application.approval_repository import ApprovalRepository
from ai_incident_commander.application.remediation_preflight import (
    validate_mcp_bound_remediation_preflight,
    validate_remediation_preflight,
)
from ai_incident_commander.application.target_resolver import TargetResolver
from ai_incident_commander.domain.action_catalog import ActionCatalog
from ai_incident_commander.domain.approval_decision_rules import (
    ApprovalDecisionOutsideWindowError,
    ApprovalDecisionRequestMismatchError,
    validate_approval_decision_for_request,
)
from ai_incident_commander.domain.mcp_action_binding import TrustedMcpActionBindings
from ai_incident_commander.domain.remediation import RemediationStep
from ai_incident_commander.domain.remediation_approval import RemediationApprovalOutcome
from ai_incident_commander.domain.target_identity import ResolvedTarget


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


@dataclass(frozen=True, slots=True, kw_only=True)
class VerifiedExecutionContext:
    """Approved scope and resolved identity from the SAME trusted preflight.

    This is not an MCP authorization, retry permit, or durable dispatch token.
    A trusted application service must still validate execution eligibility.
    """

    scope: VerifiedExecutionScope
    target: ResolvedTarget


class ApprovalExecutionGuard:
    """Validate approval eligibility; do not reserve or perform execution."""

    def __init__(
        self,
        *,
        repository: ApprovalRepository,
        catalog: ActionCatalog,
        resolver: TargetResolver,
        mcp_bindings: TrustedMcpActionBindings | None = None,
    ) -> None:
        if mcp_bindings is not None:
            if not isinstance(mcp_bindings, TrustedMcpActionBindings):
                raise TypeError("MCP-bound Guard requires trusted action bindings.")
            if mcp_bindings.catalog != catalog:
                raise ValueError("MCP bindings do not match the Guard action catalog.")

        self._repository = repository
        self._catalog = catalog
        self._resolver = resolver
        self._mcp_bindings = mcp_bindings

    async def validate_for_step(self, *, request_id: UUID, step: RemediationStep) -> None:
        """Retain the existing validation-only API (returns None on success)."""
        await self.verify_scope_for_step(request_id=request_id, step=step)

    async def verify_scope_for_step(
        self, *, request_id: UUID, step: RemediationStep
    ) -> VerifiedExecutionScope:
        """Preserve the scope-only API for existing claim/recovery callers."""
        context = await self.verify_execution_context_for_step(request_id=request_id, step=step)
        return context.scope

    async def verify_mcp_execution_context_for_step(
        self, *, request_id: UUID, step: RemediationStep
    ) -> VerifiedExecutionContext:
        """Require an MCP-configured Guard; never fall back to legacy policy.

        This validates approval but does not grant permission to call MCP.
        """
        if self._mcp_bindings is None:
            raise ApprovalExecutionDeniedError("MCP-bound Guard configuration is required.")
        return await self.verify_execution_context_for_step(request_id=request_id, step=step)

    async def verify_execution_context_for_step(
        self, *, request_id: UUID, step: RemediationStep
    ) -> VerifiedExecutionContext:
        """Verify approval and target using the Guard's configured policy mode.

        With MCP bindings, enforce apv:v2 and run a fresh MCP-bound preflight.
        Without bindings, preserve legacy non-MCP validation during migration.
        Neither mode authorizes MCP execution or a retry after EXECUTING.
        """
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

        # The configured Guard mode is trusted application configuration, not a
        # caller-selected policy version. A bound Guard never falls back to v1.
        if self._mcp_bindings is not None:
            if not request.policy_version.startswith("apv:v2:"):
                raise ApprovalExecutionScopeMismatchError(
                    "MCP-bound remediation requires an apv:v2 approval."
                )
            preflight = await validate_mcp_bound_remediation_preflight(
                step, self._catalog, self._resolver, bindings=self._mcp_bindings
            )
        else:
            # Retained only for existing non-MCP callers during migration.
            preflight = await validate_remediation_preflight(step, self._catalog, self._resolver)
        if preflight.policy_version != request.policy_version:
            raise ApprovalExecutionScopeMismatchError("Action policy version has changed.")
        fingerprint = create_action_fingerprint(step, preflight)
        if fingerprint != request.action_fingerprint:
            raise ApprovalExecutionScopeMismatchError("Remediation action fingerprint has changed.")

        return VerifiedExecutionContext(
            scope=VerifiedExecutionScope(
                request_id=request.request_id,
                plan_id=step.plan_id,
                step_id=step.step_id,
                action_fingerprint=fingerprint,
                policy_version=request.policy_version,
            ),
            target=preflight.target,
        )
