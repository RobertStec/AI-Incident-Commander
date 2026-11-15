"""Create persisted approval requests from trusted remediation preflight checks."""

from datetime import datetime, timedelta

from ai_incident_commander.application.action_fingerprint import (
    ActionFingerprintInputMismatchError,
    create_action_fingerprint,
)
from ai_incident_commander.application.approval_repository import ApprovalRepository
from ai_incident_commander.application.clock import Clock
from ai_incident_commander.application.remediation_preflight import (
    validate_mcp_bound_remediation_preflight,
    validate_remediation_preflight,
)
from ai_incident_commander.application.target_resolver import TargetResolver
from ai_incident_commander.domain.action_catalog import ActionCatalog
from ai_incident_commander.domain.mcp_action_binding import TrustedMcpActionBindings
from ai_incident_commander.domain.remediation import RemediationStep
from ai_incident_commander.domain.remediation_approval import RemediationApprovalRequest


class ApprovalRequestConfigurationError(ValueError):
    """Raised when approval creation configuration is invalid or incomplete."""


class ApprovalRequestClockError(ValueError):
    """Raised when the clock cannot provide a usable UTC approval window."""


class ApprovalRequestCreationService:
    """Persist an approval request using trusted, configuration-selected preflight.

    With MCP bindings the service requires apv:v2 for all creation methods.
    Without bindings create_for_step retains the legacy apv:v1 behavior;
    create_mcp_bound_for_step always refuses unconfigured legacy service.
    Neither an approval request nor its fingerprint is an MCP capability.
    """

    def __init__(
        self,
        *,
        repository: ApprovalRepository,
        clock: Clock,
        catalog: ActionCatalog,
        resolver: TargetResolver,
        validity_period: timedelta,
        mcp_bindings: TrustedMcpActionBindings | None = None,
    ) -> None:
        if not isinstance(validity_period, timedelta) or validity_period <= timedelta(0):
            raise ApprovalRequestConfigurationError(
                "Approval request validity_period must be a positive timedelta."
            )
        if mcp_bindings is not None:
            if not isinstance(mcp_bindings, TrustedMcpActionBindings):
                raise TypeError("MCP-bound approval creation requires trusted action bindings.")
            if mcp_bindings.catalog != catalog:
                raise ApprovalRequestConfigurationError(
                    "MCP bindings do not match the approval request action catalog."
                )

        self._repository = repository
        self._clock = clock
        self._catalog = catalog
        self._resolver = resolver
        self._validity_period = validity_period
        self._mcp_bindings = mcp_bindings

    async def create_mcp_bound_for_step(self, step: RemediationStep) -> RemediationApprovalRequest:
        """Require trusted MCP bindings; never fall back to legacy apv:v1."""
        if self._mcp_bindings is None:
            raise ApprovalRequestConfigurationError(
                "MCP-bound approval creation requires trusted action bindings."
            )
        return await self.create_for_step(step)

    async def create_for_step(self, step: RemediationStep) -> RemediationApprovalRequest:
        """Create a request after preflight for the configured policy mode."""
        if self._mcp_bindings is None:
            preflight = await validate_remediation_preflight(
                step,
                self._catalog,
                self._resolver,
            )
        else:
            preflight = await validate_mcp_bound_remediation_preflight(
                step,
                self._catalog,
                self._resolver,
                bindings=self._mcp_bindings,
            )
        fingerprint = create_action_fingerprint(step, preflight)

        policy_version = preflight.policy_version
        if policy_version is None:
            raise ActionFingerprintInputMismatchError(
                "Remediation preflight result has no trusted policy version."
            )

        # Read the application clock only after the asynchronous preflight finishes.
        requested_at = self._clock.now()
        if not isinstance(requested_at, datetime) or requested_at.utcoffset() != timedelta(0):
            raise ApprovalRequestClockError(
                "Approval request clock must return a timezone-aware UTC datetime."
            )

        try:
            expires_at = requested_at + self._validity_period
        except OverflowError as exc:
            raise ApprovalRequestClockError(
                "Approval request validity window is out of range."
            ) from exc

        request = RemediationApprovalRequest(
            plan_id=step.plan_id,
            step_id=step.step_id,
            action_fingerprint=fingerprint,
            policy_version=policy_version,
            requested_at=requested_at,
            expires_at=expires_at,
        )
        await self._repository.create_request(request)
        return request
