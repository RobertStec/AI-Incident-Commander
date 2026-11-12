"""Create persisted approval requests from trusted remediation preflight checks."""

from datetime import datetime, timedelta

from ai_incident_commander.application.action_fingerprint import (
    ActionFingerprintInputMismatchError,
    create_action_fingerprint,
)
from ai_incident_commander.application.approval_repository import ApprovalRepository
from ai_incident_commander.application.clock import Clock
from ai_incident_commander.application.remediation_preflight import (
    validate_remediation_preflight,
)
from ai_incident_commander.application.target_resolver import TargetResolver
from ai_incident_commander.domain.action_catalog import ActionCatalog
from ai_incident_commander.domain.remediation import RemediationStep
from ai_incident_commander.domain.remediation_approval import RemediationApprovalRequest


class ApprovalRequestConfigurationError(ValueError):
    """Raised when the configured approval request validity period is invalid."""


class ApprovalRequestClockError(ValueError):
    """Raised when the clock cannot provide a usable UTC approval window."""


class ApprovalRequestCreationService:
    """Preflight a remediation step, fingerprint it, and persist an approval request."""

    def __init__(
        self,
        *,
        repository: ApprovalRepository,
        clock: Clock,
        catalog: ActionCatalog,
        resolver: TargetResolver,
        validity_period: timedelta,
    ) -> None:
        if not isinstance(validity_period, timedelta) or validity_period <= timedelta(0):
            raise ApprovalRequestConfigurationError(
                "Approval request validity_period must be a positive timedelta."
            )

        self._repository = repository
        self._clock = clock
        self._catalog = catalog
        self._resolver = resolver
        self._validity_period = validity_period

    async def create_for_step(self, step: RemediationStep) -> RemediationApprovalRequest:
        """Create a request only after trusted preflight and fingerprint validation."""
        preflight = await validate_remediation_preflight(
            step,
            self._catalog,
            self._resolver,
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
