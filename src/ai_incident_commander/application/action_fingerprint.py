"""Deterministic fingerprints for proposed remediation actions."""

from hashlib import sha256
from json import dumps
from re import fullmatch

from ai_incident_commander.application.remediation_preflight import (
    RemediationPreflightResult,
)
from ai_incident_commander.domain.remediation import RemediationStep

_FINGERPRINT_DOMAIN = b"ai-incident-commander:remediation-action:v2\x00"


class ActionFingerprintInputMismatchError(ValueError):
    """Raised when step and preflight describe different action contexts."""


def _canonical_json_bytes(value: object) -> bytes:
    """Serialize data deterministically without coercing scalar types."""
    return dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def create_action_fingerprint(
    step: RemediationStep,
    preflight: RemediationPreflightResult,
) -> str:
    """Fingerprint the exact action scope for a future approval."""

    snapshot = preflight.step_snapshot

    if snapshot is None:
        raise ActionFingerprintInputMismatchError(
            "Remediation preflight result has no validated step snapshot."
        )

    if (
        step.plan_id != snapshot.plan_id
        or step.step_id != snapshot.step_id
        or step.position != snapshot.position
        or step.action_name != snapshot.action_name
        or step.risk_level is not snapshot.risk_level
        or step.target != snapshot.target
        or step.environment != snapshot.environment
        or _canonical_json_bytes(dict(step.parameters))
        != _canonical_json_bytes(dict(snapshot.parameters))
    ):
        raise ActionFingerprintInputMismatchError(
            "Remediation step differs from the validated preflight snapshot."
        )

    if (
        step.action_name != preflight.action.action_name
        or step.risk_level is not preflight.action.risk_level
        or step.environment not in preflight.action.allowed_environments
        or step.target != preflight.target.target
        or step.environment != preflight.target.environment
    ):
        raise ActionFingerprintInputMismatchError(
            "Remediation step and preflight result are inconsistent."
        )

    policy_version = preflight.policy_version

    if (
        not isinstance(policy_version, str)
        or fullmatch(r"apv:v1:[0-9a-f]{64}", policy_version) is None
    ):
        raise ActionFingerprintInputMismatchError(
            "Remediation preflight result has no valid trusted policy version."
        )

    payload = {
        "version": 2,
        "policy_version": policy_version,
        "plan_id": str(step.plan_id),
        "step_id": str(step.step_id),
        "position": step.position,
        "action": {
            "name": preflight.action.action_name,
            "effect": preflight.action.effect.value,
            "risk_level": preflight.action.risk_level.value,
        },
        "target": {
            "name": preflight.target.target,
            "resource_id": preflight.target.resource_id,
            "environment": preflight.target.environment,
            "source": preflight.target.source,
        },
        "parameters": dict(step.parameters),
    }

    canonical_bytes = _canonical_json_bytes(payload)

    digest = sha256(_FINGERPRINT_DOMAIN + canonical_bytes).hexdigest()

    return f"afp:v2:{digest}"
