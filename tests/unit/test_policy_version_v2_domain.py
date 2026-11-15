"""Policy-version format compatibility at approval and claim domain boundaries.

These tests assert structural validation only; they do not authorize MCP calls.
"""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from ai_incident_commander.domain.execution_claim import ExecutionClaim
from ai_incident_commander.domain.remediation_approval import RemediationApprovalRequest

_FINGERPRINT = "afp:v2:" + "a" * 64
_NOW = datetime(2026, 11, 15, tzinfo=UTC)


def _approval_request(policy_version: object) -> RemediationApprovalRequest:
    return RemediationApprovalRequest(
        plan_id=uuid4(),
        step_id=uuid4(),
        action_fingerprint=_FINGERPRINT,
        policy_version=policy_version,  # type: ignore[arg-type]
        requested_at=_NOW,
        expires_at=_NOW + timedelta(minutes=30),
    )


def _execution_claim(policy_version: object) -> ExecutionClaim:
    return ExecutionClaim(
        plan_id=uuid4(),
        step_id=uuid4(),
        request_id=uuid4(),
        action_fingerprint=_FINGERPRINT,
        policy_version=policy_version,  # type: ignore[arg-type]
        claimed_at=_NOW,
    )


@pytest.mark.parametrize(
    "factory", (_approval_request, _execution_claim), ids=("approval", "claim")
)
@pytest.mark.parametrize("version", ("v1", "v2"))
def test_policy_version_accepts_exact_supported_formats(factory, version: str) -> None:
    policy_version = f"apv:{version}:" + "a" * 64
    model = factory(policy_version)
    assert model.policy_version == policy_version


@pytest.mark.parametrize(
    "factory", (_approval_request, _execution_claim), ids=("approval", "claim")
)
@pytest.mark.parametrize(
    "invalid",
    (
        "apv:v3:" + "a" * 64,
        "APV:v2:" + "a" * 64,
        "apv:v2:" + "A" * 64,
        "apv:v2:" + "g" * 64,
        "apv:v2:" + "a" * 63,
        "apv:v2:" + "a" * 65,
        "apv:v2:" + "a" * 64 + "\n",
        "v2:" + "a" * 64,
        "",
        None,
        123,
    ),
    ids=(
        "unsupported-version",
        "uppercase-prefix",
        "uppercase-digest",
        "nonhex-digest",
        "short-digest",
        "long-digest",
        "trailing-newline",
        "missing-prefix",
        "empty",
        "none",
        "non-string",
    ),
)
def test_policy_version_rejects_malformed_values(factory, invalid: object) -> None:
    with pytest.raises(ValueError, match="requires a valid policy version"):
        factory(invalid)
