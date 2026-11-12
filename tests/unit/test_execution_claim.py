"""Unit tests for the immutable remediation execution claim model."""

from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta, timezone
from typing import Any
from uuid import UUID, uuid4

import pytest

from ai_incident_commander.domain.execution_claim import ExecutionClaim

_CLAIMED_AT = datetime(2026, 11, 12, 16, 0, tzinfo=UTC)
_FINGERPRINT = "afp:v2:" + "a" * 64
_POLICY_VERSION = "apv:v1:" + "b" * 64


def _make_claim(**overrides: Any) -> ExecutionClaim:
    values = {
        "plan_id": uuid4(),
        "step_id": uuid4(),
        "request_id": uuid4(),
        "action_fingerprint": _FINGERPRINT,
        "policy_version": _POLICY_VERSION,
        "claimed_at": _CLAIMED_AT,
    }
    values.update(overrides)
    return ExecutionClaim(**values)


def test_claim_preserves_approved_scope_and_generates_identifier() -> None:
    claim = _make_claim()

    assert isinstance(claim.claim_id, UUID)
    assert isinstance(claim.plan_id, UUID)
    assert isinstance(claim.step_id, UUID)
    assert isinstance(claim.request_id, UUID)
    assert claim.action_fingerprint == _FINGERPRINT
    assert claim.policy_version == _POLICY_VERSION
    assert claim.claimed_at == _CLAIMED_AT


def test_claim_accepts_explicit_id_for_database_reconstruction() -> None:
    claim_id = uuid4()
    claim = _make_claim(claim_id=claim_id)

    assert claim.claim_id == claim_id


def test_claim_is_immutable() -> None:
    claim = _make_claim()

    with pytest.raises(FrozenInstanceError):
        claim.request_id = uuid4()  # type: ignore[misc]


@pytest.mark.parametrize("field_name", ["claim_id", "plan_id", "step_id", "request_id"])
def test_claim_rejects_non_uuid_identifiers(field_name: str) -> None:
    with pytest.raises(ValueError, match=field_name):
        _make_claim(**{field_name: "not-a-uuid"})


@pytest.mark.parametrize(
    "bad_value",
    ["", "afp:v1:" + "a" * 64, "afp:v2:" + "G" * 64, None],
)
def test_claim_rejects_invalid_fingerprint(bad_value: object) -> None:
    with pytest.raises(ValueError, match="action fingerprint"):
        _make_claim(action_fingerprint=bad_value)


@pytest.mark.parametrize(
    "bad_value",
    ["", "apv:v2:" + "b" * 64, "apv:v1:" + "G" * 64, None],
)
def test_claim_rejects_invalid_policy_version(bad_value: object) -> None:
    with pytest.raises(ValueError, match="policy version"):
        _make_claim(policy_version=bad_value)


@pytest.mark.parametrize(
    "bad_value",
    [
        datetime(2026, 11, 12, 16, 0),
        datetime(2026, 11, 12, 16, 0, tzinfo=timezone(timedelta(hours=1))),
        None,
    ],
)
def test_claim_requires_utc_timestamp(bad_value: object) -> None:
    with pytest.raises(ValueError, match="claimed_at must use UTC"):
        _make_claim(claimed_at=bad_value)


def test_claim_can_be_reconstructed_with_utc_zero_offset() -> None:
    claim = _make_claim(claimed_at=datetime(2026, 11, 12, 16, tzinfo=UTC))

    assert claim.claimed_at.utcoffset() == timedelta(0)
