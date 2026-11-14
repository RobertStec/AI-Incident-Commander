"""Domain tests for a single durable remediation dispatch reservation."""

from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta, timezone
from uuid import UUID, uuid4

import pytest

from ai_incident_commander.domain.remediation_dispatch import RemediationDispatch

_RESERVED = datetime(2026, 11, 14, 12, 0, tzinfo=UTC)


def _new_dispatch() -> RemediationDispatch:
    return RemediationDispatch(execution_id=uuid4(), reserved_at=_RESERVED)


def test_dispatch_records_execution_identity_and_reservation_time() -> None:
    execution_id = uuid4()
    dispatch = RemediationDispatch(execution_id=execution_id, reserved_at=_RESERVED)

    assert dispatch.execution_id == execution_id
    assert isinstance(dispatch.dispatch_id, UUID)
    assert dispatch.reserved_at == _RESERVED


def test_dispatch_identifiers_are_distinct_by_default() -> None:
    first = _new_dispatch()
    second = _new_dispatch()

    assert first.dispatch_id != second.dispatch_id


def test_dispatch_can_be_rehydrated_with_persisted_identity_and_time() -> None:
    dispatch_id, execution_id = uuid4(), uuid4()

    dispatch = RemediationDispatch(
        dispatch_id=dispatch_id,
        execution_id=execution_id,
        reserved_at=_RESERVED,
    )

    assert dispatch.dispatch_id == dispatch_id
    assert dispatch.execution_id == execution_id
    assert dispatch.reserved_at == _RESERVED


def test_dispatch_snapshot_is_immutable() -> None:
    dispatch = _new_dispatch()

    with pytest.raises(FrozenInstanceError):
        dispatch.execution_id = uuid4()  # type: ignore[misc]


@pytest.mark.parametrize("field_name", ("dispatch_id", "execution_id"))
def test_dispatch_rejects_non_uuid_identifiers(field_name: str) -> None:
    fields: dict[str, object] = {"execution_id": uuid4(), "reserved_at": _RESERVED}
    fields[field_name] = "invalid"

    with pytest.raises(ValueError, match=f"{field_name} must be a UUID"):
        RemediationDispatch(**fields)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "invalid_time",
    (
        datetime(2026, 11, 14, 12, 0),
        datetime(2026, 11, 14, 13, 0, tzinfo=timezone(timedelta(hours=1))),
        datetime(2026, 11, 14, 8, 0, tzinfo=timezone(timedelta(hours=-4))),
        "2026-11-14T12:00:00Z",
        None,
    ),
)
def test_dispatch_rejects_invalid_reservation_timestamp(invalid_time: object) -> None:
    with pytest.raises(ValueError, match="reserved_at must use UTC"):
        RemediationDispatch(  # type: ignore[arg-type]
            execution_id=uuid4(), reserved_at=invalid_time
        )


def test_dispatch_accepts_explicit_utc_offset_zero() -> None:
    offset_zero = datetime(2026, 11, 14, 12, 0, tzinfo=timezone(timedelta(0)))
    dispatch = RemediationDispatch(execution_id=uuid4(), reserved_at=offset_zero)

    assert dispatch.reserved_at.utcoffset() == timedelta(0)


def test_rehydrated_snapshot_equals_original() -> None:
    original = _new_dispatch()
    rehydrated = RemediationDispatch(
        execution_id=original.execution_id,
        dispatch_id=original.dispatch_id,
        reserved_at=original.reserved_at,
    )

    assert rehydrated == original
