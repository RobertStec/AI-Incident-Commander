"""SQLAlchemy Core definitions for remediation approval tables."""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

approval_metadata = sa.MetaData()

approval_requests_table = sa.Table(
    "remediation_approval_requests",
    approval_metadata,
    sa.Column("request_id", postgresql.UUID(as_uuid=True), nullable=False),
    sa.Column("plan_id", postgresql.UUID(as_uuid=True), nullable=False),
    sa.Column("step_id", postgresql.UUID(as_uuid=True), nullable=False),
    sa.Column("action_fingerprint", sa.Text(), nullable=False),
    sa.Column("policy_version", sa.Text(), nullable=False),
    sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
    sa.PrimaryKeyConstraint("request_id", name="pk_approval_requests"),
    sa.CheckConstraint(
        "action_fingerprint ~ '^afp:v2:[0-9a-f]{64}$'",
        name="ck_approval_request_fingerprint",
    ),
    sa.CheckConstraint(
        "policy_version ~ '^apv:v1:[0-9a-f]{64}$'",
        name="ck_approval_request_policy_version",
    ),
    sa.CheckConstraint(
        "expires_at > requested_at",
        name="ck_approval_request_time_window",
    ),
)

approval_decisions_table = sa.Table(
    "remediation_approval_decisions",
    approval_metadata,
    sa.Column("decision_id", postgresql.UUID(as_uuid=True), nullable=False),
    sa.Column("request_id", postgresql.UUID(as_uuid=True), nullable=False),
    sa.Column("operator_id", sa.Text(), nullable=False),
    sa.Column("outcome", sa.Text(), nullable=False),
    sa.Column("decided_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("reason", sa.Text(), nullable=False),
    sa.PrimaryKeyConstraint("decision_id", name="pk_approval_decisions"),
    sa.ForeignKeyConstraint(
        ["request_id"],
        ["remediation_approval_requests.request_id"],
        name="fk_approval_decisions_request_id",
        ondelete="RESTRICT",
    ),
    sa.UniqueConstraint(
        "request_id",
        name="uq_approval_decisions_request_id",
    ),
    sa.CheckConstraint(
        "outcome IN ('approved', 'rejected')",
        name="ck_approval_decision_outcome",
    ),
    sa.CheckConstraint(
        "operator_id ~ '[^[:space:]]'",
        name="ck_approval_decision_operator_not_blank",
    ),
    sa.CheckConstraint(
        "reason ~ '[^[:space:]]'",
        name="ck_approval_decision_reason_not_blank",
    ),
)
