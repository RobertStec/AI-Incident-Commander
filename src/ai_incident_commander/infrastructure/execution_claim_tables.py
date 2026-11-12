"""SQLAlchemy Core table for durable remediation execution claims."""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from ai_incident_commander.infrastructure.approval_tables import approval_metadata

execution_claims_table = sa.Table(
    "remediation_execution_claims",
    approval_metadata,
    sa.Column("claim_id", postgresql.UUID(as_uuid=True), nullable=False),
    sa.Column("plan_id", postgresql.UUID(as_uuid=True), nullable=False),
    sa.Column("step_id", postgresql.UUID(as_uuid=True), nullable=False),
    sa.Column("request_id", postgresql.UUID(as_uuid=True), nullable=False),
    sa.Column("action_fingerprint", sa.Text(), nullable=False),
    sa.Column("policy_version", sa.Text(), nullable=False),
    sa.Column("claimed_at", sa.DateTime(timezone=True), nullable=False),
    sa.PrimaryKeyConstraint("claim_id", name="pk_execution_claims"),
    sa.ForeignKeyConstraint(
        ["request_id"],
        ["remediation_approval_requests.request_id"],
        name="fk_execution_claims_request_id",
        ondelete="RESTRICT",
    ),
    sa.UniqueConstraint("plan_id", "step_id", name="uq_execution_claims_plan_step"),
    sa.UniqueConstraint("request_id", name="uq_execution_claims_request_id"),
    sa.CheckConstraint(
        "action_fingerprint ~ '^afp:v2:[0-9a-f]{64}$'",
        name="ck_execution_claims_fingerprint",
    ),
    sa.CheckConstraint(
        "policy_version ~ '^apv:v1:[0-9a-f]{64}$'",
        name="ck_execution_claims_policy_version",
    ),
)
