"""Create remediation approval tables.

Revision ID: c9d851ac39cb
Revises:
Create Date: 2026-11-10 13:47:12.162846
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "c9d851ac39cb"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create requests and their at-most-one decisions."""
    op.create_table(
        "remediation_approval_requests",
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

    op.create_table(
        "remediation_approval_decisions",
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


def downgrade() -> None:
    """Drop decisions before requests because of the foreign key."""
    op.drop_table("remediation_approval_decisions")
    op.drop_table("remediation_approval_requests")
