"""Create durable remediation execution claim table.

Revision ID: f4d2a6b8c901
Revises: c9d851ac39cb
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "f4d2a6b8c901"
down_revision: str | None = "c9d851ac39cb"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create a one-time execution reservation per step and approval request."""
    op.create_table(
        "remediation_execution_claims",
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


def downgrade() -> None:
    """Remove execution claims without changing historical approval records."""
    op.drop_table("remediation_execution_claims")
