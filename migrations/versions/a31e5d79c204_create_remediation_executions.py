"""Create durable remediation execution lifecycle table.

Revision ID: a31e5d79c204
Revises: f4d2a6b8c901
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "a31e5d79c204"
down_revision: str | None = "f4d2a6b8c901"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create at most one durable execution attempt per execution claim."""
    op.create_table(
        "remediation_executions",
        sa.Column("execution_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("claim_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status_changed_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("execution_id", name="pk_remediation_executions"),
        sa.ForeignKeyConstraint(
            ["claim_id"],
            ["remediation_execution_claims.claim_id"],
            name="fk_remediation_executions_claim_id",
            ondelete="RESTRICT",
        ),
        sa.UniqueConstraint("claim_id", name="uq_remediation_executions_claim_id"),
        sa.CheckConstraint(
            "status IN ('executing', 'succeeded', 'failed', 'unknown')",
            name="ck_remediation_executions_status",
        ),
        sa.CheckConstraint(
            "(status = 'executing' AND status_changed_at IS NULL) OR "
            "(status IN ('succeeded', 'failed', 'unknown') AND status_changed_at IS NOT NULL)",
            name="ck_remediation_executions_status_timestamp",
        ),
        sa.CheckConstraint(
            "status_changed_at IS NULL OR status_changed_at >= started_at",
            name="ck_remediation_executions_time_order",
        ),
    )


def downgrade() -> None:
    """Remove execution lifecycle rows without touching execution claims."""
    op.drop_table("remediation_executions")
