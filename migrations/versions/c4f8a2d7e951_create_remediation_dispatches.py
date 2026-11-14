"""Create durable remediation dispatch reservations.

Revision ID: c4f8a2d7e951
Revises: a31e5d79c204
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "c4f8a2d7e951"
down_revision: str | None = "a31e5d79c204"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Allow at most one durable dispatch reservation per execution attempt."""
    op.create_table(
        "remediation_dispatches",
        sa.Column("dispatch_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("execution_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("reserved_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("dispatch_id", name="pk_remediation_dispatches"),
        sa.ForeignKeyConstraint(
            ["execution_id"],
            ["remediation_executions.execution_id"],
            name="fk_remediation_dispatches_execution_id",
            ondelete="RESTRICT",
        ),
        sa.UniqueConstraint("execution_id", name="uq_remediation_dispatches_execution_id"),
    )


def downgrade() -> None:
    """Drop dispatch reservations without deleting execution attempts."""
    op.drop_table("remediation_dispatches")
