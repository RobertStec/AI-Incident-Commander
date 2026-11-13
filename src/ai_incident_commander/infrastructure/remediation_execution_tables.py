"""SQLAlchemy Core table for the durable remediation execution lifecycle."""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from ai_incident_commander.infrastructure.execution_claim_tables import execution_claims_table

remediation_executions_table = sa.Table(
    "remediation_executions",
    execution_claims_table.metadata,
    sa.Column("execution_id", postgresql.UUID(as_uuid=True), nullable=False),
    sa.Column("claim_id", postgresql.UUID(as_uuid=True), nullable=False),
    sa.Column("status", sa.Text(), nullable=False),
    sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("status_changed_at", sa.DateTime(timezone=True), nullable=True),
    sa.PrimaryKeyConstraint("execution_id", name="pk_remediation_executions"),
    sa.ForeignKeyConstraint(
        ["claim_id"],
        [execution_claims_table.c.claim_id],
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
