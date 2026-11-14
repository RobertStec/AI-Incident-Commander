"""SQLAlchemy Core table for one durable MCP dispatch reservation per execution."""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from ai_incident_commander.infrastructure.remediation_execution_tables import (
    remediation_executions_table,
)

remediation_dispatches_table = sa.Table(
    "remediation_dispatches",
    remediation_executions_table.metadata,
    sa.Column("dispatch_id", postgresql.UUID(as_uuid=True), nullable=False),
    sa.Column("execution_id", postgresql.UUID(as_uuid=True), nullable=False),
    sa.Column("reserved_at", sa.DateTime(timezone=True), nullable=False),
    sa.PrimaryKeyConstraint("dispatch_id", name="pk_remediation_dispatches"),
    sa.ForeignKeyConstraint(
        ["execution_id"],
        [remediation_executions_table.c.execution_id],
        name="fk_remediation_dispatches_execution_id",
        ondelete="RESTRICT",
    ),
    sa.UniqueConstraint("execution_id", name="uq_remediation_dispatches_execution_id"),
)
