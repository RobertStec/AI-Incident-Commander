"""Allow legacy and MCP-bound action policy versions in approval and claim rows.

Revision ID: e62b4f0c91ad
Revises: c4f8a2d7e951
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "e62b4f0c91ad"
down_revision: str | None = "c4f8a2d7e951"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


_CHECKS = (
    ("remediation_approval_requests", "ck_approval_request_policy_version"),
    ("remediation_execution_claims", "ck_execution_claims_policy_version"),
)


def upgrade() -> None:
    """Accept both apv:v1 and apv:v2 without weakening unrelated constraints."""
    for table_name, constraint_name in _CHECKS:
        op.drop_constraint(constraint_name, table_name, type_="check")
        op.create_check_constraint(
            constraint_name,
            table_name,
            "policy_version ~ '^apv:v[12]:[0-9a-f]{64}$'",
        )


def downgrade() -> None:
    """Restore v1-only checks, refusing to strand existing v2 records."""
    connection = op.get_bind()
    for table_name, _ in _CHECKS:
        # Table names are constants declared in this migration, not user input.
        has_v2 = connection.execute(
            sa.text(
                f"SELECT 1 FROM {table_name} "
                "WHERE policy_version ~ '^apv:v2:[0-9a-f]{64}$' LIMIT 1"
            )
        ).first()
        if has_v2 is not None:
            raise RuntimeError(f"Cannot downgrade: {table_name} contains MCP-bound apv:v2 rows.")

    for table_name, constraint_name in _CHECKS:
        op.drop_constraint(constraint_name, table_name, type_="check")
        op.create_check_constraint(
            constraint_name,
            table_name,
            "policy_version ~ '^apv:v1:[0-9a-f]{64}$'",
        )
