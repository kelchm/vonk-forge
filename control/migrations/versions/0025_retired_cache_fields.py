"""Remove retired cache projections from pre-cleanup schema-2 databases.

Current 0015 already omits these fields. Existing databases stamped at 0024
still require them on inserts, so normalize that historical shape once. No
runtime compatibility reader or replacement identity data is introduced.
"""

import sqlalchemy as sa
from alembic import op

revision = "0025_retired_cache_fields"
down_revision = "0024_failure_evidence"
branch_labels = None
depends_on = None


def upgrade() -> None:
    connection = op.get_bind()
    for table, column in (
        ("model_cache_artifacts", "identity"),
        ("model_cache_set_artifacts", "roles"),
    ):
        inspector = sa.inspect(connection)
        if column not in {item["name"] for item in inspector.get_columns(table)}:
            continue
        with op.batch_alter_table(table) as batch:
            if column == "identity" and any(
                item["name"] == "ck_model_cache_artifacts_identity_size"
                for item in inspector.get_check_constraints(table)
            ):
                batch.drop_constraint(
                    "ck_model_cache_artifacts_identity_size", type_="check"
                )
            batch.drop_column(column)


def downgrade() -> None:
    # The current 0024 schema, built through current 0015, omits these fields
    # too. Restoring historical redundant values requires the pre-upgrade
    # database backup; do not fabricate defaults or reintroduce retired fields.
    pass
