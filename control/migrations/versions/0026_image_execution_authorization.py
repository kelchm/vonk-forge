"""Bind each current compiled execution separately to immutable image evidence."""
from alembic import op

revision = "0026_image_execution_auth"
down_revision = "0025_retired_cache_fields"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("runtime_image_authorizations") as batch:
        batch.drop_constraint("uq_runtime_image_authorization_revision_receipt", type_="unique")
        batch.create_unique_constraint(
            "uq_runtime_image_authorization_revision_receipt_execution",
            ["recipe_revision_id", "receipt_id", "effective_execution_key"],
        )


def downgrade() -> None:
    # Refuse rollback once several current execution bindings use one receipt.
    # Never discard authorizations to make the old uniqueness constraint fit.
    with op.batch_alter_table("runtime_image_authorizations") as batch:
        batch.drop_constraint("uq_runtime_image_authorization_revision_receipt_execution", type_="unique")
        batch.create_unique_constraint(
            "uq_runtime_image_authorization_revision_receipt",
            ["recipe_revision_id", "receipt_id"],
        )
