"""Historical schema-2 cleanup; no legacy runtime contract is supported."""

import json
from datetime import UTC, datetime

import pytest
from alembic import command
from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy import (
    JSON,
    Column,
    MetaData,
    Table,
    create_engine,
    insert,
    inspect,
    select,
)
from sqlalchemy.exc import IntegrityError
from vonk_control.models import ModelCacheArtifact, ModelCacheSet, ModelCacheSetArtifact

from .test_migrations import _config


def _surviving_structure(connection):
    inspector = inspect(connection)
    return {
        table: {
            kind: sorted(
                (item for item in reader(table)
                 if item.get("name") != "ck_model_cache_artifacts_identity_size"),
                key=lambda item: json.dumps(item, sort_keys=True),
            )
            for kind, reader in (
                ("checks", inspector.get_check_constraints),
                ("uniques", inspector.get_unique_constraints),
                ("foreign_keys", inspector.get_foreign_keys),
                ("indexes", inspector.get_indexes),
            )
        }
        for table in ("model_cache_artifacts", "model_cache_set_artifacts")
    }


@pytest.mark.parametrize("backend", ["sqlite", "postgres"])
def test_historical_cache_fields_are_removed_without_losing_objects_or_membership(
    backend,
    tmp_path,
    request,
):
    engine = (
        request.getfixturevalue("postgres_engine")
        if backend == "postgres"
        else create_engine(f"sqlite:///{tmp_path / 'cache.sqlite'}")
    )
    config = _config(engine.url.render_as_string(hide_password=False))
    command.upgrade(config, "0024_failure_evidence")
    with engine.begin() as connection:
        operations = Operations(MigrationContext.configure(connection))
        # Reconstruct only the inert historical columns removed from 0015.
        with operations.batch_alter_table("model_cache_artifacts") as batch:
            batch.add_column(Column("identity", JSON, nullable=False))
            batch.create_check_constraint(
                "ck_model_cache_artifacts_identity_size",
                "length(CAST(identity AS TEXT)) BETWEEN 2 AND 65536",
            )
        with operations.batch_alter_table("model_cache_set_artifacts") as batch:
            batch.add_column(Column("roles", JSON, nullable=False))
        now = datetime.now(UTC)
        connection.execute(
            insert(ModelCacheSet).values(
                artifact_set_sha256="a" * 64,
                schema_version=2,
                manifest={},
                expected_bytes=1,
                verified_bytes=1,
                state="cached",
                protected=False,
                protected_reasons=[],
                created_at=now,
                updated_at=now,
                last_accessed_at=now,
            )
        )
        old_object = Table(
            "model_cache_artifacts", MetaData(), autoload_with=connection
        )
        old_member = Table(
            "model_cache_set_artifacts", MetaData(), autoload_with=connection
        )
        connection.execute(
            insert(old_object).values(
                sha256="b" * 64,
                storage_key="objects/bb/" + "b" * 64,
                expected_bytes=1,
                actual_bytes=1,
                state="verified",
                verified_at=now,
                updated_at=now,
                identity={"historical": True},
            )
        )
        connection.execute(
            insert(old_member).values(
                artifact_set_sha256="a" * 64,
                artifact_key="model.bin",
                artifact_sha256="b" * 64,
                path="model.bin",
                roles=["model"],
            )
        )
        before_object = connection.execute(select(ModelCacheArtifact)).mappings().all()
        before_members = (
            connection.execute(select(ModelCacheSetArtifact)).mappings().all()
        )
        before_structure = _surviving_structure(connection)
    values = {
        "sha256": "c" * 64,
        "storage_key": "objects/cc/" + "c" * 64,
        "expected_bytes": 1,
        "actual_bytes": 0,
        "state": "missing",
        "updated_at": now,
    }
    with pytest.raises(IntegrityError), engine.begin() as connection:
        connection.execute(insert(ModelCacheArtifact).values(**values))
    with pytest.raises(IntegrityError), engine.begin() as connection:
        connection.execute(
            insert(ModelCacheSetArtifact).values(
                artifact_set_sha256="a" * 64,
                artifact_key="another.bin",
                artifact_sha256="b" * 64,
                path="another.bin",
            )
        )
    command.upgrade(config, "head")
    with engine.begin() as connection:
        assert _surviving_structure(connection) == before_structure
        assert (
            connection.execute(select(ModelCacheArtifact)).mappings().all()
            == before_object
        )
        assert (
            connection.execute(select(ModelCacheSetArtifact)).mappings().all()
            == before_members
        )
        assert "identity" not in {
            c["name"] for c in inspect(connection).get_columns("model_cache_artifacts")
        }
        assert "roles" not in {
            c["name"]
            for c in inspect(connection).get_columns("model_cache_set_artifacts")
        }
        connection.execute(insert(ModelCacheArtifact).values(**values))
        connection.execute(
            insert(ModelCacheSetArtifact).values(
                artifact_set_sha256="a" * 64,
                artifact_key="another.bin",
                artifact_sha256="c" * 64,
                path="another.bin",
            )
        )
    command.downgrade(config, "0024_failure_evidence")
    command.upgrade(config, "head")
    with engine.connect() as connection:
        assert len(connection.execute(select(ModelCacheArtifact)).all()) == 2
        assert len(connection.execute(select(ModelCacheSetArtifact)).all()) == 2
