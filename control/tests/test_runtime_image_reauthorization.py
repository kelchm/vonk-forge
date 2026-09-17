from __future__ import annotations

import copy
from types import SimpleNamespace

import pytest
from sqlalchemy import select
from vonk_control.agent_api import _runtime_image_receipt_matches
from vonk_control.catalog_entities import CatalogEntityService
from vonk_control.catalog_revision_contract import read_catalog_document
from vonk_control.distribution_executor import DurableDistributionPhaseExecutor
from vonk_control.models import (
    CatalogDocumentRevision,
    RecipeBuild,
    RuntimeImageAuthorization,
)
from vonk_control.models import RuntimeImageReceipt as ReceiptRow
from vonk_control.recipe_builds import RecipeBuildService
from vonk_control.runtime_image_preparation import (
    FilesystemRuntimeImageStorage,
    RuntimeImagePreparationError,
    persist_runtime_image_receipt,
    prepare_runtime_image,
    resolve_persisted_runtime_image_receipt,
)
from vonk_forge_contracts import RecipeDefinition, content_sha256

from .test_recipe_builds import setup
from .test_runtime_image_preparation import (
    ARCHIVE,
    ARCHIVE_DIGEST,
    BUILT_IMAGE_DIGEST,
    TinyTransport,
    _runtime,
)

CURRENT_REVISION_ID = "11111111-2222-4333-8444-555555555555"


def scenario(tmp_path, *, current_recipe_mutation=None, build_label=None):
    sessions, bundles, now, node_id, original = setup(tmp_path)
    if build_label is not None:
        catalog = CatalogEntityService(sessions, clock=lambda: now)
        raw = copy.deepcopy(original.document)
        raw["settings"]["knobs"] = {
            "label": {"value": build_label, "change_effect": "rebuild"},
        }
        draft = catalog.revise(original.document_id, raw, actor="admin")
        with sessions.begin() as session:
            stored = session.get(CatalogDocumentRevision, draft.id)
            stored.projected = copy.deepcopy(original.projected)
        original = catalog.resolve(draft.id, actor="admin")
    service = RecipeBuildService(sessions, bundles=bundles)
    plan = service.plan(original.id, node_id, now=now)
    storage = FilesystemRuntimeImageStorage(tmp_path / "images")
    storage.root.mkdir(parents=True, exist_ok=True)
    (storage.root / ARCHIVE_DIGEST).write_bytes(ARCHIVE)
    with sessions.begin() as session:
        build = session.get(RecipeBuild, plan.build_id)
        build.state = "succeeded"
        build.image_digest = BUILT_IMAGE_DIGEST
        build.oci_layout_sha256 = ARCHIVE_DIGEST
        build.image_bytes = len(ARCHIVE)
        recipe = read_catalog_document(session.get(CatalogDocumentRevision, original.id))
    receipt = prepare_runtime_image(
        recipe, runtime=_runtime(), storage=storage, transport=TinyTransport(),
        build_receipt={"state": "succeeded", "build_id": plan.build_id,
                       "image_digest": BUILT_IMAGE_DIGEST, "oci_layout_sha256": ARCHIVE_DIGEST,
                       "image_bytes": len(ARCHIVE)},
    )
    with sessions.begin() as session:
        old = session.get(CatalogDocumentRevision, original.id)
        row = persist_runtime_image_receipt(
            session, recipe_revision_id=old.id, original_content_digest=old.content_digest,
            effective_execution_key="1" * 64, receipt=receipt, verified_at=now,
        )
        raw = copy.deepcopy(old.document)
        for role in raw["topology"]["roles"]:
            role["resources"]["memory"]["system_reserve_bytes"] = 4_000_000_000
        raw["metadata"]["description"] = "New host reserve, unchanged image build"
        if current_recipe_mutation is not None:
            current_recipe_mutation(raw)
        new_recipe = RecipeDefinition.model_validate(raw)
        new = CatalogDocumentRevision(
            id=CURRENT_REVISION_ID, document_id=old.document_id, kind=old.kind,
            publisher=old.publisher, slug=old.slug, revision_number=old.revision_number + 1, schema_version=2,
            state="active", document=new_recipe.model_dump(mode="json"),
            content_digest=content_sha256(new_recipe), artifact_key=old.artifact_key,
            execution_key="2" * 64, projected=copy.deepcopy(old.projected),
            created_by="test", created_at=now,
        )
        session.add(new)
        original_row_id = row.id
    return sessions, now, receipt, original_row_id


def test_new_runtime_authorizes_two_ranks_without_rewriting_image(tmp_path):
    sessions, now, receipt, original_row_id = scenario(tmp_path)
    with sessions.begin() as session:
        revision = session.get(CatalogDocumentRevision, CURRENT_REVISION_ID)
        old_row = session.get(ReceiptRow, original_row_id)
        old_provenance = (old_row.recipe_revision_id, old_row.original_content_digest, old_row.effective_execution_key)
        for key in ("2" * 64, "3" * 64):
            row = persist_runtime_image_receipt(
                session, recipe_revision_id=revision.id, original_content_digest=revision.content_digest,
                effective_execution_key=key, receipt=receipt, verified_at=now,
            )
            assert row.id == original_row_id
            assert resolve_persisted_runtime_image_receipt(
                session, recipe_revision_id=revision.id, current_content_digest=revision.content_digest,
                effective_execution_key=key, receipt=receipt,
            ).id == row.id
        assert (old_row.recipe_revision_id, old_row.original_content_digest, old_row.effective_execution_key) == old_provenance
        assert session.query(ReceiptRow).count() == 1
        auths = session.scalars(select(RuntimeImageAuthorization).where(RuntimeImageAuthorization.recipe_revision_id == revision.id)).all()
        assert len(auths) == 2
        runtime_image = {
            "image_digest": receipt.platform_manifest_digest,
            "platform_manifest_digest": receipt.platform_manifest_digest,
            "registry_manifest_digest": receipt.registry_manifest_digest,
            "local_image_config_id": receipt.local_image_config_id,
            "oci_layout_sha256": receipt.oci_archive_sha256,
            "image_bytes": receipt.image_bytes,
            "architecture": receipt.architecture,
            "runtime_interface": receipt.runtime_interface,
            "runtime_interface_label": receipt.runtime_interface_label,
            "source": receipt.source, "build_id": receipt.build_id,
        }
        for auth in auths:
            identity = {"recipe_revision_sha256": revision.content_digest,
                        "execution_sha256": auth.effective_execution_key}
            kwargs = {"revision_id": revision.id, "revision_digest": revision.content_digest,
                          "installation_image_digest": receipt.platform_manifest_digest,
                          "installation_recipe_build_id": receipt.build_id, "authorization": auth}
            assert _runtime_image_receipt_matches(runtime_image, identity, old_row, **kwargs)
            assert not _runtime_image_receipt_matches(
                runtime_image, dict(identity, execution_sha256="9" * 64), old_row, **kwargs
            )
        session.flush()
        auths[0].state = "revoked"
        with pytest.raises(ValueError, match="not authorized"):
            resolve_persisted_runtime_image_receipt(
                session, recipe_revision_id=revision.id, current_content_digest=revision.content_digest,
                effective_execution_key=auths[0].effective_execution_key, receipt=receipt,
            )


@pytest.mark.parametrize("mutation", ["source", "artifact", "build-input", "policy", "archive", "revoked"])
def test_reauthorization_rejects_changed_evidence(tmp_path, mutation):
    sessions, now, receipt, original_row_id = scenario(tmp_path)
    with sessions.begin() as session:
        revision = session.get(CatalogDocumentRevision, CURRENT_REVISION_ID)
        build = session.get(RecipeBuild, receipt.build_id)
        if mutation == "source":
            revision.projected = dict(revision.projected, source_bundle_sha256="9" * 64)
        elif mutation == "artifact":
            revision.artifact_key = "9" * 64
        elif mutation == "build-input":
            build.build_input_sha256 = "9" * 64
        elif mutation == "policy":
            build.policy_report = dict(build.policy_report, passed=False)
        elif mutation == "archive":
            receipt = receipt.model_copy(update={"oci_archive_sha256": "9" * 64})
        elif mutation == "revoked":
            session.get(ReceiptRow, original_row_id).state = "revoked"
        with session.no_autoflush, pytest.raises(RuntimeImagePreparationError):
            persist_runtime_image_receipt(
                session, recipe_revision_id=revision.id, original_content_digest=revision.content_digest,
                effective_execution_key="2" * 64, receipt=receipt, verified_at=now,
            )
        session.rollback()


def test_distribution_uses_current_authorization_and_original_receipt(tmp_path):
    sessions, now, receipt, original_row_id = scenario(tmp_path)
    with sessions.begin() as session:
        revision = session.get(CatalogDocumentRevision, CURRENT_REVISION_ID)
        persist_runtime_image_receipt(
            session, recipe_revision_id=revision.id, original_content_digest=revision.content_digest,
            effective_execution_key="2" * 64, receipt=receipt, verified_at=now,
        )
    executor = object.__new__(DurableDistributionPhaseExecutor)
    executor._sessions = sessions
    kwargs = {"build_id": receipt.build_id, "image_digest": receipt.platform_manifest_digest,
                  "layout_digest": receipt.oci_archive_sha256, "image_bytes": receipt.image_bytes}
    plan = SimpleNamespace(recipe_revision_id=CURRENT_REVISION_ID)
    assert executor._archive(plan, effective_execution_key="2" * 64, **kwargs).sha256 == ARCHIVE_DIGEST
    with pytest.raises(RuntimeError, match="not authorized"):
        executor._archive(plan, effective_execution_key="9" * 64, **kwargs)
    with sessions.begin() as session:
        session.get(ReceiptRow, original_row_id).state = "revoked"
    with pytest.raises(RuntimeError, match="authority changed"):
        executor._archive(plan, effective_execution_key="2" * 64, **kwargs)


@pytest.mark.parametrize("field", ["rebuild-setting", "build-target"])
def test_reauthorization_recomputes_current_recipe_build_inputs(tmp_path, field):
    def mutate(raw):
        if field == "rebuild-setting":
            raw["settings"]["knobs"]["compiler"] = {"value": "clang", "change_effect": "rebuild"}
        else:
            raw["execution"]["build"]["target"] = "different-runtime"

    sessions, now, receipt, _ = scenario(tmp_path, current_recipe_mutation=mutate)
    with sessions.begin() as session:
        revision = session.get(CatalogDocumentRevision, CURRENT_REVISION_ID)
        with pytest.raises(RuntimeImagePreparationError, match="executable build identity changed"):
            persist_runtime_image_receipt(
                session, recipe_revision_id=revision.id, original_content_digest=revision.content_digest,
                effective_execution_key=revision.execution_key, receipt=receipt, verified_at=now,
            )


def test_retry_keeps_existing_decision_and_cannot_route_around_revocation(tmp_path):
    sessions, now, receipt, original_row_id = scenario(tmp_path)
    with sessions.begin() as session:
        revision = session.get(CatalogDocumentRevision, CURRENT_REVISION_ID)
        first = persist_runtime_image_receipt(
            session, recipe_revision_id=revision.id, original_content_digest=revision.content_digest,
            effective_execution_key=revision.execution_key, receipt=receipt, verified_at=now,
        )
        original = session.get(ReceiptRow, original_row_id)
        sibling = ReceiptRow(**{
            column.name: getattr(original, column.name)
            for column in ReceiptRow.__table__.columns
            if column.name not in {"id", "effective_execution_key"}
        }, id="00000000-0000-4000-8000-000000000001", effective_execution_key="4" * 64)
        session.add(sibling)
        session.flush()
        retry = persist_runtime_image_receipt(
            session, recipe_revision_id=revision.id, original_content_digest=revision.content_digest,
            effective_execution_key=revision.execution_key, receipt=receipt, verified_at=now,
        )
        assert retry.id == first.id == original_row_id
        authorization = session.scalar(select(RuntimeImageAuthorization).where(
            RuntimeImageAuthorization.recipe_revision_id == revision.id,
            RuntimeImageAuthorization.effective_execution_key == revision.execution_key,
        ))
        authorization.state = "revoked"
        session.flush()
        with pytest.raises(RuntimeImagePreparationError, match="authorization is not active"):
            persist_runtime_image_receipt(
                session, recipe_revision_id=revision.id, original_content_digest=revision.content_digest,
                effective_execution_key=revision.execution_key, receipt=receipt, verified_at=now,
            )


def test_run_switch_build_consumers_require_current_catalog_authority(tmp_path):
    from vonk_control.run_switch_operations import (
        RecipeLifecyclePhaseExecutor,
        RunSwitchOperationConflict,
        RunSwitchOperationService,
        _build_receipt_in_session,
    )
    sessions, now, receipt, _ = scenario(tmp_path)
    with sessions.begin() as session:
        revision = session.get(CatalogDocumentRevision, CURRENT_REVISION_ID)
        build = session.get(RecipeBuild, receipt.build_id)
        assert RunSwitchOperationService._matching_build(session, revision.id, None) is None
        persist_runtime_image_receipt(
            session, recipe_revision_id=revision.id, original_content_digest=revision.content_digest,
            effective_execution_key=revision.execution_key, receipt=receipt, verified_at=now,
        )
        assert RunSwitchOperationService._matching_build(session, revision.id, None).id == build.id
        plan = SimpleNamespace(recipe_revision_id=revision.id, recipe_build_id=build.id,
                               build=SimpleNamespace(build_id=build.id, build_input_sha256=build.build_input_sha256))
        assert _build_receipt_in_session(session, plan)["build_id"] == build.id
    executor = object.__new__(RecipeLifecyclePhaseExecutor)
    executor._sessions = sessions
    assert executor._execute_container_build(plan, actor="test", request_key="reuse").result["build_id"] == build.id
    with sessions.begin() as session:
        authorization = session.scalar(select(RuntimeImageAuthorization).where(
            RuntimeImageAuthorization.recipe_revision_id == CURRENT_REVISION_ID,
            RuntimeImageAuthorization.effective_execution_key == "2" * 64,
        ))
        authorization.state = "revoked"
        session.flush()
        assert RunSwitchOperationService._matching_build(session, CURRENT_REVISION_ID, None) is None
        with pytest.raises(RunSwitchOperationConflict, match="receipt-unavailable"):
            _build_receipt_in_session(session, plan)
    with pytest.raises(RunSwitchOperationConflict, match="receipt-unavailable"):
        executor._execute_container_build(plan, actor="test", request_key="reuse")


def test_reauthorization_preserves_non_ascii_build_identity(tmp_path):
    sessions, now, receipt, original_row_id = scenario(tmp_path, build_label="modèle-模型")
    with sessions.begin() as session:
        revision = session.get(CatalogDocumentRevision, CURRENT_REVISION_ID)
        row = persist_runtime_image_receipt(
            session, recipe_revision_id=revision.id,
            original_content_digest=revision.content_digest,
            effective_execution_key=revision.execution_key,
            receipt=receipt, verified_at=now,
        )
        assert row.id == original_row_id
        assert resolve_persisted_runtime_image_receipt(
            session, recipe_revision_id=revision.id,
            current_content_digest=revision.content_digest,
            effective_execution_key=revision.execution_key, receipt=receipt,
        ).id == original_row_id
