from __future__ import annotations

import copy
import uuid
from types import SimpleNamespace

from sqlalchemy import select
from vonk_agent_protocol import DistributionObject
from vonk_control.catalog_entities import CatalogEntityService
from vonk_control.cluster_mappings import ClusterMappingService
from vonk_control.distribution import DistributionService
from vonk_control.execution_plan_service import ControllerExecutionPlanService
from vonk_control.install_admission import InstallAdmissionService
from vonk_control.models import (
    AgentNode,
    CatalogDocumentRevision,
    Job,
    NodeInventorySnapshot,
    RecipeBuild,
    RecipeInstallation,
    RecipeSourceBundle,
    RuntimeImageReceipt,
)
from vonk_control.recipe_builds import RecipeBuildService
from vonk_control.recipe_operations import RecipeOperationService
from vonk_control.run_admission import RunAdmissionService
from vonk_control.run_switch_contract import (
    RunSwitchApplyRequest,
    RunSwitchPreviewRequest,
    SparkGroup,
    SparkGroupNode,
)
from vonk_control.run_switch_operations import RunSwitchOperationService
from vonk_control.runtime_image_preparation import (
    FilesystemRuntimeImageStorage,
    persist_runtime_image_receipt,
    prepare_runtime_image,
    resolve_persisted_runtime_image_receipt,
)
from vonk_forge_contracts import RecipeDefinition

from .test_direct_run_switch_production_path import (
    MODEL_DIGEST,
    NODE_ID,
    NOW,
    _Inspector,
    _ModelCache,
    _Queue,
    _read_spec_endpoint,
    _seed,
    _TargetExecutor,
)
from .test_recipe_builds import setup as build_fixture
from .test_runtime_image_preparation import (
    ARCHIVE,
    ARCHIVE_DIGEST,
    BUILT_IMAGE_DIGEST,
    TinyTransport,
    _runtime,
)


def _service(tmp_path):
    # Reuse canonical build-policy/source provenance, then plan the actual
    # two-rank recipe through RecipeBuildService (never fabricate a build plan).
    donor = tmp_path / "build-provenance"
    donor.mkdir()
    donor_sessions, bundles, _, _, donor_revision = build_fixture(donor)
    sessions, published_id, _, _ = _seed(node_count=2)
    with donor_sessions() as source, sessions.begin() as target:
        source_bundle = source.scalar(select(RecipeSourceBundle))
        target.add(RecipeSourceBundle(**{
            column.name: getattr(source_bundle, column.name)
            for column in RecipeSourceBundle.__table__.columns
        }))
        published = target.get(CatalogDocumentRevision, published_id)
        document = copy.deepcopy(published.document)
        document["execution"] = copy.deepcopy(donor_revision.document["execution"])
        document["identity"]["slug"] = "source-reuse-two-rank"
        node = target.get(AgentNode, NODE_ID)
        node.binary_digest = "1" * 64
        node.build_digest = "sha256:" + "a" * 64
        node.semantic_version = "1.2.3"
        node.self_test_passed = True
        node.last_seen_at = NOW
        node.capabilities = [*node.capabilities, "recipe.build.v1", "recipe.build.egress-proxy.v1", "recipe.image.import.v1"]
        inventory = target.scalar(select(NodeInventorySnapshot).where(NodeInventorySnapshot.node_id == NODE_ID))
        inventory.capabilities = list(node.capabilities) + ["fabric.connected.mbps.1000"]
        inventory.disk_total_bytes = 2 * 1024**4
        inventory.disk_free_bytes = 1024**4
    catalog = CatalogEntityService(sessions, clock=lambda: NOW)
    draft = catalog.create_draft(document, actor="test")
    with sessions.begin() as session:
        row = session.get(CatalogDocumentRevision, draft.id)
        row.projected = {
            **row.projected,
            **{key: copy.deepcopy(donor_revision.projected[key]) for key in (
                "source_bundle_sha256", "build_resources", "build_security", "build_options", "build_model_artifacts"
            )},
        }
    original = catalog.resolve(draft.id, actor="test")
    build_service = RecipeBuildService(sessions, bundles=bundles)
    planned = build_service.plan(original.id, NODE_ID, now=NOW)
    storage = FilesystemRuntimeImageStorage(tmp_path / "runtime")
    storage.root.mkdir(parents=True, exist_ok=True)
    (storage.root / ARCHIVE_DIGEST).write_bytes(ARCHIVE)
    with sessions.begin() as session:
        build = session.get(RecipeBuild, planned.build_id)
        build.state = "succeeded"
        build.image_digest = BUILT_IMAGE_DIGEST
        build.oci_layout_sha256 = ARCHIVE_DIGEST
        build.image_bytes = len(ARCHIVE)
    receipt = prepare_runtime_image(
        RecipeDefinition.model_validate(original.document), runtime=_runtime(), storage=storage,
        transport=TinyTransport(), build_receipt={
            "state": "succeeded", "build_id": planned.build_id, "image_digest": BUILT_IMAGE_DIGEST,
            "oci_layout_sha256": ARCHIVE_DIGEST, "image_bytes": len(ARCHIVE),
        }, now=NOW,
    )
    with sessions.begin() as session:
        original_receipt = persist_runtime_image_receipt(
            session, recipe_revision_id=original.id, original_content_digest=original.content_digest,
            effective_execution_key=original.execution_key, receipt=receipt, verified_at=NOW,
        )
        original_receipt_id = original_receipt.id
    current_document = copy.deepcopy(original.document)
    for role in current_document["topology"]["roles"]:
        role["resources"]["memory"]["system_reserve_bytes"] = 4_000_000_000
    draft = catalog.revise(original.document_id, current_document, actor="test")
    with sessions.begin() as session:
        session.get(CatalogDocumentRevision, draft.id).projected = copy.deepcopy(original.projected)
    current = catalog.resolve(draft.id, actor="test")
    assert current.content_digest != original.content_digest
    assert current.execution_key != original.execution_key
    assert build_service.plan(current.id, NODE_ID, now=NOW).build_id == planned.build_id
    with sessions.begin() as session:
        persist_runtime_image_receipt(
            session, recipe_revision_id=current.id, original_content_digest=current.content_digest,
            effective_execution_key=current.execution_key, receipt=receipt, verified_at=NOW,
        )

    events = []
    def prepare_and_persist(document, runtime_spec, build):
        assert build.id == planned.build_id and build.recipe_revision_id == original.id
        with sessions.begin() as session:
            persist_runtime_image_receipt(
                session, recipe_revision_id=current.id, original_content_digest=current.content_digest,
                effective_execution_key=runtime_spec["identity"]["execution_sha256"], receipt=receipt,
                verified_at=NOW,
            )
        events.append("runtime-image-db-committed")
        return receipt

    def resolve_image(document, image_digest, runtime_spec):
        assert image_digest == receipt.image_digest
        with sessions() as session:
            resolve_persisted_runtime_image_receipt(
                session, recipe_revision_id=current.id, current_content_digest=current.content_digest,
                effective_execution_key=runtime_spec["identity"]["execution_sha256"], receipt=receipt,
            )
        return receipt

    cache = _ModelCache(current.content_digest)
    compiler = ControllerExecutionPlanService(cache, runtime_image_resolver=resolve_image)
    admission = InstallAdmissionService(sessions, disk_floor_bytes=10, compiled_plan_provider=compiler.compile_installation)
    lifecycle = RecipeOperationService(
        sessions, install_admission=admission,
        run_admission=RunAdmissionService(sessions, inventory_max_age=300, memory_floor_bytes=50),
        agent_jobs=_Queue(), clock=lambda: NOW, mappings=ClusterMappingService(sessions),
    )
    source = SimpleNamespace(objects_for_set=lambda digest: (
        DistributionObject(name="model.safetensors", sha256=MODEL_DIGEST, bytes=1024, kind="model"),
    ))
    executor = _TargetExecutor(
        sessions, None, DistributionService(source, sessions=sessions), clock=lambda: NOW,
        model_cache=cache, runtime_image_preparer=prepare_and_persist, events=events,
    )
    service = RunSwitchOperationService(
        sessions, lifecycle=lifecycle, clock=lambda: NOW, mappings=ClusterMappingService(sessions),
        artifacts=_Inspector(), artifact_phase_executor=executor, memory_floor_bytes=50,
    )
    return service, sessions, current, original, planned.build_id, original_receipt_id, executor, events


def test_source_successor_real_switch_installs_and_serves_both_current_rank_specs(tmp_path):
    service, sessions, current, original, build_id, receipt_id, executor, events = _service(tmp_path)
    request = RunSwitchPreviewRequest(
        model_content_sha256="e1e9de42be3e14bdb392cba65c9bbcbec6a4ea5b448597e0c32d187c5840029c",
        recipe_revision_id=current.id,
        spark_group=SparkGroup(nodes=[
            SparkGroupNode(node_id=NODE_ID, rank=0, role="entrypoint", endpoint_owner=True),
            SparkGroupNode(node_id="spk_" + "2" * 32, rank=1, role="worker", endpoint_owner=False),
        ]), alias="source-successor",
    )
    preview = service.preview(request, actor="test")
    assert preview.allowed, preview.blockers
    assert preview.recipe_build_id == build_id
    operation = service.apply(RunSwitchApplyRequest(**request.model_dump(mode="json"), request_key=str(uuid.uuid4())), actor="test")
    for _ in range(24):
        service._advance(operation.operation_id)
        with sessions() as session:
            parent = session.get(Job, operation.operation_id)
            assert parent.state != "failed", (parent.status_reason, parent.result, events)
            child_id = (parent.result or {}).get("child_operation_id")
            child = session.get(Job, child_id) if child_id else None
            if child is not None and child.kind == "recipe.install":
                break
    else:
        raise AssertionError("normal switch did not reach real recipe.install child")
    with sessions() as session:
        installation = session.scalar(select(RecipeInstallation))
        assert installation is not None and installation.state == "installing"
        assert installation.recipe_revision_id == current.id
        assert installation.recipe_build_id == build_id
        build = session.get(RecipeBuild, build_id)
        assert build.recipe_revision_id == original.id
        assert session.query(RecipeBuild).count() == 1
        assert session.query(RuntimeImageReceipt).count() == 1
        old_receipt = session.get(RuntimeImageReceipt, receipt_id)
        assert old_receipt.original_content_digest == original.content_digest
        assert old_receipt.effective_execution_key == original.execution_key
        installation_id = installation.id
        plans = installation.plan["compiled_execution_plans"]
    assert events.index("runtime-image-db-committed") < events.index("target-copy")
    keys = set()
    for second, node_id in [(False, NODE_ID), (True, "spk_" + "2" * 32)]:
        response = _read_spec_endpoint(sessions, tmp_path, installation_id, second=second)
        assert response.status_code == 200, response.text
        assert response.json() == plans[node_id]
        assert response.json()["identity"]["recipe_revision_sha256"] == current.content_digest
        assert response.json()["runtime_image"]["build_id"] == build_id
        keys.add(response.json()["identity"]["execution_sha256"])
        assert executor.assignments[node_id]["oci_image_digest"] == BUILT_IMAGE_DIGEST
    assert len(keys) == 2


def test_install_accept_rechecks_revoked_successor_authority(tmp_path):
    import pytest
    from vonk_control.models import RuntimeImageAuthorization

    service, sessions, current, _, build_id, _, executor, _ = _service(tmp_path)
    nodes = (NODE_ID, "spk_" + "2" * 32)
    mappings = ClusterMappingService(sessions)
    mapping = mappings.preview(current.id, nodes, {}, "test")
    mapping_id = mappings.materialize(mapping, actor="test", now=NOW)
    request = RunSwitchPreviewRequest(
        model_content_sha256="e1e9de42be3e14bdb392cba65c9bbcbec6a4ea5b448597e0c32d187c5840029c",
        recipe_revision_id=current.id,
        spark_group=SparkGroup(nodes=[
            SparkGroupNode(node_id=nodes[0], rank=0, role="entrypoint", endpoint_owner=True),
            SparkGroupNode(node_id=nodes[1], rank=1, role="worker", endpoint_owner=False),
        ]), alias="source-successor",
    )
    preview = service.preview(request, actor="test")
    assert preview.allowed, preview.blockers
    executor._prepare_runtime_image(preview)
    admission = service._lifecycle._install_admission
    plan = admission.plan_install(mapping_id, build_id, now=NOW)
    assert plan.allowed
    with sessions.begin() as session:
        authorization = session.scalar(select(RuntimeImageAuthorization).where(
            RuntimeImageAuthorization.recipe_revision_id == current.id,
            RuntimeImageAuthorization.effective_execution_key == current.execution_key,
        ))
        assert authorization is not None
        authorization.state = "revoked"
    with pytest.raises(ValueError, match="successful recipe build does not match the mapping"):
        admission.accept_install(plan, actor="test", now=NOW)
    with sessions() as session:
        assert session.query(RecipeInstallation).count() == 0
