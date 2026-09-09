from __future__ import annotations

import copy

import pytest
from vonk_control.compiled_execution_plan import CompiledExecutionPlan
from vonk_control.harness_conformance import (
    HarnessConformanceError,
    _fixture_request,
    run_recipe_conformance,
    run_synthetic_conformance,
    validate_terminal_evidence,
)
from vonk_control.harnesses.canonical_metadata import CANONICAL_HARNESSES
from vonk_forge_contracts import ModelDefinition, RecipeDefinition

CANONICAL_SLUGS = tuple(item.slug for item in CANONICAL_HARNESSES)


@pytest.mark.parametrize("slug", CANONICAL_SLUGS)
def test_canonical_harness_completes_observed_synthetic_lifecycle(slug: str) -> None:
    evidence = run_synthetic_conformance(slug)

    assert evidence.phases == (
        "inspect",
        "prepare",
        "verify",
        "start",
        "inspect",
        "inspect",
        "start",
        "ready",
        "invoke",
        "inspect",
        "stop",
        "inspect",
        "inspect",
        "stop",
        "verify-stopped",
    )
    assert evidence.offline_runtime is True
    assert evidence.security["docker_socket"] is False
    assert evidence.security["plan_schema_version"] == 2
    assert evidence.interrupted_start_recovered is True
    assert evidence.interrupted_stop_recovered is True
    assert evidence.stop_bounded is True
    assert evidence.recovery_phases == (
        "start-interrupted",
        "inspect-idempotent",
        "start-recovered",
        "stop-interrupted",
        "inspect-idempotent",
        "stop-recovered",
    )
    assert evidence.document["schema_version"] == 2
    assert CompiledExecutionPlan.model_validate(evidence.document["plan"])


def test_conformance_fixture_uses_canonical_pydantic_definitions() -> None:
    request = _fixture_request("vllm")
    assert isinstance(request.recipe, RecipeDefinition)
    assert request.models and all(isinstance(item, ModelDefinition) for item in request.models)
    assert isinstance(request.plan, CompiledExecutionPlan)
    assert request.plan.schema_version == 2
    assert request.runtime_spec["identity"]["recipe_revision_sha256"]


@pytest.mark.parametrize("engine", ["vllm", "sglang"])
@pytest.mark.parametrize("fabric", ["connected", "full_mesh", "switch"])
@pytest.mark.parametrize("rank,role", [(0, "entrypoint"), (1, "worker")])
def test_two_node_recipe_conformance_preserves_host_network_without_claiming_offline(engine, fabric, rank, role):
    request = _fixture_request(engine)
    raw = request.recipe.model_dump(mode="json")
    owner = raw["topology"]["roles"][0]
    worker = copy.deepcopy(owner)
    worker.update(name="worker", endpoint_owner=False)
    raw["topology"].update(
        mode="distributed", node_count=2, roles=[owner, worker],
        parallelism={"world_size": 2, "tensor": 2, "pipeline": 1, "data": 1, "backend": "mp" if engine == "vllm" else "native"},
        fabric={"connectivity": fabric, "minimum_bandwidth_mbps": 1},
        start_order=["worker", "entrypoint"], stop_order=["entrypoint", "worker"],
    )
    for selection in raw["models"]:
        for file in selection["files"]:
            file["roles"] = ["entrypoint", "worker"]
    recipe = RecipeDefinition.model_validate(raw)
    evidence = run_recipe_conformance(recipe, request.models, rank=rank, role=role)
    assert evidence.security["network_mode"] == "host"
    assert evidence.offline_runtime is False
    assert evidence.interrupted_start_recovered and evidence.interrupted_stop_recovered
    raw["topology"]["roles"].reverse()
    reversed_evidence = run_recipe_conformance(raw, request.models, rank=1 - rank, role=role)
    assert reversed_evidence.security["network_mode"] == "host"
    assert reversed_evidence.offline_runtime is False


def test_artifact_job_uses_production_nullable_placement() -> None:
    request = _fixture_request("diffusers")

    assert request.launch_payload["endpoint"] is None
    assert request.launch_payload["job"] is not None
    assert request.placement["port"] is None
    assert request.placement["reserved_memory_bytes"] > 0


def test_conformance_rejects_unknown_harness() -> None:
    with pytest.raises(HarnessConformanceError, match="unknown execution harness"):
        run_synthetic_conformance("legacy-harness")


def test_conformance_rejects_tampered_plan_evidence() -> None:
    request = _fixture_request("vllm")
    document = copy.deepcopy(run_synthetic_conformance("vllm").document)
    document["plan"]["harness_sha256"] = "0" * 64

    with pytest.raises(HarnessConformanceError, match="plan identity"):
        validate_terminal_evidence(document, request)


def test_conformance_rejects_invalid_schema_or_retired_identity_evidence() -> None:
    request = _fixture_request("vllm")
    document = copy.deepcopy(run_synthetic_conformance("vllm").document)
    document["schema_version"] = 0

    with pytest.raises(HarnessConformanceError, match="evidence is invalid"):
        validate_terminal_evidence(document, request)


def test_conformance_fails_closed_for_mutated_canonical_recipe() -> None:
    request = _fixture_request("vllm")
    raw = request.recipe.model_dump(mode="json")
    raw["runtime"]["entrypoint"] = ["/bin/sh", "-c", "unsafe"]
    with pytest.raises(HarnessConformanceError):
        from vonk_control.harness_conformance import run_recipe_conformance

        run_recipe_conformance(raw, request.models)
