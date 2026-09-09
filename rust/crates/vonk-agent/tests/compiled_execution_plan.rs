use std::path::Path;

use serde_json::{Value, json};
use vonk_agent::workloads::{
    CompiledExecutionPlan, MAX_COMPILED_EXECUTION_PLAN_MOUNTS, WorkloadError,
    materialized_model_path,
};

fn fixture() -> Value {
    serde_json::from_str(include_str!(
        "../../../../control/tests/fixtures/compiled_workload_v2.json"
    ))
    .unwrap()
}

#[test]
fn generated_python_workload_fixture_round_trips_through_rust() {
    let value = fixture();
    let plan: CompiledExecutionPlan = serde_json::from_value(value.clone()).unwrap();
    plan.validate().unwrap();
    assert_eq!(plan.schema_version, 2);
    assert_eq!(plan.runtime.executable, "/opt/vonk/bin/vllm");
    assert_eq!(plan.artifacts.len(), 3);
    assert_eq!(plan.artifacts[0].path, "config.json");
    assert_eq!(plan.artifacts[1].path, "config.json");
    assert_ne!(plan.artifacts[0].model, plan.artifacts[1].model);
    assert_eq!(plan.artifacts[2].roles, ["entrypoint"]);
    assert!(
        plan.runtime
            .argv
            .contains(&"--served-model-name".to_owned())
    );
    assert_eq!(serde_json::to_value(plan).unwrap(), value);
}

#[test]
fn recipe_topology_vocabulary_and_engine_backends_survive_validation() {
    for mode in [
        "single",
        "distributed",
        "tensor_parallel",
        "pipeline_parallel",
        "data_parallel",
        "hybrid",
        "ray",
        "mpi",
    ] {
        for backend in ["tcp", "ucx", "future-engine-Δ"] {
            let mut value = fixture();
            value["topology"]["mode"] = json!(mode);
            value["topology"]["backend"] = json!(backend);
            let plan: CompiledExecutionPlan = serde_json::from_value(value).unwrap();
            plan.validate().unwrap();
            assert_eq!(plan.topology.mode, mode);
            assert_eq!(plan.topology.backend, backend);
        }
    }
    let mut value = fixture();
    value["topology"]["backend"] = json!("");
    assert!(serde_json::from_value::<CompiledExecutionPlan>(value).is_err());
}

#[test]
fn endpoint_and_job_are_required_one_of_wire_keys() {
    let mut value = fixture();
    value.as_object_mut().unwrap().remove("endpoint");
    assert!(serde_json::from_value::<CompiledExecutionPlan>(value).is_err());

    let mut value = fixture();
    value.as_object_mut().unwrap().remove("job");
    assert!(serde_json::from_value::<CompiledExecutionPlan>(value).is_err());

    let mut value = fixture();
    value["job"] = json!({
        "interface": "artifact-job",
        "input": null,
        "output_path": "/outputs",
        "timeout_seconds": 30
    });
    let plan: CompiledExecutionPlan = serde_json::from_value(value).unwrap();
    assert!(plan.validate().is_err());
}

#[test]
fn compiled_job_input_round_trips_as_a_fixed_nested_contract() {
    let mut value = fixture();
    value["endpoint"] = Value::Null;
    value["runtime"]["placement"]["port"] = Value::Null;
    value["job"] = json!({
        "interface": "artifact-job",
        "input": {
            "path": "/inputs",
            "required": true,
            "media_types": ["application/json"],
            "max_bytes": 1024,
            "slots": [{
                "id": "document",
                "label": "Document",
                "description": "A JSON document to process",
                "media_types": ["application/json"],
                "extensions": [".7z"],
                "min_files": 1,
                "max_files": 1,
                "max_file_bytes": 1024,
                "max_total_bytes": 1024
            }]
        },
        "output_path": "/outputs",
        "timeout_seconds": 60
    });
    let plan: CompiledExecutionPlan = serde_json::from_value(value.clone()).unwrap();
    plan.validate().unwrap();
    assert_eq!(serde_json::to_value(plan).unwrap(), value);

    for mutation in [
        ("unknown", json!({"vendor": "free-form"})),
        ("missing", Value::Null),
        ("zero_max_files", json!(0)),
    ] {
        let mut invalid = value.clone();
        if mutation.0 == "unknown" {
            invalid["job"]["input"]["declared_content"] = mutation.1;
        } else if mutation.0 == "missing" {
            invalid["job"]["input"]
                .as_object_mut()
                .unwrap()
                .remove("required");
        } else {
            invalid["job"]["input"]["slots"][0]["max_files"] = mutation.1;
        }
        if let Ok(plan) = serde_json::from_value::<CompiledExecutionPlan>(invalid) {
            assert!(plan.validate().is_err());
        }
    }
}

#[test]
fn materialized_paths_remain_selection_scoped() {
    let plan: CompiledExecutionPlan = serde_json::from_value(fixture()).unwrap();
    let primary =
        materialized_model_path(Path::new("/run/vonk/models"), &plan.artifacts[0]).unwrap();
    let draft = materialized_model_path(Path::new("/run/vonk/models"), &plan.artifacts[1]).unwrap();
    assert_eq!(primary, Path::new("/run/vonk/models/primary/config.json"));
    assert_eq!(
        draft,
        Path::new("/run/vonk/models/dependency-qwen3-8-27b-dspark-b3c99101/config.json")
    );
    assert_ne!(primary, draft);
}

#[test]
fn canonical_unicode_space_and_max_length_model_identity_round_trip() {
    let mut value = fixture();
    let path = "模型 file_".repeat(64);
    assert_eq!(path.chars().count(), 512);
    let publisher = format!("发布者 {}", "_".repeat(124));
    assert_eq!(publisher.chars().count(), 128);
    value["artifacts"][0]["path"] = json!(path);
    value["artifacts"][0]["distribution_object"]["name"] = json!(path);
    value["artifacts"][0]["model"]["publisher"] = json!(publisher);

    let plan: CompiledExecutionPlan = serde_json::from_value(value.clone()).unwrap();
    plan.validate().unwrap();
    assert_eq!(plan.artifacts[0].path.chars().count(), 512);
    assert_eq!(plan.artifacts[0].model.publisher.chars().count(), 128);
    assert_eq!(serde_json::to_value(plan).unwrap(), value);
}

#[test]
fn unsafe_model_path_and_publisher_values_remain_rejected() {
    for path in [
        "/absolute",
        "../escape",
        "nested//file",
        "nested/./file",
        "nested/../file",
        "bad\\name",
        "bad\0name",
    ] {
        let mut value = fixture();
        value["artifacts"][0]["path"] = json!(path);
        value["artifacts"][0]["distribution_object"]["name"] = json!(path);
        let plan: CompiledExecutionPlan = serde_json::from_value(value).unwrap();
        assert!(plan.validate().is_err(), "{path}");
    }

    let mut value = fixture();
    value["artifacts"][0]["model"]["publisher"] = json!("publisher\0");
    let plan: CompiledExecutionPlan = serde_json::from_value(value).unwrap();
    assert!(plan.validate().is_err());

    let mut value = fixture();
    value["artifacts"][0]["model"]["publisher"] = json!("p".repeat(129));
    assert!(serde_json::from_value::<CompiledExecutionPlan>(value).is_err());
}

#[test]
fn duplicate_final_mount_target_is_rejected() {
    let mut value = fixture();
    let duplicate = value["artifacts"][0].clone();
    value["artifacts"] = serde_json::json!([duplicate.clone(), duplicate]);
    let plan: CompiledExecutionPlan = serde_json::from_value(value).unwrap();
    assert!(matches!(
        plan.validate(),
        Err(WorkloadError::Invalid(
            "compiled model artifact mount target"
        ))
    ));
}

#[test]
fn valid_empty_support_file_is_admitted_and_empty_weight_is_rejected() {
    let mut value = fixture();
    value["identity"]["model_artifact_bytes"] = serde_json::json!(0);
    let artifact = &mut value["artifacts"][0];
    artifact["file_id"] = serde_json::json!("tokenizer-config");
    artifact["path"] = serde_json::json!("tokenizer_config.json");
    artifact["sha256"] = serde_json::json!(vonk_agent::workloads::EMPTY_SHA256);
    artifact["size_bytes"] = serde_json::json!(0);
    artifact["roles"] = serde_json::json!(["tokenizer"]);
    artifact["distribution_object"] = serde_json::json!({
        "name": "tokenizer_config.json",
        "sha256": vonk_agent::workloads::EMPTY_SHA256,
        "bytes": 0,
        "kind": "model"
    });
    value["artifacts"] = serde_json::json!([artifact.clone()]);
    let plan: CompiledExecutionPlan = serde_json::from_value(value.clone()).unwrap();
    plan.validate().unwrap();

    value["artifacts"][0]["roles"] = serde_json::json!(["weights"]);
    let plan: CompiledExecutionPlan = serde_json::from_value(value).unwrap();
    assert!(matches!(
        plan.validate(),
        Err(WorkloadError::Invalid("compiled model artifact"))
    ));
}

#[test]
fn retired_upstream_authority_is_rejected_by_strict_serde() {
    let mut value = fixture();
    value["artifacts"][0]["repository"] = serde_json::json!("huggingface/private");
    assert!(serde_json::from_value::<CompiledExecutionPlan>(value).is_err());
}

#[test]
fn opaque_argv_preserves_large_json_and_unicode_byte_boundaries() {
    let mut value = fixture();
    let compact_json = format!("{{\"payload\":\"{}\"}}", "x".repeat(4_090));
    assert!(compact_json.len() > 4_096);
    assert!(compact_json.len() <= 65_536);
    let exact_unicode = "🙂".repeat(16_384);
    assert_eq!(exact_unicode.len(), 65_536);
    value["runtime"]["argv"] = json!(["serve", compact_json, exact_unicode]);

    let plan: CompiledExecutionPlan = serde_json::from_value(value.clone()).unwrap();
    plan.validate().unwrap();
    assert_eq!(serde_json::to_value(plan).unwrap(), value);
}

#[test]
fn opaque_argv_rejects_nul_and_token_or_total_overflow() {
    let mut value = fixture();
    value["runtime"]["argv"] = json!([format!("{}x", "🙂".repeat(16_384))]);
    let plan: CompiledExecutionPlan = serde_json::from_value(value.clone()).unwrap();
    assert!(plan.validate().is_err());

    value["runtime"]["argv"] = json!(["value\u{0000}"]);
    let plan: CompiledExecutionPlan = serde_json::from_value(value.clone()).unwrap();
    assert!(plan.validate().is_err());

    value["runtime"]["argv"] = json!(vec!["x".repeat(65_536); 17]);
    let plan: CompiledExecutionPlan = serde_json::from_value(value).unwrap();
    assert!(plan.validate().is_err());
}

#[test]
fn canonical_multi_model_mount_projection_is_admitted() {
    let mut value = fixture();
    value["security"]["mounts"] = json!([
        {"source": "model", "target": "/models/target", "read_only": true},
        {"source": "model", "target": "/models/draft", "read_only": true},
        {"source": "model", "target": "/models/support", "read_only": true},
        {"source": "inputs", "target": "/inputs", "read_only": true},
        {"source": "outputs", "target": "/outputs", "read_only": false}
    ]);
    let plan: CompiledExecutionPlan = serde_json::from_value(value).unwrap();
    plan.validate().unwrap();
}

#[test]
fn mount_source_and_target_policy_matches_python_matrix() {
    for (source, target, read_only) in [
        ("model", "/models", true),
        ("model", "/models/secondary", true),
        ("inputs", "/inputs", true),
        ("outputs", "/outputs", false),
    ] {
        let mut value = fixture();
        value["security"]["mounts"] = json!([{
            "source": source,
            "target": target,
            "read_only": read_only
        }]);
        let plan: CompiledExecutionPlan = serde_json::from_value(value).unwrap();
        plan.validate().unwrap();
    }

    for (source, target, read_only) in [
        ("model", "/inputs", true),
        ("inputs", "/models", true),
        ("outputs", "/models", false),
    ] {
        let mut value = fixture();
        value["security"]["mounts"] = json!([{
            "source": source,
            "target": target,
            "read_only": read_only
        }]);
        let plan: CompiledExecutionPlan = serde_json::from_value(value).unwrap();
        assert!(matches!(
            plan.validate(),
            Err(WorkloadError::Invalid("compiled security"))
        ));
    }
}

#[test]
fn mount_projection_rejects_over_duplicate_or_unsafe_targets() {
    let mut over = fixture();
    let mounts = over["security"]["mounts"].as_array_mut().unwrap();
    while mounts.len() <= MAX_COMPILED_EXECUTION_PLAN_MOUNTS {
        let index = mounts.len();
        mounts.push(json!({
            "source": "model",
            "target": format!("/models/extra-{index}"),
            "read_only": true
        }));
    }
    let plan: CompiledExecutionPlan = serde_json::from_value(over).unwrap();
    assert!(matches!(
        plan.validate(),
        Err(WorkloadError::Invalid("compiled security"))
    ));

    let mut duplicate = fixture();
    let first = duplicate["security"]["mounts"][0].clone();
    duplicate["security"]["mounts"]
        .as_array_mut()
        .unwrap()
        .push(first);
    let plan: CompiledExecutionPlan = serde_json::from_value(duplicate).unwrap();
    assert!(matches!(
        plan.validate(),
        Err(WorkloadError::Invalid("compiled security"))
    ));

    let mut unsafe_target = fixture();
    unsafe_target["security"]["mounts"][0]["target"] = json!("/models/../escape");
    let plan: CompiledExecutionPlan = serde_json::from_value(unsafe_target).unwrap();
    assert!(matches!(
        plan.validate(),
        Err(WorkloadError::Invalid("compiled security"))
    ));
}

fn host_fabric_plan() -> Value {
    let mut value = fixture();
    value["runtime"]["placement"] = json!({
        "endpoint_address": "192.168.1.211",
        "rank": 0,
        "role": "entrypoint",
        "world_size": 2,
        "local_address": "192.168.100.10",
        "master_address": "192.168.100.10",
        "master_port": 29500,
        "port": 8000,
        "reserved_memory_bytes": 80000000
    });
    value["security"]["network_mode"] = json!("host");
    value["security"]["host_network"] = json!(true);
    value["security"]["devices"] = json!(["nvidia.com/gpu=all"]);
    value["topology"] = json!({
        "name": "dual",
        "mode": "distributed",
        "backend": "nccl",
        "node_count": 2,
        "world_size": 2,
        "rank": 0,
        "role": "entrypoint"
    });
    value
}

#[test]
fn host_network_flag_must_equal_host_network_mode() {
    let mut value = fixture();
    value["security"]["host_network"] = json!(true);
    let plan: CompiledExecutionPlan = serde_json::from_value(value).unwrap();
    assert!(matches!(
        plan.validate(),
        Err(WorkloadError::Invalid("compiled security"))
    ));
}

#[test]
fn host_mode_accepts_unresolved_two_node_endpoint_plan() {
    let mut value = host_fabric_plan();
    value["runtime"]["placement"]["local_address"] = Value::Null;
    value["runtime"]["placement"]["master_address"] = Value::Null;
    value["runtime"]["placement"]["endpoint_address"] = Value::Null;
    let plan: CompiledExecutionPlan = serde_json::from_value(value).unwrap();
    plan.validate().unwrap();
    assert!(plan.runtime.placement.validate_bound().is_err());
    assert!(plan.runtime.placement.validate_host_bound().is_err());
}

#[test]
fn host_mode_start_requires_routable_rank_roles() {
    let plan: CompiledExecutionPlan = serde_json::from_value(host_fabric_plan()).unwrap();
    plan.validate().unwrap();
    plan.runtime.placement.validate_host_bound().unwrap();

    let mut worker = host_fabric_plan();
    worker["runtime"]["placement"]["rank"] = json!(1);
    worker["runtime"]["placement"]["role"] = json!("worker");
    worker["runtime"]["placement"]["endpoint_address"] = Value::Null;
    worker["runtime"]["placement"]["local_address"] = json!("192.168.100.11");
    worker["runtime"]["placement"]["master_address"] = json!("192.168.100.10");
    worker["topology"]["rank"] = json!(1);
    worker["topology"]["role"] = json!("worker");
    let worker: CompiledExecutionPlan = serde_json::from_value(worker).unwrap();
    worker.validate().unwrap();
    worker.runtime.placement.validate_host_bound().unwrap();

    let mut nonzero_owner = host_fabric_plan();
    nonzero_owner["runtime"]["placement"]["rank"] = json!(1);
    nonzero_owner["topology"]["rank"] = json!(1);
    let nonzero_owner: CompiledExecutionPlan = serde_json::from_value(nonzero_owner).unwrap();
    nonzero_owner.validate().unwrap();
    nonzero_owner
        .runtime
        .placement
        .validate_host_bound()
        .unwrap();

    let mut inverted = host_fabric_plan();
    inverted["runtime"]["placement"]["master_address"] = json!("192.168.100.11");
    let inverted: CompiledExecutionPlan = serde_json::from_value(inverted).unwrap();
    assert!(inverted.validate().is_err());

    let mut loopback = host_fabric_plan();
    loopback["runtime"]["placement"]["local_address"] = json!("127.0.0.1");
    loopback["runtime"]["placement"]["master_address"] = json!("127.0.0.1");
    let loopback: CompiledExecutionPlan = serde_json::from_value(loopback).unwrap();
    assert!(loopback.validate().is_err());
}

#[test]
fn host_mode_rejects_single_node_job_and_partial_identity() {
    let mut single = host_fabric_plan();
    single["topology"]["mode"] = json!("single");
    single["topology"]["node_count"] = json!(1);
    single["topology"]["world_size"] = json!(1);
    single["runtime"]["placement"]["world_size"] = json!(1);
    single["runtime"]["placement"]["rank"] = json!(0);
    let single: CompiledExecutionPlan = serde_json::from_value(single).unwrap();
    assert!(single.validate().is_err());

    let mut job = host_fabric_plan();
    job["endpoint"] = Value::Null;
    job["runtime"]["placement"]["port"] = Value::Null;
    job["job"] = json!({
        "interface": "image-job",
        "input": {
            "path": "/inputs",
            "required": true,
            "media_types": ["application/octet-stream"],
            "max_bytes": 1024,
            "slots": null
        },
        "output_path": "/outputs",
        "timeout_seconds": 90
    });
    let job: CompiledExecutionPlan = serde_json::from_value(job).unwrap();
    assert!(job.validate().is_err());

    let mut extra_device = host_fabric_plan();
    extra_device["security"]["devices"] =
        json!(["nvidia.com/gpu=all", "/dev/infiniband:/dev/infiniband"]);
    let extra_device: CompiledExecutionPlan = serde_json::from_value(extra_device).unwrap();
    assert!(extra_device.validate().is_err());

    let mut missing_gpu = host_fabric_plan();
    missing_gpu["security"]["devices"] = json!([]);
    let missing_gpu: CompiledExecutionPlan = serde_json::from_value(missing_gpu).unwrap();
    assert!(missing_gpu.validate().is_err());

    let mut no_master_port = host_fabric_plan();
    no_master_port["runtime"]["placement"]["master_port"] = Value::Null;
    let no_master_port: CompiledExecutionPlan = serde_json::from_value(no_master_port).unwrap();
    assert!(no_master_port.validate().is_err());
}
