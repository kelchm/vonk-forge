#![forbid(unsafe_code)]

use serde_json::{Value, json};
use std::{fs, os::unix::fs::symlink, path::Path, time::Duration};
use tempfile::tempdir;
use vonk_agent::{
    oci::{OciError, OciRuntime, RecipeRunStartIdentity},
    process::{ProcessError, ProcessOutput, ProcessRunner, Program},
    workloads::{CompiledExecutionPlan, Placement},
};

const INSTALLATION: &str = "cb555393-764b-4eb6-8f15-b416d289428f";
const RUN: &str = "45ea6921-50c9-4971-be2a-4cd04ce05069";
struct NoProcess;
impl ProcessRunner for NoProcess {
    fn run(&self, _: Program, _: &[String], _: Duration) -> Result<ProcessOutput, ProcessError> {
        panic!("retained-plan reconstruction must not launch a process");
    }
}

fn schema2_fixture() -> Value {
    serde_json::from_str(include_str!(
        "../../../../control/tests/fixtures/compiled_workload_v2.json"
    ))
    .unwrap()
}

fn schema2_dual_plan() -> CompiledExecutionPlan {
    let mut value = schema2_fixture();
    value["runtime"]["placement"] = json!({
        "endpoint_address": "192.168.1.212", "rank": 1, "role": "worker", "world_size": 2,
        "local_address": "192.168.100.11", "master_address": "192.168.100.10",
        "master_port": 29500, "port": 8000, "reserved_memory_bytes": 68719476736_u64
    });
    value["security"]["network_mode"] = json!("bridge");
    value["topology"] = json!({
        "name": "dual", "mode": "distributed", "backend": "nccl",
        "node_count": 2, "world_size": 2, "rank": 1, "role": "worker"
    });
    let plan: CompiledExecutionPlan = serde_json::from_value(value).unwrap();
    plan.validate().unwrap();
    plan
}

fn schema2_installation_plan() -> CompiledExecutionPlan {
    let mut value = schema2_fixture();
    value["runtime"]["placement"] = json!({
        "endpoint_address": null, "rank": 1, "role": "worker", "world_size": 2,
        "local_address": null, "master_address": null,
        "master_port": 29500, "port": 8000, "reserved_memory_bytes": 80000000_u64
    });
    value["security"]["network_mode"] = json!("bridge");
    value["topology"] = json!({
        "name": "dual", "mode": "distributed", "backend": "nccl",
        "node_count": 2, "world_size": 2, "rank": 1, "role": "worker"
    });
    let plan: CompiledExecutionPlan = serde_json::from_value(value).unwrap();
    plan.validate().unwrap();
    plan
}

fn schema2_launch_plan() -> CompiledExecutionPlan {
    let mut value = schema2_fixture();
    value["runtime"]["placement"] = json!({
        "endpoint_address": "192.168.1.212", "rank": 1, "role": "worker", "world_size": 2,
        "local_address": "192.168.100.11", "master_address": "192.168.100.10",
        "master_port": 29500, "port": 9000, "reserved_memory_bytes": 68719476736_u64
    });
    value["security"]["network_mode"] = json!("bridge");
    value["topology"] = json!({
        "name": "dual", "mode": "distributed", "backend": "nccl",
        "node_count": 2, "world_size": 2, "rank": 1, "role": "worker"
    });
    let plan: CompiledExecutionPlan = serde_json::from_value(value).unwrap();
    plan.validate().unwrap();
    plan
}

fn persist_plan(root: &Path, plan: &CompiledExecutionPlan) {
    let directory = root.join("installations").join(INSTALLATION);
    fs::create_dir_all(&directory).unwrap();
    fs::write(
        directory.join("spec.json"),
        serde_json::to_vec(plan).unwrap(),
    )
    .unwrap();
    fs::write(
        directory.join("recipe-content.sha256"),
        &plan.identity.recipe_revision_sha256,
    )
    .unwrap();
}

fn placement(plan: &CompiledExecutionPlan) -> Placement {
    serde_json::from_value(serde_json::to_value(&plan.runtime.placement).unwrap()).unwrap()
}

fn identity(plan: &CompiledExecutionPlan) -> RecipeRunStartIdentity {
    RecipeRunStartIdentity {
        mapping_generation: 3,
        mapping_id: "11111111-1111-4111-8111-111111111111".parse().unwrap(),
        recipe_content_sha256: plan.identity.recipe_revision_sha256.clone(),
        recipe_revision_id: "22222222-2222-4222-8222-222222222222".parse().unwrap(),
        run_generation: 2,
    }
}

fn started_distinct_run(root: &Path) -> (CompiledExecutionPlan, Placement, RecipeRunStartIdentity) {
    let installation = schema2_installation_plan();
    let launch = schema2_launch_plan();
    assert_ne!(installation, launch);
    persist_plan(root, &installation);
    let runtime = OciRuntime {
        runner: &NoProcess,
        data_root: root,
        huggingface_curl_config: None,
    };
    let placement = placement(&launch);
    let identity = identity(&installation);
    runtime
        .prepare_start_with_inspection_identity(&launch, INSTALLATION, RUN, &placement, &identity)
        .unwrap();
    (launch, placement, identity)
}

#[test]
fn retained_inspection_preserves_live_tmp_and_cache_but_actual_start_resets_tmp() {
    let root = tempdir().unwrap();
    let plan = schema2_dual_plan();
    persist_plan(root.path(), &plan);
    let runtime = OciRuntime {
        runner: &NoProcess,
        data_root: root.path(),
        huggingface_curl_config: None,
    };
    let placement = placement(&plan);
    let identity = identity(&plan);
    runtime
        .prepare_start_with_inspection_identity(&plan, INSTALLATION, RUN, &placement, &identity)
        .unwrap();
    let marker = root
        .path()
        .join("runs")
        .join(RUN)
        .join("outputs/tmp/live.marker");
    let cache = root
        .path()
        .join("installations")
        .join(INSTALLATION)
        .join("runtime-cache/live.marker");
    fs::write(&marker, b"live kernel workspace").unwrap();
    fs::write(&cache, b"persistent cache").unwrap();

    runtime
        .prepare_retained_start(&plan, INSTALLATION, RUN, &placement)
        .unwrap();
    runtime
        .prepare_retained_start_with_inspection_identity(
            &plan,
            INSTALLATION,
            RUN,
            &placement,
            &identity,
        )
        .unwrap();
    let inspections = runtime.recipe_run_inspection_plans().unwrap();
    assert_eq!(inspections.len(), 1);
    assert_eq!(
        &inspections[0].arguments[..4],
        &[
            plan.runtime_image.oci_layout_sha256.clone(),
            plan.runtime_image.registry_manifest_digest.clone().unwrap(),
            plan.runtime_image.platform_manifest_digest.clone(),
            plan.runtime_image.local_image_reference.clone(),
        ]
    );
    assert_eq!(fs::read(&marker).unwrap(), b"live kernel workspace");
    assert_eq!(fs::read(&cache).unwrap(), b"persistent cache");

    runtime.complete_stop(RUN).unwrap();
    runtime
        .prepare_start_with_inspection_identity(&plan, INSTALLATION, RUN, &placement, &identity)
        .unwrap();
    assert!(!marker.exists());
    assert_eq!(fs::read(cache).unwrap(), b"persistent cache");
}

#[test]
fn real_751_artifact_spec_json_round_trips_through_persisted_loader() {
    let plan: CompiledExecutionPlan = serde_json::from_str(include_str!(
        "../../../../control/tests/fixtures/compiled_plan_751.json"
    ))
    .unwrap();
    plan.validate().unwrap();
    let root = tempdir().unwrap();
    let directory = root.path().join("installations").join(INSTALLATION);
    fs::create_dir_all(&directory).unwrap();
    let encoded = serde_json::to_vec(&plan).unwrap();
    assert!(encoded.len() > 500 * 1024);
    fs::write(directory.join("spec.json"), &encoded).unwrap();
    let runtime = OciRuntime {
        runner: &NoProcess,
        data_root: root.path(),
        huggingface_curl_config: None,
    };
    let loaded = runtime.load_spec(INSTALLATION).unwrap();
    assert_eq!(loaded.artifacts.len(), 751);
}

#[test]
fn retained_inspection_uses_resolved_launch_plan_not_installation_spec() {
    let root = tempdir().unwrap();
    let (launch, _, _) = started_distinct_run(root.path());
    let runtime = OciRuntime {
        runner: &NoProcess,
        data_root: root.path(),
        huggingface_curl_config: None,
    };

    let inspections = runtime.recipe_run_inspection_plans().unwrap();
    assert_eq!(inspections.len(), 1);
    assert!(
        inspections[0]
            .arguments
            .iter()
            .any(|argument| argument == "VONK_LOCAL_ADDR=192.168.100.11")
    );
    assert!(
        inspections[0]
            .arguments
            .iter()
            .any(|argument| argument.contains("192.168.1.212:9000:8000"))
    );
    assert_eq!(inspections[0].endpoint_port, 9000);
    assert_eq!(
        inspections[0].arguments[0],
        launch.runtime_image.oci_layout_sha256
    );
}

#[test]
fn retained_collective_readiness_matches_resolved_launch_arguments() {
    let root = tempdir().unwrap();
    let installation = schema2_installation_plan();
    let launch = schema2_launch_plan();
    persist_plan(root.path(), &installation);
    let runtime = OciRuntime {
        runner: &NoProcess,
        data_root: root.path(),
        huggingface_curl_config: None,
    };
    let placement = placement(&launch);
    let identity = identity(&installation);
    let started = runtime
        .prepare_start_with_inspection_identity(&launch, INSTALLATION, RUN, &placement, &identity)
        .unwrap();

    let retained = runtime
        .prepare_retained_start(&launch, INSTALLATION, RUN, &placement)
        .unwrap();
    runtime
        .prepare_retained_start_with_inspection_identity(
            &launch,
            INSTALLATION,
            RUN,
            &placement,
            &identity,
        )
        .unwrap();

    assert!(retained.pre_start.is_empty());
    assert_eq!(retained.main, started.main);
    assert!(
        runtime
            .prepare_retained_start(&installation, INSTALLATION, RUN, &placement)
            .is_err()
    );
}

#[test]
fn retained_run_plan_rejects_missing_corrupt_symlink_and_foreign_plans() {
    let cases = ["missing", "corrupt", "symlink", "foreign"];
    for case in cases {
        let root = tempdir().unwrap();
        let (launch, placement, _) = started_distinct_run(root.path());
        let runtime_path = root
            .path()
            .join("run-metadata")
            .join(RUN)
            .join("runtime.json");
        match case {
            "missing" => fs::remove_file(&runtime_path).unwrap(),
            "corrupt" => fs::write(&runtime_path, b"not-json").unwrap(),
            "symlink" => {
                let outside = root.path().join("foreign-runtime.json");
                fs::copy(&runtime_path, &outside).unwrap();
                fs::remove_file(&runtime_path).unwrap();
                symlink(&outside, &runtime_path).unwrap();
            }
            "foreign" => {
                let mut foreign = launch.clone();
                foreign.identity.recipe_revision_sha256 = "ab".repeat(32);
                foreign.validate().unwrap();
                fs::write(&runtime_path, serde_json::to_vec(&foreign).unwrap()).unwrap();
            }
            _ => unreachable!(),
        }
        let runtime = OciRuntime {
            runner: &NoProcess,
            data_root: root.path(),
            huggingface_curl_config: None,
        };
        match case {
            "corrupt" => assert!(
                matches!(
                    runtime.recipe_run_inspection_plans(),
                    Err(OciError::Json(_))
                ),
                "case {case}"
            ),
            _ => assert!(
                matches!(
                    runtime.recipe_run_inspection_plans(),
                    Err(OciError::Artifact)
                ),
                "case {case}"
            ),
        }
        assert!(
            runtime
                .prepare_retained_start(&launch, INSTALLATION, RUN, &placement)
                .is_err(),
            "case {case}"
        );
    }
}

#[test]
fn retained_single_inspection_keeps_resolved_endpoint_and_bridge_network() {
    let root = tempdir().unwrap();
    let installed: CompiledExecutionPlan = serde_json::from_value(schema2_fixture()).unwrap();
    installed.validate().unwrap();
    assert_eq!(installed.security.network_mode, "none");
    assert!(installed.runtime.placement.endpoint_address.is_none());
    let mut launch = installed.clone();
    launch.runtime.placement.endpoint_address = Some("172.31.171.1".parse().unwrap());
    launch.security.network_mode = "bridge".to_owned();
    launch.validate().unwrap();
    persist_plan(root.path(), &installed);
    let runtime = OciRuntime {
        runner: &NoProcess,
        data_root: root.path(),
        huggingface_curl_config: None,
    };
    let started = runtime
        .prepare_start_with_inspection_identity(
            &launch,
            INSTALLATION,
            RUN,
            &placement(&launch),
            &identity(&installed),
        )
        .unwrap();
    let plans = runtime.recipe_run_inspection_plans().unwrap();
    assert_eq!(plans.len(), 1);
    assert_eq!(plans[0].arguments, started.main);
    assert!(
        plans[0]
            .arguments
            .iter()
            .any(|arg| arg == "172.31.171.1:8000:8000")
    );
    runtime.prepare_stop(RUN).unwrap();
    assert_eq!(runtime.load_spec(INSTALLATION).unwrap(), installed);
}
