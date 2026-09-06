#![forbid(unsafe_code)]

use serde_json::{Value, json};
use std::{fs, path::Path, time::Duration};
use tempfile::tempdir;
use vonk_agent::{
    oci::{OciRuntime, RecipeRunStartIdentity},
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

fn schema2_dual_plan() -> CompiledExecutionPlan {
    let mut value: Value = serde_json::from_str(include_str!(
        "../../../../control/tests/fixtures/compiled_workload_v2.json"
    ))
    .unwrap();
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
fn exact_snapshot_survives_atomic_stop_and_job_cleanup_without_losing_live_run() {
    use std::{
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        thread,
    };
    let root = tempdir().unwrap();
    let plan = schema2_dual_plan();
    persist_plan(root.path(), &plan);
    let runtime = OciRuntime {
        runner: &NoProcess,
        data_root: root.path(),
        huggingface_curl_config: None,
    };
    let stopping = "55ea6921-50c9-4971-be2a-4cd04ce05069";
    let job = "65ea6921-50c9-4971-be2a-4cd04ce05069";
    for run in [RUN, stopping] {
        runtime
            .prepare_start_with_inspection_identity(
                &plan,
                INSTALLATION,
                run,
                &placement(&plan),
                &identity(&plan),
            )
            .unwrap();
    }
    let marker = root
        .path()
        .join("run-metadata")
        .join(stopping)
        .join("lifecycle.json");
    let record = fs::read(&marker).unwrap();
    let done = Arc::new(AtomicBool::new(false));
    let writer_done = done.clone();
    let writer_root = root.path().to_path_buf();
    let writer = thread::spawn(move || {
        let runtime = OciRuntime {
            runner: &NoProcess,
            data_root: &writer_root,
            huggingface_curl_config: None,
        };
        for _ in 0..200 {
            runtime.complete_stop(stopping).unwrap();
            fs::create_dir_all(writer_root.join("runs").join(job)).unwrap();
            runtime.cleanup_job_scope(job).unwrap();
            let temporary = marker.with_extension("pending");
            fs::write(&temporary, &record).unwrap();
            fs::rename(temporary, &marker).unwrap();
        }
        runtime.complete_stop(stopping).unwrap();
        writer_done.store(true, Ordering::SeqCst);
    });
    let mut cycles = 0;
    while !done.load(Ordering::SeqCst) || cycles < 200 {
        let snapshot = runtime.recipe_run_inspection_plans().unwrap();
        assert!(
            snapshot
                .iter()
                .any(|plan| plan.binding.run_id.to_string() == RUN)
        );
        assert!(
            snapshot
                .iter()
                .all(|plan| [RUN, stopping].contains(&plan.binding.run_id.to_string().as_str()))
        );
        cycles += 1;
    }
    writer.join().unwrap();
    let snapshot = runtime.recipe_run_inspection_plans().unwrap();
    assert_eq!(snapshot.len(), 1);
    assert_eq!(snapshot[0].binding.run_id.to_string(), RUN);
}
