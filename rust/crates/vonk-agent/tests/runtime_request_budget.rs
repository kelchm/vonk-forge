//! The helper transport must accommodate a valid sharded workload after OCI
//! projection adds mount/environment flags, without changing its launch authority.
#![forbid(unsafe_code)]

use std::path::PathBuf;

use serde_json::{Value, json};
use uuid::Uuid;
use vonk_agent::{
    compiled_oci::CompiledOciPaths,
    executor::runtime_arguments_for_plan,
    oci::{RuntimeStartPlan, start_arguments_for_paths},
    workloads::CompiledExecutionPlan,
};
use vonk_agent_protocol::{HostRuntimeAction, HostRuntimeRequest, canonical_json};

fn sharded_workload() -> CompiledExecutionPlan {
    let mut value: Value = serde_json::from_str(include_str!(
        "../../../../control/tests/fixtures/compiled_workload_v2.json"
    ))
    .unwrap();
    // Retain the Controller fixture's target/draft/support selections and their
    // mount policy. Each additional synthetic shard belongs to that same target.
    let template = value["artifacts"][0].clone();
    for index in 0..192 {
        let mut shard = template.clone();
        let path = format!("shard-{index:03}.safetensors");
        let digest = format!("{:064x}", index + 1);
        shard["file_id"] = json!(format!("shard-{index:03}"));
        shard["path"] = json!(path);
        shard["sha256"] = json!(digest);
        shard["size_bytes"] = json!(1024);
        shard["distribution_object"]["name"] = json!(path);
        shard["distribution_object"]["sha256"] = json!(digest);
        shard["distribution_object"]["bytes"] = json!(1024);
        value["artifacts"].as_array_mut().unwrap().push(shard);
    }
    value["identity"]["model_artifact_bytes"] =
        json!(value["identity"]["model_artifact_bytes"].as_u64().unwrap() + 192 * 1024);
    for index in 0..64 {
        value["runtime"]["env"]
            .as_array_mut()
            .unwrap()
            .push(json!({"name": format!("MODEL_OPTION_{index:03}"), "value": "enabled"}));
    }
    let plan: CompiledExecutionPlan = serde_json::from_value(value).unwrap();
    plan.validate()
        .expect("the complete sharded workload is valid");
    plan
}

fn projected_request(plan: &CompiledExecutionPlan) -> HostRuntimeRequest {
    let paths = CompiledOciPaths {
        image_archive: PathBuf::from("/var/lib/vonk-forge-agent/oci-archives")
            .join(&plan.runtime_image.oci_layout_sha256),
        model_root: PathBuf::from(
            "/var/lib/vonk-forge-agent/installations/10000000-0000-4000-8000-000000000001/models",
        ),
        input_root: None,
        output_root: PathBuf::from(
            "/var/lib/vonk-forge-agent/runs/10000000-0000-4000-8000-000000000001/outputs",
        ),
        cache_root: PathBuf::from(
            "/var/lib/vonk-forge-agent/installations/10000000-0000-4000-8000-000000000001/runtime-cache",
        ),
        runtime_spec: PathBuf::from(
            "/var/lib/vonk-forge-agent/run-metadata/10000000-0000-4000-8000-000000000001/runtime.json",
        ),
    };
    let main =
        start_arguments_for_paths(plan, &paths, "10000000-0000-4000-8000-000000000001").unwrap();
    let start = RuntimeStartPlan {
        image_digest: plan.runtime_image.image_digest.clone(),
        registry_index_digest: plan
            .runtime_image
            .registry_manifest_digest
            .clone()
            .unwrap_or_else(|| plan.runtime_image.platform_manifest_digest.clone()),
        platform_manifest_digest: plan.runtime_image.platform_manifest_digest.clone(),
        archive_sha256: plan.runtime_image.oci_layout_sha256.clone(),
        image_reference: plan.runtime_image.local_image_reference(),
        pre_start: vec![],
        main,
    };
    let arguments = runtime_arguments_for_plan(&start, &start.main);
    assert_eq!(
        &arguments[..4],
        &[
            start.archive_sha256,
            start.registry_index_digest,
            start.platform_manifest_digest,
            start.image_reference,
        ]
    );
    HostRuntimeRequest {
        schema_version: 1,
        action: HostRuntimeAction::Start,
        job_id: Uuid::new_v4(),
        operation_id: Uuid::new_v4(),
        attempt: 1,
        fence: Uuid::new_v4(),
        arguments,
        observation: None,
        installation_id: None,
    }
}

#[test]
fn sharded_workload_projection_fits_helper_body_without_truncating_arguments() {
    let plan = sharded_workload();
    let request = projected_request(&plan);
    let arguments = &request.arguments;
    assert!(
        arguments.len() > 512,
        "exercise the former projected-argument cap"
    );
    let body = canonical_json(&request).unwrap();
    assert!(
        body.len() < 64 * 1024,
        "the existing helper body limit is sufficient"
    );
    assert!(arguments.iter().all(|argument| argument.len() <= 4096));

    // Growing the transport budget must not collapse files to a broad directory
    // mount, drop environment options, or lose the helper's executable binding.
    for artifact in &plan.artifacts {
        let mount = format!(
            "type=bind,src=/var/lib/vonk-forge-agent/installations/10000000-0000-4000-8000-000000000001/models/{}/{},dst={}/{},readonly",
            artifact.selection_id, artifact.path, artifact.mount.target, artifact.path
        );
        assert!(
            arguments
                .windows(2)
                .any(|pair| pair[0] == "--mount" && pair[1] == mount)
        );
    }
    for environment in &plan.runtime.env {
        let value = format!("{}={}", environment.name, environment.value);
        assert!(
            arguments
                .windows(2)
                .any(|pair| pair[0] == "--env" && pair[1] == value)
        );
    }
    let mut expected_tail = vec![
        "--entrypoint".to_owned(),
        plan.runtime.executable.clone(),
        plan.runtime_image.local_image_reference(),
        plan.runtime.executable.clone(),
    ];
    expected_tail.extend(plan.runtime.argv.clone());
    assert!(arguments.ends_with(&expected_tail));
    assert!(arguments.iter().any(|argument| argument == "--read-only"));
    assert!(
        arguments
            .iter()
            .any(|argument| argument == "--cap-drop=ALL")
    );
    assert!(
        arguments
            .iter()
            .any(|argument| argument == "--security-opt=no-new-privileges")
    );

    // Regression: the old512-item ceiling rejects here despite the valid
    // compiled plan, preserved authority and request body below64KiB.
    assert!(
        request.validate().is_ok(),
        "valid projected workload with {} arguments and {} canonical bytes must fit the host request contract",
        arguments.len(),
        body.len()
    );
}

#[test]
fn projected_environment_still_obeys_the_per_argument_byte_limit() {
    let mut value: Value = serde_json::from_str(include_str!(
        "../../../../control/tests/fixtures/compiled_workload_v2.json"
    ))
    .unwrap();
    // A valid environment value can become an oversized CLI item after the
    // real projection adds NAME=. The count-budget fix must not waive this.
    value["runtime"]["env"]
        .as_array_mut()
        .unwrap()
        .push(json!({"name": "ENGINE_OPTIONS", "value": "x".repeat(4096)}));
    let plan: CompiledExecutionPlan = serde_json::from_value(value).unwrap();
    plan.validate().unwrap();
    let request = projected_request(&plan);
    assert!(request.arguments.len() < 512);
    assert!(canonical_json(&request).unwrap().len() < 64 * 1024);
    assert!(
        request
            .arguments
            .iter()
            .any(|argument| argument.len() > 4096)
    );
    assert!(request.validate().is_err());
}
