//! Teardown validates current storage authority without granting launch authority.
use vonk_agent_protocol::generated::CompiledExecutionPlan;

fn plan() -> CompiledExecutionPlan {
    serde_json::from_str(include_str!(
        "../../../../control/tests/fixtures/compiled_workload_v2.json"
    ))
    .unwrap()
}

#[test]
fn storage_validation_does_not_admit_an_unlaunchable_runtime() {
    let mut plan = plan();
    plan.validate().unwrap();
    plan.security.privileged = true;
    plan.validate_storage().unwrap();
    assert!(plan.validate().is_err());
}

#[test]
fn storage_validation_still_rejects_identity_paths_and_artifact_bytes() {
    for defect in ["identity", "path", "bytes"] {
        let mut plan = plan();
        match defect {
            "identity" => plan.identity.recipe_revision_sha256 = "bad".to_owned(),
            "path" => plan.artifacts[0].path = "../../outside".to_owned(),
            "bytes" => plan.identity.model_artifact_bytes += 1,
            _ => unreachable!(),
        }
        assert!(plan.validate_storage().is_err(), "{defect}");
        assert!(plan.validate().is_err(), "{defect}");
    }
}
