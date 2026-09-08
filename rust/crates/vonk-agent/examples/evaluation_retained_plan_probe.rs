//! Fork-only read-only reproduction against disposable canary metadata.
#![forbid(unsafe_code)]
use std::{path::Path, time::Duration};
use vonk_agent::{
    oci::OciRuntime,
    process::{ProcessError, ProcessOutput, ProcessRunner, Program},
};
struct NoProcess;
impl ProcessRunner for NoProcess {
    fn run(&self, _: Program, _: &[String], _: Duration) -> Result<ProcessOutput, ProcessError> {
        panic!("read-only evaluation probe must never launch a process");
    }
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("GITHUB_REPOSITORY").as_deref() != Ok("kelchm/vonk-forge") {
        return Err("probe is restricted to disposable evaluation fork CI".into());
    }
    let runtime = OciRuntime {
        runner: &NoProcess,
        data_root: Path::new("/var/lib/vonk-forge-agent"),
        huggingface_curl_config: None,
    };
    let plans = runtime.recipe_run_inspection_plans()?;
    if plans.len() != 1 {
        return Err("expected one retained synthetic canary".into());
    }
    for plan in plans {
        // Constructs stop arguments only. No engine, helper or HTTP call.
        runtime.prepare_stop(&plan.binding.run_id.to_string())?;
        println!(
            "{}",
            serde_json::json!({"run_id": plan.binding.run_id,
            "inspection_reconstructed": true, "stop_reconstructed": true,
            "endpoint_address": plan.endpoint_address, "endpoint_port": plan.endpoint_port})
        );
    }
    Ok(())
}
