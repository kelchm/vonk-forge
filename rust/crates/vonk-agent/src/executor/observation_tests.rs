//! Snapshot tests use the real retained-plan collector and HTTP reporter.
//! Only the privileged signed-inspection boundary is replaced; these fixtures
//! are not cryptographic or physical helper acceptance evidence.
use super::*;
use crate::{
    client::AgentHttpClient,
    process::{ProcessError, ProcessOutput, Program},
    workloads::*,
};
use std::{
    io::{Read, Write},
    net::TcpListener,
    thread,
};
use tempfile::tempdir;
use uuid::Uuid;
use vonk_agent_protocol::{
    RECIPE_RUN_OBSERVATION_RECEIPT_AUTHORITY, RecipeRunObservationOutcome,
    RecipeRunObservationReceipt, RecipeRunObservationReceiptClaims,
    RecipeRunObservationReceiptSignature,
};
const DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const NODE: &str = "spk_0123456789abcdef0123456789abcdef";
struct NoProcess;
impl ProcessRunner for NoProcess {
    fn run(&self, _: Program, _: &[String], _: Duration) -> Result<ProcessOutput, ProcessError> {
        panic!("worker inspection fixture must not probe an endpoint");
    }
}
fn spec() -> CompiledExecutionPlan {
    let mut value: Value = serde_json::from_str(include_str!(
        "../../../../../control/tests/fixtures/compiled_workload_v2.json"
    ))
    .unwrap();
    value["identity"]["recipe_revision_sha256"] = json!(DIGEST);
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

fn write_persisted_installation(root: &Path, installation_id: &str, plan: &CompiledExecutionPlan) {
    let installation = root.join("installations").join(installation_id);
    fs::create_dir_all(&installation).unwrap();
    fs::write(
        installation.join("spec.json"),
        serde_json::to_vec(plan).unwrap(),
    )
    .unwrap();
    fs::write(
        installation.join("recipe-content.sha256"),
        &plan.identity.recipe_revision_sha256,
    )
    .unwrap();
}

fn report_server(
    count: usize,
    stopping: Option<String>,
) -> (AgentHttpClient, thread::JoinHandle<Vec<Value>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let client = AgentHttpClient::for_http_test(
        &format!("http://{}/", listener.local_addr().unwrap()),
        NODE,
    );
    let server = thread::spawn(move || {
        let mut bodies = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(5);
        while bodies.len() < count {
            let (mut socket, _) = match listener.accept() {
                Ok(connection) => connection,
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        && Instant::now() < deadline =>
                {
                    thread::sleep(Duration::from_millis(1));
                    continue;
                }
                Err(error) => panic!("observation report missing: {error}"),
            };
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut raw = Vec::new();
            let mut buffer = [0; 4096];
            let end = loop {
                let n = socket.read(&mut buffer).unwrap();
                assert_ne!(n, 0);
                raw.extend_from_slice(&buffer[..n]);
                if let Some(i) = raw.windows(4).position(|v| v == b"\r\n\r\n") {
                    break i + 4;
                }
            };
            let headers = std::str::from_utf8(&raw[..end]).unwrap();
            assert!(headers.starts_with("POST /agent/v1/recipe-runs/observations HTTP/1.1"));
            let size: usize = headers
                .lines()
                .find_map(|line| {
                    let (key, value) = line.split_once(':')?;
                    key.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse().unwrap())
                })
                .unwrap();
            while raw.len() - end < size {
                let n = socket.read(&mut buffer).unwrap();
                assert_ne!(n, 0);
                raw.extend_from_slice(&buffer[..n]);
            }
            let body: Value = serde_json::from_slice(&raw[end..]).unwrap();
            let stopped = stopping
                .as_ref()
                .is_some_and(|run| body["runs"][0]["run_id"].as_str() == Some(run.as_str()));
            bodies.push(body);
            if stopped {
                socket
                    .write_all(
                        b"HTTP/1.1 425 Too Early\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    )
                    .unwrap();
                continue;
            }
            socket
                .write_all(
                    b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .unwrap();
        }
        bodies
    });
    (client, server)
}

#[tokio::test]
async fn retained_stop_transition_preserves_other_exact_report_but_protocol_error_clears_snapshot()
{
    for mode in ["grant-transition", "report-transition", "protocol-error"] {
        let typed_transition = mode != "protocol-error";
        let root = tempdir().unwrap();
        let requests = tempdir().unwrap();
        let installation = "cb555393-764b-4eb6-8f15-b416d289428f";
        let stopping = "45ea6921-50c9-4971-be2a-4cd04ce05069";
        let running = "55ea6921-50c9-4971-be2a-4cd04ce05069";
        let workload = spec();
        write_persisted_installation(root.path(), installation, &workload);
        let runtime = OciRuntime {
            runner: &NoProcess,
            data_root: root.path(),
            huggingface_curl_config: None,
        };
        let placement = Placement {
            endpoint_address: Some("192.168.1.212".parse().unwrap()),
            rank: 1,
            role: "worker".into(),
            world_size: 2,
            local_address: Some("192.168.100.11".parse().unwrap()),
            master_address: Some("192.168.100.10".parse().unwrap()),
            master_port: Some(29500),
            port: 8000,
            reserved_memory_bytes: 64 * 1024 * 1024 * 1024,
        };
        let identity = RecipeRunStartIdentity {
            mapping_generation: 3,
            mapping_id: "11111111-1111-4111-8111-111111111111".parse().unwrap(),
            recipe_content_sha256: DIGEST.into(),
            recipe_revision_id: "22222222-2222-4222-8222-222222222222".parse().unwrap(),
            run_generation: 2,
        };
        for run in [stopping, running] {
            runtime
                .prepare_start_with_inspection_identity(
                    &workload,
                    installation,
                    run,
                    &placement,
                    &identity,
                )
                .unwrap();
        }
        assert_eq!(runtime.recipe_run_inspection_plans().unwrap().len(), 2);
        let (client, server) = report_server(
            if mode == "grant-transition" { 1 } else { 2 },
            (mode == "report-transition").then(|| stopping.to_owned()),
        );
        let executor = RecipeExecutor {
            client: &client,
            runtime,
            runtime_root: requests.path(),
            observation_receipt_public_key: [0; 32],
        };
        let observed_at = Utc::now().timestamp() - 2;
        let result = executor.report_exact_recipe_run_observations_with(|plan| async move {
   if plan.binding.run_id.to_string() == stopping && mode != "report-transition" {
    return Err(HostRuntimeError::Controller(if typed_transition { ClientError::ObservationNotReady } else { ClientError::Protocol }));
   }
   assert!([stopping, running].contains(&plan.binding.run_id.to_string().as_str()));
   let receipt = RecipeRunObservationReceipt {
    schema_version: 1,
    claims: RecipeRunObservationReceiptClaims {
     schema_version: 1, authority: RECIPE_RUN_OBSERVATION_RECEIPT_AUTHORITY.into(), node_id: NODE.into(),
     request_id: Uuid::new_v4(), request_sha256: "f".repeat(64), observation_identity_sha256: "e".repeat(64),
     outcome: RecipeRunObservationOutcome::Running, observed_at,
    },
    signature: RecipeRunObservationReceiptSignature { algorithm: "ed25519".into(), key_id: "a".repeat(64), value: "b".repeat(128) },
   };
   Ok(RecipeRunInspectionOutcome {
    grant: json!({"claims": {"request_id": receipt.claims.request_id, "request_sha256": receipt.claims.request_sha256}}),
    observation_identity_sha256: "e".repeat(64), receipt, process_running: true,
   })
  }).await;
        assert_eq!(result.unwrap_err().not_ready(), typed_transition);
        let reports = server.join().unwrap();
        let live_report = reports
            .iter()
            .find(|report| report["runs"][0]["run_id"] == running)
            .unwrap();
        assert_eq!(live_report["schema_version"], 2);
        assert_eq!(live_report["runs"].as_array().unwrap().len(), 1);
        let timestamp = live_report["runs"][0]["observed_at"].as_str().unwrap();
        if typed_transition {
            assert!(
                reports
                    .iter()
                    .all(|report| !report["runs"].as_array().unwrap().is_empty())
            );
        }
        assert_eq!(
            DateTime::parse_from_rfc3339(timestamp).unwrap().timestamp(),
            observed_at
        );
        if !typed_transition {
            assert_eq!(reports[1]["runs"], json!([]));
        }
        executor.runtime.complete_stop(stopping).unwrap();
        let plans = executor.runtime.recipe_run_inspection_plans().unwrap();
        assert_eq!(plans.len(), 1);
        assert_eq!(plans[0].binding.run_id.to_string(), running);
    }
}
