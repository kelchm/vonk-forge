#![forbid(unsafe_code)]

use std::{
    future::Future,
    io::{self, Read},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use clap::{Parser, Subcommand};
use url::Url;
use vonk_agent::{
    agent_upgrade::AgentUpgradeExecutor,
    client::{AgentHttpClient, ClientError},
    config::{AgentConfig, DEFAULT_CONFIG_PATH},
    executor::{
        ControlExecutor, LoopError, RecipeExecutor, RecipeObservationError,
        run_once_with_claim_hook,
    },
    inventory::InventoryCollector,
    oci::OciRuntime,
    pair::{collect_evidence, complete_pairing_with, pair},
    process::SystemProcessRunner,
    readiness::{publish_current, verify_current},
    rotation::rotate_if_due,
    runtime_identity::AgentRuntimeIdentity,
    self_test,
    state::{StateStore, backoff_delay},
    telemetry::{
        SystemFileSystemProvider, TelemetryCollector, TelemetryPaths, TelemetryQueue,
        TelemetrySchedule, read_boot_id,
    },
};

const CLAIM_CAPABILITIES: &[&str] = &[
    "agent.runtime.rust.v1",
    "runtime.vonk.v1",
    "agent.upgrade.v1",
    "artifact.distribution.v1",
    "recipe.build.v1",
    "recipe.image.import.v1",
    "recipe.job.run.v1",
    "recipe.install",
    "recipe.start",
    "recipe.start.two-phase.v1",
    "recipe.run.inspect.exact.v1",
    "recipe.run.inspect.receipt.v1",
    "recipe.stop",
    "recipe.uninstall",
    "recipe.model-uninstall.v1",
];

#[derive(Parser)]
#[command(
    name = "vonk-agent",
    version = env!("VONK_AGENT_SEMANTIC_VERSION"),
    about = "Vonk Forge outbound agent"
)]
struct Cli {
    #[arg(long, default_value = DEFAULT_CONFIG_PATH)]
    config: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Capabilities,
    Run,
    SelfTest,
    VerifyReadiness {
        #[arg(long, default_value = "/run/vonk-forge-agent/readiness.json")]
        receipt: PathBuf,
        #[arg(long)]
        pid: u32,
        #[arg(long, default_value_t = 90)]
        max_age_seconds: u64,
    },
    Pair {
        #[arg(long)]
        enrollment: Url,
        #[arg(long)]
        ca_sha256: String,
        #[arg(long, default_value_t = false)]
        token_stdin: bool,
    },
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    match cli.command {
        Command::Capabilities => {
            println!("{}", serde_json::to_string(CLAIM_CAPABILITIES)?);
        }
        Command::Run => run_agent(&AgentConfig::load(&cli.config)?).await?,
        Command::SelfTest => {
            let config = AgentConfig::load(&cli.config)?;
            let identity = self_test::run(
                &config,
                &std::env::current_exe()?,
                Path::new("/run/vonk-forge-agent"),
            )?;
            println!("{}", serde_json::to_string(&identity)?);
        }
        Command::VerifyReadiness {
            receipt,
            pid,
            max_age_seconds,
        } => {
            let config = AgentConfig::load(&cli.config)?;
            let identity = self_test::run(
                &config,
                &std::env::current_exe()?,
                Path::new("/run/vonk-forge-agent"),
            )?;
            verify_current(
                &receipt,
                &identity,
                pid,
                std::time::Duration::from_secs(max_age_seconds),
            )?;
        }
        Command::Pair {
            enrollment,
            ca_sha256,
            token_stdin,
        } => {
            if !token_stdin {
                return Err("pairing token must be supplied through --token-stdin".into());
            }
            let mut token = String::new();
            io::stdin().take(4096).read_to_string(&mut token)?;
            pair_agent(
                &AgentConfig::load(&cli.config)?,
                &enrollment,
                token.trim(),
                &ca_sha256,
            )
            .await?;
        }
    }
    Ok(())
}

async fn pair_agent(
    config: &AgentConfig,
    enrollment: &Url,
    token: &str,
    ca_sha256: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let executable = std::env::current_exe()?;
    let evidence = collect_evidence(&executable)?;
    complete_pairing_with(
        180,
        std::time::Duration::from_secs(5),
        || {
            let evidence = evidence.clone();
            async move { pair(config, enrollment, token, ca_sha256, evidence).await }
        },
        |pending| {
            println!(
                "pairing {} is {}; waiting for approval",
                pending.id, pending.state
            )
        },
    )
    .await?;
    println!("paired {}", config.node_id);
    Ok(())
}

async fn run_agent(config: &AgentConfig) -> Result<(), Box<dyn std::error::Error>> {
    let runtime_identity = self_test::run(
        config,
        &std::env::current_exe()?,
        Path::new("/run/vonk-forge-agent"),
    )?;
    rotate_if_due(config).await?;
    let client = AgentHttpClient::from_config(config)?;
    let mut state = StateStore::open(&config.data_dir.join("state.sqlite"), &config.node_id)?;
    state.recover_interrupted()?;
    let (client_updates, telemetry_client) = tokio::sync::watch::channel(client.clone());
    let rotation = Arc::new(tokio::sync::Mutex::new(()));
    let (managed_updates, managed_runs) = tokio::sync::watch::channel(0);
    let observations = run_observation_lane(
        config.clone(),
        runtime_identity.observation_receipt_public_key()?,
        telemetry_client.clone(),
        managed_updates,
        rotation.clone(),
    );
    let control = run_control_lane(
        config,
        runtime_identity,
        client,
        state,
        client_updates,
        managed_runs,
        rotation,
    );
    let telemetry = run_telemetry_lane(
        config.data_dir.clone(),
        telemetry_client,
        config.poll_min_seconds,
        config.poll_max_seconds,
    );
    match supervise_lanes(control, observations, telemetry, tokio::signal::ctrl_c()).await {
        LaneExit::Control(result) => result,
        LaneExit::Observation(Ok(Err(error))) => Err(error),
        LaneExit::Observation(Err(error)) => Err(error.into()),
        LaneExit::Observation(Ok(Ok(()))) => Err("runtime observation lane stopped".into()),
        LaneExit::Shutdown(signal) => {
            signal?;
            Ok(())
        }
    }
}

async fn run_control_lane(
    config: &AgentConfig,
    runtime_identity: AgentRuntimeIdentity,
    mut client: AgentHttpClient,
    mut state: StateStore,
    client_updates: tokio::sync::watch::Sender<AgentHttpClient>,
    managed_runs: tokio::sync::watch::Receiver<usize>,
    rotation: Arc<tokio::sync::Mutex<()>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let runner = SystemProcessRunner;
    let mut failures = 0_u32;
    let mut next_inventory = tokio::time::Instant::now();
    let mut readiness_published = false;
    loop {
        if tokio::time::Instant::now() >= next_inventory {
            {
                // Activation immediately revokes the prior certificate. Never
                // revoke it during an in-flight observation/grant exchange.
                let _rotation = rotation.lock().await;
                if rotate_if_due(config).await? {
                    client = AgentHttpClient::from_config(config)?;
                    client_updates.send_replace(client.clone());
                }
            }
            let inventory = InventoryCollector {
                runner: &runner,
                meminfo_path: Path::new("/proc/meminfo"),
                store_path: &config.data_dir,
                egress_binary_path: Path::new("/usr/lib/vonk-forge/vonk-build-egress"),
                fabric_address: config.fabric_address,
                fabric_bandwidth_mbps: config.fabric_bandwidth_mbps,
            }
            .collect()?;
            match client.report_inventory(&inventory).await {
                Ok(()) => {
                    failures = 0;
                    next_inventory =
                        tokio::time::Instant::now() + std::time::Duration::from_secs(60);
                }
                Err(error) if error.retryable() => {
                    failures = failures.saturating_add(1);
                    let entropy =
                        SystemTime::now().duration_since(UNIX_EPOCH)?.subsec_nanos() as u64;
                    tokio::time::sleep(backoff_delay(
                        failures,
                        entropy,
                        config.poll_min_seconds,
                        config.poll_max_seconds,
                    ))
                    .await;
                    continue;
                }
                Err(error) => return Err(error.into()),
            }
        }
        let executor = ControlExecutor {
            recipes: RecipeExecutor {
                client: &client,
                runtime_root: Path::new("/run/vonk-forge-agent"),
                observation_receipt_public_key: runtime_identity
                    .observation_receipt_public_key()?,
                runtime: OciRuntime {
                    runner: &runner,
                    data_root: &config.data_dir,
                    huggingface_curl_config: config.huggingface_curl_config.as_deref(),
                },
            },
            upgrades: AgentUpgradeExecutor {
                client: &client,
                incoming: Path::new("/var/lib/vonk-forge/incoming"),
            },
        };
        let wait_seconds = claim_wait_seconds(
            config.poll_max_seconds,
            *managed_runs.borrow(),
            readiness_published,
        );
        let operation = run_once_with_claim_hook(
            &client,
            &mut state,
            &executor,
            CLAIM_CAPABILITIES,
            wait_seconds,
            Some(&runtime_identity),
            || {
                publish_current(
                    Path::new("/run/vonk-forge-agent/readiness.json"),
                    &runtime_identity,
                )
                .map_err(|error| LoopError::Readiness(error.to_string()))
            },
        );
        match operation.await {
            Ok(()) => {
                failures = 0;
                readiness_published = true;
            }
            Err(error) if matches!(&error, vonk_agent::executor::LoopError::Client(inner) if inner.retryable()) =>
            {
                failures = failures.saturating_add(1);
                let entropy = SystemTime::now().duration_since(UNIX_EPOCH)?.subsec_nanos() as u64;
                tokio::time::sleep(backoff_delay(
                    failures,
                    entropy,
                    config.poll_min_seconds,
                    config.poll_max_seconds,
                ))
                .await;
            }
            Err(error) => return Err(error.into()),
        }
    }
}

type ObservationError = Box<dyn std::error::Error + Send + Sync>;

struct ObservationCycle {
    managed_runs: usize,
    failures: u32,
    delay: Duration,
}

async fn run_observation_lane(
    config: AgentConfig,
    receipt_key: [u8; 32],
    clients: tokio::sync::watch::Receiver<AgentHttpClient>,
    managed_runs: tokio::sync::watch::Sender<usize>,
    rotation: Arc<tokio::sync::Mutex<()>>,
) -> Result<(), ObservationError> {
    run_observation_cycles(clients, managed_runs, rotation, move |client, failures| {
        let config = config.clone();
        async move { collect_observation_cycle(&config, receipt_key, &client, failures).await }
    })
    .await
}

// Each cycle owns its current client and completes before the next begins. A
// credential rotation is consumed at the next cycle, never halfway through an
// inspection/grant/receipt exchange. No prior observation is replayed.
async fn run_observation_cycles<C, F, Fut, E>(
    clients: tokio::sync::watch::Receiver<C>,
    managed_runs: tokio::sync::watch::Sender<usize>,
    rotation: Arc<tokio::sync::Mutex<()>>,
    mut collect: F,
) -> Result<(), E>
where
    C: Clone,
    F: FnMut(C, u32) -> Fut,
    Fut: Future<Output = Result<ObservationCycle, E>>,
{
    let mut failures = 0;
    loop {
        let rotation_guard = rotation.lock().await;
        let client = clients.borrow().clone();
        let cycle = collect(client, failures).await?;
        drop(rotation_guard);
        failures = cycle.failures;
        managed_runs.send_replace(cycle.managed_runs);
        tokio::time::sleep(cycle.delay).await;
    }
}

async fn collect_observation_cycle(
    config: &AgentConfig,
    receipt_key: [u8; 32],
    client: &AgentHttpClient,
    mut failures: u32,
) -> Result<ObservationCycle, ObservationError> {
    let runner = SystemProcessRunner;
    let executor = RecipeExecutor {
        client,
        runtime_root: Path::new("/run/vonk-forge-agent"),
        observation_receipt_public_key: receipt_key,
        runtime: OciRuntime {
            runner: &runner,
            data_root: &config.data_dir,
            huggingface_curl_config: config.huggingface_curl_config.as_deref(),
        },
    };
    let exact_result = executor.report_exact_recipe_run_observations().await;
    let disposition = exact_observation_disposition(&exact_result);
    let exact_complete = exact_result.is_ok();
    match exact_result {
        Ok(_) => failures = 0,
        Err(_) if disposition.transition_not_ready => {
            // Retained rank launch can precede the Controller's running state.
            // Its next readiness claim remains independent of this transition.
        }
        Err(error) => {
            // Existing collection reports an explicit empty v2 snapshot on
            // integrity/inspection failure. Keep claims available for recovery.
            failures = failures.saturating_add(1);
            eprintln!("vonk-agent: exact recipe observation failed: {error}");
        }
    }
    let observations = executor.runtime.recipe_run_observations()?;
    let managed_runs = observations.len() + disposition.managed_run_count;
    let mut delay = observation_delay(config.poll_max_seconds, managed_runs, exact_complete);
    match client.report_recipe_run_observations(&observations).await {
        Ok(()) => failures = 0,
        Err(error) => match observation_failure_action(&error) {
            ObservationFailureAction::BackoffThenClaim => {
                failures = failures.saturating_add(1);
                let entropy = SystemTime::now().duration_since(UNIX_EPOCH)?.subsec_nanos() as u64;
                delay = backoff_delay(
                    failures,
                    entropy,
                    config.poll_min_seconds,
                    config.poll_max_seconds,
                );
            }
            ObservationFailureAction::Stop => return Err(error.into()),
        },
    }
    Ok(ObservationCycle {
        managed_runs,
        failures,
        delay,
    })
}

fn observation_delay(
    configured_maximum: u64,
    managed_runs: usize,
    exact_complete: bool,
) -> Duration {
    // A partial exact cycle or expected transition is not proof of an idle
    // node, even when the disposition cannot return the original plan count.
    Duration::from_secs(claim_wait_seconds(
        configured_maximum,
        managed_runs.max(usize::from(!exact_complete)),
        true,
    ))
}

async fn run_telemetry_lane(
    data_dir: PathBuf,
    clients: tokio::sync::watch::Receiver<AgentHttpClient>,
    poll_min_seconds: u64,
    poll_max_seconds: u64,
) {
    let boot_id_path = PathBuf::from("/proc/sys/kernel/random/boot_id");
    let boot_id = loop {
        match read_boot_id(&boot_id_path) {
            Ok(boot_id) => break boot_id,
            Err(error) => {
                eprintln!("telemetry boot identity unavailable: {error}");
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
        }
    };
    let collector = TelemetryCollector::new(
        SystemProcessRunner,
        SystemFileSystemProvider,
        TelemetryPaths {
            stat: PathBuf::from("/proc/stat"),
            loadavg: PathBuf::from("/proc/loadavg"),
            uptime: PathBuf::from("/proc/uptime"),
            meminfo: PathBuf::from("/proc/meminfo"),
            net_dev: PathBuf::from("/proc/net/dev"),
            store: data_dir,
            sys_block: PathBuf::from("/sys/block"),
            sys_class_net: PathBuf::from("/sys/class/net"),
            thermal: PathBuf::from("/sys/class/thermal"),
            powercap: PathBuf::from("/sys/class/powercap"),
        },
        boot_id,
    );
    let mut collector = match collector {
        Ok(collector) => collector,
        Err(error) => {
            eprintln!("telemetry durable state unavailable: {error}");
            return;
        }
    };
    let mut previous = None;
    let mut queue = TelemetryQueue::new();
    let mut schedule = TelemetrySchedule::new(tokio::time::Instant::now());
    let mut send_failures = 0_u32;

    loop {
        tokio::time::sleep_until(schedule.next_collection()).await;
        let collection_started = tokio::time::Instant::now();
        let prior = previous.take();
        let collection = tokio::task::spawn_blocking(move || {
            let result = collector.sample(prior.as_ref());
            (collector, prior, result)
        })
        .await;
        let Ok((returned_collector, prior, result)) = collection else {
            eprintln!("telemetry collector task stopped unexpectedly");
            return;
        };
        collector = returned_collector;
        match result {
            Ok(sample) => {
                previous = Some(sample.clone());
                queue.push(sample);
            }
            Err(error) => {
                previous = prior;
                eprintln!("telemetry sample unavailable: {error}");
            }
        }
        let now = tokio::time::Instant::now();
        schedule.collected(collection_started, now);

        if !schedule.send_due(now, !queue.is_empty()) {
            continue;
        }
        let batch = queue.batch();
        let client = clients.borrow().clone();
        match client.report_telemetry(&batch).await {
            Ok(()) => {
                queue
                    .acknowledge_prefix(batch.len())
                    .expect("reported telemetry prefix exists");
                send_failures = 0;
                schedule.send_succeeded(tokio::time::Instant::now());
            }
            Err(error) => {
                send_failures = send_failures.saturating_add(1);
                let entropy = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_or(0, |duration| duration.subsec_nanos() as u64);
                let retry_after = telemetry_retry_after(
                    &error,
                    send_failures,
                    entropy,
                    poll_min_seconds,
                    poll_max_seconds,
                );
                schedule.send_failed(tokio::time::Instant::now(), retry_after);
                eprintln!("telemetry report deferred: {error}");
            }
        }
    }
}

fn telemetry_retry_after(
    error: &ClientError,
    failures: u32,
    entropy: u64,
    poll_min_seconds: u64,
    poll_max_seconds: u64,
) -> std::time::Duration {
    if error.retryable() {
        backoff_delay(failures, entropy, poll_min_seconds, poll_max_seconds)
    } else {
        std::time::Duration::from_secs(60)
    }
}

#[derive(Debug, PartialEq, Eq)]
enum LaneExit<C, O, S> {
    Control(C),
    Observation(Result<O, String>),
    Shutdown(S),
}

// A dropped supervisor must not detach maintenance tasks. Explicit completion
// also joins tasks after abort; an already-running synchronous probe must first
// return under its existing subprocess deadline. This does not make a blocked
// control operation itself cancellable.
struct OwnedLane<T>(tokio::task::JoinHandle<T>);

impl<T> Drop for OwnedLane<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn supervise_lanes<C, O, T, S>(
    control: C,
    observations: O,
    telemetry: T,
    shutdown: S,
) -> LaneExit<C::Output, O::Output, S::Output>
where
    C: Future,
    O: Future + Send + 'static,
    O::Output: Send + 'static,
    T: Future<Output = ()> + Send + 'static,
    S: Future,
{
    tokio::pin!(control);
    tokio::pin!(shutdown);
    // Separate tasks are essential: install/build subprocesses can block while
    // the control future is being polled. Another select! branch cannot help.
    let mut observations = OwnedLane(tokio::spawn(observations));
    let mut telemetry = OwnedLane(tokio::spawn(telemetry));
    let mut telemetry_running = true;
    let mut observations_running = true;
    let outcome = loop {
        tokio::select! {
            result = &mut control => break LaneExit::Control(result),
            result = &mut observations.0 => {
                observations_running = false;
                break LaneExit::Observation(result.map_err(|error| error.to_string()));
            }
            signal = &mut shutdown => break LaneExit::Shutdown(signal),
            _ = &mut telemetry.0, if telemetry_running => telemetry_running = false,
        }
    };
    observations.0.abort();
    telemetry.0.abort();
    if observations_running {
        let _ = (&mut observations.0).await;
    }
    if telemetry_running {
        let _ = (&mut telemetry.0).await;
    }
    outcome
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ObservationFailureAction {
    BackoffThenClaim,
    Stop,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ExactObservationDisposition {
    managed_run_count: usize,
    transition_not_ready: bool,
}

fn exact_observation_disposition(
    result: &Result<usize, RecipeObservationError>,
) -> ExactObservationDisposition {
    ExactObservationDisposition {
        managed_run_count: result.as_ref().copied().unwrap_or(0),
        transition_not_ready: result.as_ref().is_err_and(|error| error.not_ready()),
    }
}

fn observation_failure_action(error: &ClientError) -> ObservationFailureAction {
    if error.retryable() {
        ObservationFailureAction::BackoffThenClaim
    } else {
        ObservationFailureAction::Stop
    }
}

fn claim_wait_seconds(
    configured_maximum: u64,
    managed_run_count: usize,
    readiness_published: bool,
) -> u64 {
    if !readiness_published {
        return 0;
    }
    let existing_wait = configured_maximum.min(60);
    if managed_run_count == 0 {
        existing_wait
    } else {
        existing_wait.min(10)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        LaneExit, ObservationCycle, ObservationFailureAction, claim_wait_seconds,
        exact_observation_disposition, observation_delay, observation_failure_action,
        run_observation_cycles, supervise_lanes, telemetry_retry_after,
    };
    use std::future;
    use vonk_agent::client::ClientError;
    use vonk_agent::{executor::RecipeObservationError, host_runtime::HostRuntimeError};

    #[test]
    fn exact_observation_failures_never_stop_the_next_claim() {
        let transition = Err(RecipeObservationError::Inspection(
            HostRuntimeError::Controller(ClientError::ObservationNotReady),
        ));
        let transition = exact_observation_disposition(&transition);
        assert_eq!(transition.managed_run_count, 0);
        assert!(transition.transition_not_ready);

        let denied = Err(RecipeObservationError::Inspection(
            HostRuntimeError::Controller(ClientError::Protocol),
        ));
        let denied = exact_observation_disposition(&denied);
        assert_eq!(denied.managed_run_count, 0);
        assert!(!denied.transition_not_ready);

        for cycle in [Ok(2), Ok(2)] {
            let complete = exact_observation_disposition(&cycle);
            assert_eq!(complete.managed_run_count, 2);
            assert!(!complete.transition_not_ready);
        }
    }

    #[test]
    fn managed_runs_cap_claim_long_poll_at_ten_seconds() {
        assert_eq!(claim_wait_seconds(60, 1, true), 10);
        assert_eq!(claim_wait_seconds(7, 1, true), 7);
    }

    #[test]
    fn no_managed_runs_retain_existing_claim_long_poll_behavior() {
        assert_eq!(claim_wait_seconds(300, 0, true), 60);
        assert_eq!(claim_wait_seconds(7, 0, true), 7);
    }

    #[test]
    fn first_claim_returns_immediately_to_publish_controller_readiness() {
        assert_eq!(claim_wait_seconds(60, 0, false), 0);
        assert_eq!(claim_wait_seconds(60, 1, false), 0);
    }

    #[test]
    fn retryable_observation_failure_backs_off_then_allows_claim() {
        assert_eq!(
            observation_failure_action(&ClientError::Retryable),
            ObservationFailureAction::BackoffThenClaim
        );
    }

    #[test]
    fn non_retryable_observation_failure_stops_the_loop() {
        assert_eq!(
            observation_failure_action(&ClientError::Protocol),
            ObservationFailureAction::Stop
        );
    }

    #[tokio::test]
    async fn retryable_telemetry_failure_schedules_retry_without_delaying_claim_lane() {
        let retry_after = telemetry_retry_after(&ClientError::Retryable, 1, 0, 5, 60);
        assert!(retry_after >= std::time::Duration::from_secs(5));
        let telemetry_lane = async move {
            tokio::time::sleep(retry_after).await;
        };
        let claim_lane = future::ready("claim attempted");

        let outcome = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            supervise_lanes(
                claim_lane,
                future::pending::<()>(),
                telemetry_lane,
                future::pending::<()>(),
            ),
        )
        .await
        .expect("claim lane was gated by telemetry retry state");

        assert_eq!(outcome, LaneExit::Control("claim attempted"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn observations_and_telemetry_progress_during_synchronous_install() {
        use std::sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
        };
        use std::time::{Duration, Instant};
        let observations = Arc::new(Mutex::new(Vec::new()));
        let telemetry = Arc::new(AtomicUsize::new(0));
        let (_, clients) = tokio::sync::watch::channel(());
        let (managed, _) = tokio::sync::watch::channel(0);
        let reports = observations.clone();
        let observation_lane = run_observation_cycles(
            clients,
            managed,
            Arc::new(tokio::sync::Mutex::new(())),
            move |(), _| {
                let reports = reports.clone();
                async move {
                    reports.lock().unwrap().push(Instant::now());
                    Ok::<_, ()>(ObservationCycle {
                        managed_runs: 1,
                        failures: 0,
                        delay: Duration::from_millis(5),
                    })
                }
            },
        );
        let samples = telemetry.clone();
        let telemetry_lane = async move {
            loop {
                samples.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        };
        let control = async {
            // Deliberately no async yield. This matches synchronous curl/hash
            // work under executor.execute; sleep().await would miss the bug.
            let deadline = Instant::now() + Duration::from_secs(2);
            while Instant::now() < deadline {
                if observations.lock().unwrap().len() >= 3 && telemetry.load(Ordering::SeqCst) >= 3
                {
                    return true;
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            false
        };
        let result = supervise_lanes(
            control,
            observation_lane,
            telemetry_lane,
            future::pending::<()>(),
        )
        .await;
        assert_eq!(result, LaneExit::Control(true));
        let times = observations.lock().unwrap();
        assert!(times.windows(2).all(|pair| pair[1] > pair[0]));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn observation_cycles_are_serial_and_use_the_next_rotated_client() {
        use std::sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
        };
        use std::time::Duration;
        let (clients, client_view) = tokio::sync::watch::channel(1);
        let (managed, mut managed_view) = tokio::sync::watch::channel(0);
        let active = Arc::new(AtomicUsize::new(0));
        let seen = Arc::new(Mutex::new(Vec::new()));
        let started = Arc::new(tokio::sync::Notify::new());
        let collect_started = started.clone();
        let collect_seen = seen.clone();
        let collect_active = active.clone();
        let observation_lane = run_observation_cycles(
            client_view,
            managed,
            Arc::new(tokio::sync::Mutex::new(())),
            move |client, failures| {
                let active = collect_active.clone();
                let seen = collect_seen.clone();
                let started = collect_started.clone();
                async move {
                    assert_eq!(active.fetch_add(1, Ordering::SeqCst), 0);
                    seen.lock().unwrap().push(client);
                    started.notify_one();
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    active.fetch_sub(1, Ordering::SeqCst);
                    Ok::<_, ()>(ObservationCycle {
                        managed_runs: client,
                        failures: failures + 1,
                        delay: Duration::from_millis(1),
                    })
                }
            },
        );
        let control = async move {
            started.notified().await;
            clients.send_replace(2);
            while *managed_view.borrow() != 2 {
                managed_view.changed().await.unwrap();
            }
        };
        let result = tokio::time::timeout(
            Duration::from_secs(2),
            supervise_lanes(
                control,
                observation_lane,
                future::pending::<()>(),
                future::pending::<()>(),
            ),
        )
        .await
        .unwrap();
        assert_eq!(result, LaneExit::Control(()));
        assert_eq!(*seen.lock().unwrap(), [1, 2]);
        assert_eq!(active.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn fatal_observation_error_ends_supervision_without_retry_or_claim_success() {
        let (_, clients) = tokio::sync::watch::channel(());
        let (managed, managed_view) = tokio::sync::watch::channel(0);
        let observation_lane = run_observation_cycles(
            clients,
            managed,
            std::sync::Arc::new(tokio::sync::Mutex::new(())),
            |(), _| async { Err::<ObservationCycle, _>(ClientError::Authentication) },
        );
        let result = supervise_lanes(
            future::pending::<()>(),
            observation_lane,
            future::pending::<()>(),
            future::pending::<()>(),
        )
        .await;
        assert!(matches!(
            result,
            LaneExit::Observation(Ok(Err(ClientError::Authentication)))
        ));
        assert_eq!(*managed_view.borrow(), 0);
    }

    #[tokio::test]
    async fn control_return_and_shutdown_join_only_their_owned_maintenance_tasks() {
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };
        struct Dropped(Arc<AtomicUsize>);
        impl Drop for Dropped {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
        for shutdown in [false, true] {
            let dropped = Arc::new(AtomicUsize::new(0));
            let started = Arc::new(AtomicUsize::new(0));
            let lane = |dropped: Arc<AtomicUsize>, started: Arc<AtomicUsize>| async move {
                let _guard = Dropped(dropped);
                started.fetch_add(1, Ordering::SeqCst);
                future::pending::<()>().await;
            };
            let ready = async {
                while started.load(Ordering::SeqCst) != 2 {
                    tokio::task::yield_now().await;
                }
            };
            let result = if shutdown {
                supervise_lanes(
                    future::pending::<()>(),
                    lane(dropped.clone(), started.clone()),
                    lane(dropped.clone(), started.clone()),
                    ready,
                )
                .await
            } else {
                supervise_lanes(
                    ready,
                    lane(dropped.clone(), started.clone()),
                    lane(dropped.clone(), started.clone()),
                    future::pending::<()>(),
                )
                .await
            };
            assert!(matches!(
                result,
                LaneExit::Shutdown(()) | LaneExit::Control(())
            ));
            assert_eq!(dropped.load(Ordering::SeqCst), 2);
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn activation_cannot_revoke_credentials_during_an_observation_report() {
        use std::sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
        };
        use std::time::Duration;
        let rotation = Arc::new(tokio::sync::Mutex::new(()));
        let active_certificate = Arc::new(AtomicUsize::new(1));
        let authorize = |active: &AtomicUsize, presented| {
            if active.load(Ordering::SeqCst) == presented {
                Ok(())
            } else {
                Err(ClientError::Authentication)
            }
        };
        let (clients, client_view) = tokio::sync::watch::channel(1);
        let (managed, mut managed_view) = tokio::sync::watch::channel(0);
        let begun = Arc::new(tokio::sync::Notify::new());
        let reports = Arc::new(Mutex::new(Vec::new()));
        let collect_active = active_certificate.clone();
        let collect_begun = begun.clone();
        let collect_reports = reports.clone();
        let observations =
            run_observation_cycles(client_view, managed, rotation.clone(), move |client, _| {
                let active = collect_active.clone();
                let begun = collect_begun.clone();
                let reports = collect_reports.clone();
                async move {
                    authorize(&active, client)?; // inspection grant
                    begun.notify_one();
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    authorize(&active, client)?; // exact and legacy reports
                    reports.lock().unwrap().push(client);
                    Ok::<_, ClientError>(ObservationCycle {
                        managed_runs: client,
                        failures: 0,
                        delay: Duration::from_millis(1),
                    })
                }
            });
        let control = async {
            begun.notified().await;
            {
                let _activation = rotation.lock().await;
                // Match the Controller: activation immediately revokes the old
                // credential, before publishing the replacement local client.
                active_certificate.store(2, Ordering::SeqCst);
                assert!(matches!(
                    authorize(&active_certificate, 1),
                    Err(ClientError::Authentication)
                ));
                clients.send_replace(2);
            }
            while *managed_view.borrow() != 2 {
                managed_view.changed().await.unwrap();
            }
        };
        let result = tokio::time::timeout(
            Duration::from_secs(2),
            supervise_lanes(
                control,
                observations,
                future::pending::<()>(),
                future::pending::<()>(),
            ),
        )
        .await
        .unwrap();
        assert!(matches!(result, LaneExit::Control(())));
        assert_eq!(*reports.lock().unwrap(), [1, 2]);
    }

    #[test]
    fn mixed_exact_transition_keeps_active_cadence_instead_of_idle_wait() {
        assert_eq!(
            observation_delay(60, 0, false),
            std::time::Duration::from_secs(10)
        );
        assert_eq!(
            observation_delay(60, 2, true),
            std::time::Duration::from_secs(10)
        );
        assert_eq!(
            observation_delay(60, 0, true),
            std::time::Duration::from_secs(60)
        );
    }
}
