//! # Velstra control plane
//!
//! The user-space daemon and CLI. It compiles the eBPF data plane in (via the
//! build script), loads it, programs the firewall maps, attaches the XDP hook,
//! and reports live statistics. Config comes from either a local TOML file or a
//! central [controller](velstra_controller) over gRPC, which can push live
//! updates that are re-applied to the maps without detaching.
//!
//! ```text
//! velstra run      --iface eth0 --config rules.toml             # local config
//! velstra run      --iface eth0 --controller http://ctl:50051   # central config
//! velstra validate rules.toml                                   # parse + print
//! ```

mod controller_client;
mod firewall;

use std::{path::PathBuf, sync::Arc, time::Duration};

use anyhow::{Result, anyhow};
use clap::{Args, Parser, Subcommand};
use log::{error, info, warn};
use tokio::{signal, sync::Mutex};
use velstra_config::RuntimeConfig;

use crate::{
    controller_client::Reporter,
    firewall::{AttachMode, Firewall},
};

/// Velstra — a next-gen, eBPF/XDP software-defined networking stack.
#[derive(Debug, Parser)]
#[command(name = "velstra", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
// The CLI command enum is parsed once at startup; the size difference between a
// large `Run` and a tiny `Validate` is irrelevant here.
#[allow(clippy::large_enum_variant)]
enum Command {
    /// Load the firewall, attach it to an interface and serve (requires root).
    Run(RunArgs),
    /// Parse a config file and print the resolved ruleset. No privileges needed.
    Validate(ValidateArgs),
}

#[derive(Debug, Args)]
struct RunArgs {
    /// Network interface to attach to. Repeat `--iface` to attach to several
    /// (e.g. the client-facing and backend-facing NICs) so bidirectional NAT
    /// state is shared across them. Required unless `--auto-attach` is set.
    #[arg(short, long, num_args = 1..)]
    iface: Vec<String>,

    /// Auto-attach to interfaces whose name starts with this prefix as they
    /// appear (e.g. `--auto-attach tap` or `tap*`) — for VMs/pods joining the
    /// fabric without listing every interface. Their policy comes from the
    /// config's `[[interface]]` assignments, else `--auto-policy`.
    #[arg(long)]
    auto_attach: Option<String>,

    /// Policy id assigned to auto-attached interfaces not named in the config.
    #[arg(long, default_value_t = 0)]
    auto_policy: u32,

    /// Path to a local TOML config. Mutually exclusive with `--controller`.
    #[arg(short, long, conflicts_with = "controller")]
    config: Option<PathBuf>,

    /// Controller endpoint, e.g. `https://10.0.0.1:50051`. The node fetches its
    /// config from here and applies live updates the controller pushes.
    #[arg(long)]
    controller: Option<String>,

    /// Node identity sent to the controller. Defaults to the system hostname.
    #[arg(long)]
    node_id: Option<String>,

    /// PEM CA certificate to verify the controller (enables TLS).
    #[arg(long, requires = "controller")]
    tls_ca: Option<PathBuf>,
    /// Client certificate for mutual TLS to the controller.
    #[arg(long, requires = "tls_key")]
    tls_cert: Option<PathBuf>,
    /// Client private key for mutual TLS to the controller.
    #[arg(long, requires = "tls_cert")]
    tls_key: Option<PathBuf>,
    /// Server name to validate against the controller's certificate.
    #[arg(long)]
    tls_domain: Option<String>,

    /// XDP attach mode.
    #[arg(long, value_enum, default_value_t = AttachMode::Auto)]
    xdp_mode: AttachMode,

    /// Also attach the **egress** firewall (a TC clsact hook) to each `--iface`.
    /// Filters host-originated / tap-bound traffic by destination and records
    /// stateful flows for the return path. Off by default (it can drop traffic
    /// the ingress hook never sees).
    #[arg(long, default_value_t = false)]
    egress: bool,

    /// Seconds between live statistics dumps. `0` disables periodic dumps.
    #[arg(long, default_value_t = 5)]
    stats_interval: u64,
}

#[derive(Debug, Args)]
struct ValidateArgs {
    /// Path to the TOML config to validate.
    config: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    // `RUST_LOG=info` (or finer) controls verbosity; default to `info`.
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let cli = Cli::parse();
    match cli.command {
        Command::Validate(args) => validate(args),
        Command::Run(args) => run(args).await,
    }
}

/// `velstra validate` — load and pretty-print a config without touching the
/// kernel. Handy in CI and for editing rules safely.
fn validate(args: ValidateArgs) -> Result<()> {
    let cfg = velstra_config::load_file(&args.config)?;
    println!("Configuration {} is valid:\n", args.config.display());
    print!("{cfg}");
    Ok(())
}

/// The system hostname, used as the default node id for the controller.
fn default_node_id() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|s| s.trim().to_string())
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "velstra-node".to_string())
}

/// `velstra run` — the daemon.
async fn run(args: RunArgs) -> Result<()> {
    if args.iface.is_empty() && args.auto_attach.is_none() {
        anyhow::bail!("specify at least one --iface, or --auto-attach <prefix>");
    }

    // TLS for the controller connection, if a CA was supplied.
    let tls = args
        .tls_ca
        .as_ref()
        .map(|ca| controller_client::TlsOptions {
            ca: ca.clone(),
            client_cert: args.tls_cert.clone(),
            client_key: args.tls_key.clone(),
            domain: args.tls_domain.clone(),
        });

    // Resolve the initial config and, in controller mode, the live update stream.
    let mut watch_stream = None;
    let initial = if let Some(endpoint) = &args.controller {
        let node_id = args.node_id.clone().unwrap_or_else(default_node_id);
        info!("connecting to controller {endpoint} as node {node_id:?}");
        let mut stream = controller_client::watch(endpoint.clone(), node_id, tls.clone()).await?;
        let first = stream
            .message()
            .await?
            .ok_or_else(|| anyhow!("controller closed the stream before sending a config"))?;
        let cfg = velstra_config::runtime_from_proto(&first)?;
        watch_stream = Some((stream, first.version));
        cfg
    } else if let Some(path) = &args.config {
        velstra_config::load_file(path)?
    } else {
        warn!("no --config or --controller supplied; using a fail-open (pass-all) policy");
        RuntimeConfig::passthrough()
    };

    log_policy("policy", &initial);

    let firewall = Arc::new(Mutex::new(Firewall::load_and_attach(
        &args.iface,
        args.xdp_mode,
        &initial,
        args.egress,
    )?));
    for (iface, mode) in &firewall.lock().await.attached {
        info!("attached to {iface} in {mode:?} mode");
    }
    println!("Velstra is live. Press Ctrl-C to detach.");

    // Auto-attach: pick up matching interfaces (VM taps, pod veths) as they appear.
    if let Some(pattern) = args.auto_attach.clone() {
        info!("auto-attach watching for interfaces matching {pattern:?}");
        tokio::spawn(auto_attach_loop(
            firewall.clone(),
            pattern,
            args.xdp_mode,
            args.auto_policy,
        ));
    }

    // In controller mode, apply pushed updates to the maps in the background.
    if let Some((stream, version)) = watch_stream {
        tokio::spawn(watch_updates(firewall.clone(), stream, version));
    }

    // In controller mode, also report statistics back periodically.
    let reporter = match (&args.controller, args.stats_interval) {
        (Some(endpoint), interval) if interval > 0 => {
            let node_id = args.node_id.clone().unwrap_or_else(default_node_id);
            Reporter::connect(endpoint.clone(), node_id, tls.clone())
                .await
                .ok()
        }
        _ => None,
    };

    serve(&firewall, args.stats_interval, reporter).await?;

    println!("\nFinal statistics:");
    print!("{}", firewall.lock().await.read_stats()?.render());
    println!("Detaching XDP program and exiting.");
    Ok(())
}

/// Log a one-line summary of a config's scale.
fn log_policy(label: &str, cfg: &RuntimeConfig) {
    let rules: usize = cfg.policies.iter().map(|p| p.port_rules.len()).sum();
    let blocks: usize = cfg.policies.iter().map(|p| p.blocklist.len()).sum();
    info!(
        "{label}: {} polic(y/ies), {} interface(s), {blocks} blocklist + {rules} port rule(s), {} route(s), {} service(s)",
        cfg.policies.len(),
        cfg.interfaces.len(),
        cfg.routes.len(),
        cfg.services.len()
    );
}

/// Background task: re-apply each config the controller pushes.
async fn watch_updates(
    firewall: Arc<Mutex<Firewall>>,
    mut stream: tonic::Streaming<velstra_proto::NodeConfig>,
    mut last_version: u64,
) {
    loop {
        match stream.message().await {
            Ok(Some(node_config)) => {
                if node_config.version == last_version {
                    continue; // same config re-sent; nothing to do
                }
                last_version = node_config.version;
                match velstra_config::runtime_from_proto(&node_config) {
                    Ok(cfg) => {
                        let mut fw = firewall.lock().await;
                        match fw.reconfigure(&cfg) {
                            Ok(()) => {
                                drop(fw);
                                log_policy(
                                    &format!("applied controller update v{last_version}"),
                                    &cfg,
                                );
                            }
                            Err(e) => error!("failed to apply controller update: {e:#}"),
                        }
                    }
                    Err(e) => warn!("controller sent an invalid config: {e:#}"),
                }
            }
            Ok(None) => {
                warn!("controller closed the config stream; keeping the last config");
                break;
            }
            Err(e) => {
                warn!("controller config stream error: {e}; keeping the last config");
                break;
            }
        }
    }
}

/// List current network interface names from `/sys/class/net`.
fn list_interfaces() -> Vec<String> {
    std::fs::read_dir("/sys/class/net")
        .map(|entries| {
            entries
                .filter_map(|e| e.ok()?.file_name().into_string().ok())
                .collect()
        })
        .unwrap_or_default()
}

/// Background task: every few seconds, reconcile auto-attach against the live
/// interface list so interfaces matching `pattern` are picked up as they appear
/// and dropped as they go.
async fn auto_attach_loop(
    firewall: Arc<Mutex<Firewall>>,
    pattern: String,
    mode: AttachMode,
    default_policy: u32,
) {
    let prefix = pattern.trim_end_matches('*').to_string();
    let mut ticker = tokio::time::interval(Duration::from_secs(2));
    loop {
        ticker.tick().await;
        let present = list_interfaces();
        firewall
            .lock()
            .await
            .reconcile_auto_attach(&present, &prefix, mode, default_policy);
    }
}

/// Resolve on the first shutdown signal — **SIGINT** (Ctrl-C) *or* **SIGTERM**
/// (what `systemd`, Kubernetes, and `kill` send by default). Handling both means
/// the agent detaches cleanly under a process manager, not just at an interactive
/// terminal.
async fn shutdown_signal() -> Result<()> {
    use tokio::signal::unix::{SignalKind, signal as unix_signal};
    let mut term = unix_signal(SignalKind::terminate())?;
    tokio::select! {
        result = signal::ctrl_c() => result?,
        _ = term.recv() => {}
    }
    Ok(())
}

/// Block until a shutdown signal, optionally dumping (and reporting) statistics
/// every `interval` seconds.
async fn serve(
    firewall: &Arc<Mutex<Firewall>>,
    interval: u64,
    mut reporter: Option<Reporter>,
) -> Result<()> {
    if interval == 0 {
        shutdown_signal().await?;
        return Ok(());
    }

    let mut ticker = tokio::time::interval(Duration::from_secs(interval));
    // The first tick fires immediately; skip it so we don't print all-zeros.
    ticker.tick().await;
    loop {
        tokio::select! {
            result = shutdown_signal() => {
                result?;
                return Ok(());
            }
            _ = ticker.tick() => {
                let stats = firewall.lock().await.read_stats()?;
                println!("\nLive statistics:");
                print!("{}", stats.render());
                if let Some(reporter) = reporter.as_mut()
                    && let Err(e) = reporter.report(&stats).await {
                    warn!("could not report stats to controller: {e}");
                }
            }
        }
    }
}
