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
mod wren;

use std::{path::PathBuf, sync::Arc, time::Duration};

use anyhow::{Context, Result, anyhow};
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
    #[arg(short, long, conflicts_with = "controllers")]
    config: Option<PathBuf>,

    /// Controller endpoint(s), e.g. `https://10.0.0.1:50051`. Repeatable for an
    /// HA controller cluster: the node fetches its config from the first
    /// reachable controller and, if that one goes down, fails over to the next.
    /// Config reads are served by any cluster member (leader or follower).
    #[arg(long = "controller")]
    controllers: Vec<String>,

    /// Node identity sent to the controller. Defaults to the system hostname.
    #[arg(long)]
    node_id: Option<String>,

    /// PEM CA certificate to verify the controller (enables TLS).
    #[arg(long, requires = "controllers")]
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

    /// Orchestrator endpoint(s), e.g. `https://10.0.0.1:50052`. Repeatable.
    /// When set, this node self-registers as a VTEP host with the controller
    /// (`AddHost`) so the orchestrator can place ports on it — the agent's side
    /// of the Kubernetes CNI integration. Uses the same TLS as `--controller`.
    #[arg(long = "orchestrator")]
    orchestrators: Vec<String>,
    /// This node's underlay VTEP IPv4, advertised in self-registration. Required
    /// with `--orchestrator`.
    #[arg(long, requires = "orchestrators")]
    vtep_ip: Option<String>,
    /// Underlay interface whose MAC is advertised in self-registration. Defaults
    /// to the first `--iface`.
    #[arg(long)]
    underlay_iface: Option<String>,
    /// Encapsulation advertised in self-registration.
    #[arg(long, value_enum, default_value_t = EncapArg::Vxlan)]
    encap: EncapArg,

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

    /// Path to the co-located Wren routing daemon's control socket. When set, the
    /// agent reads locally-learned tenant MAC/IPs out of the data plane every few
    /// seconds and advertises each to Wren (`evpn advertise <vni> <mac> <ip>`),
    /// which re-advertises them as type-2 EVPN routes to remote VTEPs (roadmap
    /// B4b). Unset ⇒ the whole learn-and-advertise task is inert.
    #[arg(long)]
    wren_socket: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct ValidateArgs {
    /// Path to the TOML config to validate.
    config: PathBuf,
}

/// Encapsulation advertised when the agent self-registers its host.
#[derive(Copy, Clone, Debug, Default, clap::ValueEnum)]
enum EncapArg {
    #[default]
    Vxlan,
    Geneve,
}

impl EncapArg {
    /// The matching `velstra.v1.Encap` proto value.
    fn as_proto(self) -> i32 {
        match self {
            EncapArg::Vxlan => velstra_proto::Encap::Vxlan as i32,
            EncapArg::Geneve => velstra_proto::Encap::Geneve as i32,
        }
    }
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
    if args.iface.is_empty() && args.auto_attach.is_none() && args.controllers.is_empty() {
        anyhow::bail!(
            "specify at least one --iface, --auto-attach <prefix>, or --controller (config-driven attach)"
        );
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

    // Resolve the initial config. In controller mode, fetch it from the first
    // reachable controller; the background watch loop (re)connects on its own.
    let mut initial_version = 0;
    let initial = if !args.controllers.is_empty() {
        let node_id = args.node_id.clone().unwrap_or_else(default_node_id);
        info!(
            "connecting to controller(s) {:?} as node {node_id:?}",
            args.controllers
        );
        let (mut stream, endpoint) =
            controller_client::watch_any(&args.controllers, &node_id, &tls).await?;
        info!("got initial config from {endpoint}");
        let first = stream
            .message()
            .await?
            .ok_or_else(|| anyhow!("controller closed the stream before sending a config"))?;
        initial_version = first.version;
        velstra_config::runtime_from_proto(&first)?
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

    // Attach to config-named interfaces (every `[[interface]]` in the policy, not
    // just the `--iface` attach points) as they appear — without needing an
    // --auto-attach prefix. Needed in BOTH modes: a controller may name a veth
    // before the CNI creates it, and a file-config appliance (e.g. a
    // firewall/router) names every zoned NIC + VLAN it must filter and NAT on,
    // which `--iface` alone (one primary) would otherwise miss.
    if !args.controllers.is_empty() || args.config.is_some() {
        tokio::spawn(config_attach_loop(firewall.clone(), args.xdp_mode));
    }

    // Self-register this node as a VTEP host so the orchestrator can place ports
    // on it (the agent side of the Kubernetes CNI flow).
    if !args.orchestrators.is_empty() {
        let spec = build_host_spec(&args)?;
        info!("self-registering host {:?} (vtep {})", spec.id, spec.vtep);
        tokio::spawn(register_host_loop(
            args.orchestrators.clone(),
            tls.clone(),
            spec,
        ));
    }

    // In controller mode, apply pushed updates in the background — reconnecting
    // (and failing over to another controller) whenever the stream breaks.
    if !args.controllers.is_empty() {
        let node_id = args.node_id.clone().unwrap_or_else(default_node_id);
        tokio::spawn(watch_updates(
            firewall.clone(),
            args.controllers.clone(),
            node_id,
            tls.clone(),
            initial_version,
        ));
    }

    // B4b: local MAC learning → EVPN advertise. When a local Wren control socket
    // is given, take the `LOCAL_MACS` map handle and run a task that advertises
    // each locally-learned tenant MAC/IP to Wren. Opt-in and best-effort.
    if let Some(socket) = args.wren_socket.clone() {
        match firewall.lock().await.take_local_macs() {
            Ok(map) => {
                info!(
                    "local-MAC learning: advertising to wren socket {}",
                    socket.display()
                );
                tokio::spawn(wren::learn_and_advertise(
                    map,
                    socket,
                    Duration::from_secs(2),
                ));
            }
            Err(e) => warn!("could not start local-MAC learning: {e:#}"),
        }
    }

    // In controller mode, also report statistics back periodically.
    let reporter = if !args.controllers.is_empty() && args.stats_interval > 0 {
        let node_id = args.node_id.clone().unwrap_or_else(default_node_id);
        Reporter::connect_any(&args.controllers, node_id, &tls)
            .await
            .ok()
    } else {
        None
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

/// Background task: re-apply each config the controller pushes, reconnecting to
/// any reachable controller whenever the stream breaks. The agent keeps running
/// on its last-applied config the whole time a controller is unreachable, so a
/// controller outage never interrupts the data plane.
async fn watch_updates(
    firewall: Arc<Mutex<Firewall>>,
    endpoints: Vec<String>,
    node_id: String,
    tls: Option<controller_client::TlsOptions>,
    mut last_version: u64,
) {
    // Backoff between reconnect attempts, capped — reset to the floor on success.
    const BACKOFF_FLOOR: Duration = Duration::from_millis(500);
    const BACKOFF_CEIL: Duration = Duration::from_secs(10);
    let mut backoff = BACKOFF_FLOOR;

    loop {
        let mut stream = match controller_client::watch_any(&endpoints, &node_id, &tls).await {
            Ok((stream, endpoint)) => {
                info!("watching config from {endpoint}");
                backoff = BACKOFF_FLOOR;
                stream
            }
            Err(e) => {
                warn!(
                    "no controller reachable ({e:#}); retrying in {}s, keeping the last config",
                    backoff.as_secs_f32()
                );
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(BACKOFF_CEIL);
                continue;
            }
        };

        // Version numbers are per-controller, so they are not comparable across
        // a failover. Always apply the first config after a (re)connect — even if
        // its version collides with the last one we saw from another controller —
        // and only use the dedup to skip identical re-sends on the same stream.
        // `reconfigure` is idempotent, so a redundant apply is harmless.
        let mut fresh_connection = true;

        // Drain this stream until it breaks, then loop to reconnect/fail over.
        loop {
            match stream.message().await {
                Ok(Some(node_config)) => {
                    if !fresh_connection && node_config.version == last_version {
                        continue; // same config re-sent on this stream; nothing to do
                    }
                    fresh_connection = false;
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
                    warn!("controller closed the config stream; reconnecting");
                    break;
                }
                Err(e) => {
                    warn!("controller config stream error: {e}; reconnecting");
                    break;
                }
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

/// Background task (controller mode): attach the firewall/LB to interfaces the
/// pushed config names, as they appear, and forget them when their netdev goes.
async fn config_attach_loop(firewall: Arc<Mutex<Firewall>>, mode: AttachMode) {
    let mut ticker = tokio::time::interval(Duration::from_secs(2));
    loop {
        ticker.tick().await;
        let present = list_interfaces();
        firewall
            .lock()
            .await
            .reconcile_config_interfaces(&present, mode);
    }
}

/// Read an interface's MAC address string from `/sys/class/net/<iface>/address`.
fn read_iface_mac(iface: &str) -> Result<String> {
    let path = format!("/sys/class/net/{iface}/address");
    let mac = std::fs::read_to_string(&path).with_context(|| format!("reading {path}"))?;
    let mac = mac.trim().to_string();
    if mac.is_empty() {
        anyhow::bail!("{path} is empty");
    }
    Ok(mac)
}

/// Build the [`HostSpec`] this node advertises when self-registering as a VTEP.
fn build_host_spec(args: &RunArgs) -> Result<velstra_proto::HostSpec> {
    let id = args.node_id.clone().unwrap_or_else(default_node_id);
    let vtep = args
        .vtep_ip
        .clone()
        .ok_or_else(|| anyhow!("--orchestrator requires --vtep-ip"))?;
    let underlay_iface = args
        .underlay_iface
        .clone()
        .or_else(|| args.iface.first().cloned())
        .ok_or_else(|| anyhow!("--orchestrator requires --underlay-iface or an --iface"))?;
    let underlay_mac = read_iface_mac(&underlay_iface)?;
    Ok(velstra_proto::HostSpec {
        id,
        vtep,
        underlay_iface,
        underlay_mac,
        encap: args.encap.as_proto(),
        udp_port: 0,     // encap default
        underlay_mtu: 0, // default (1500)
    })
}

/// Background task: register this node's host with the controller, retrying
/// until it succeeds once (`AddHost` is replace-idempotent).
async fn register_host_loop(
    endpoints: Vec<String>,
    tls: Option<controller_client::TlsOptions>,
    spec: velstra_proto::HostSpec,
) {
    let mut ticker = tokio::time::interval(Duration::from_secs(3));
    loop {
        ticker.tick().await;
        match controller_client::register_host(&endpoints, &tls, &spec).await {
            Ok(()) => {
                info!("registered host {:?} with the controller", spec.id);
                return;
            }
            Err(e) => warn!("host registration failed: {e:#}; retrying"),
        }
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
