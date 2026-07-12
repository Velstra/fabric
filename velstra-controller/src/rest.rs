//! # REST/JSON northbound gateway (roadmap D1)
//!
//! A product-agnostic HTTP surface over the **same** orchestrator/controller the
//! gRPC admin/orchestrator channel drives. Both Velstra products (the Sentinel
//! firewall-OS and the virtualization platform) can therefore program the fabric
//! over plain HTTP/JSON instead of speaking gRPC.
//!
//! Every mutation flows through [`crate::propose`] exactly like the gRPC handlers
//! — propose-through-Raft in cluster mode, apply-to-local-`Topology` in single
//! mode — so there is **one** state machine, not two. This module only marshals
//! JSON in/out and enforces the same per-caller authorization.
//!
//! ## Versioning / compatibility
//!
//! The surface is versioned under `/v1`. Two products depend on it, so the
//! compatibility rule is: within `/v1` we only make **additive** changes (new
//! optional request fields default via `#[serde(default)]`; new response fields
//! are additive; unknown request fields are ignored by serde). A breaking change
//! ships under a new `/v2` prefix rather than mutating `/v1`.
//!
//! ## AuthN/Z (bearer-token stand-in)
//!
//! Wiring full client-certificate mTLS into the HTTP server is out of scope for
//! D1, so authentication uses a **bearer token that stands in for the mTLS
//! Common Name**: a `--rest-token CN=TOKEN` maps a token to the identity `CN`,
//! and the *same* [`Authz`](crate::authz::Authz) policy that guards the gRPC
//! channel is applied — admin CNs may perform any write, a node CN may only
//! mutate its own host, reads are open. With no `--rest-token` configured the
//! gateway is open (single-operator / localhost default), mirroring the gRPC
//! admin channel with no `--client-ca`. Front the gateway with TLS termination
//! (or add mTLS later) for transport confidentiality.

use std::{
    collections::{HashMap, VecDeque},
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use log::{info, warn};
use serde::{Deserialize, Serialize};
use velstra_config::{ActionName, EncapName, ProtoName};
use velstra_orchestrator::{FloatingIp, Host, Network, Port, SecurityGroup, Subnet};
use velstra_proto::{Action, Encap, PortRule, Proto, SecurityGroupSpec as ProtoSgSpec};

use crate::{
    Shared,
    authz::{Authz, Caller},
    propose, raft_host_spec, raft_network_spec, raft_security_group_spec, raft_subnet_spec,
};

// ---------------------------------------------------------------------------
// Audit log
// ---------------------------------------------------------------------------

/// How many recent audit records the in-memory ring retains.
const AUDIT_RING_CAP: usize = 1024;

/// One structured audit record for a mutation that reached the gateway.
#[derive(Debug, Clone, Serialize)]
pub struct AuditEntry {
    /// Monotonic sequence number (per controller process).
    pub seq: u64,
    /// Wall-clock time of the mutation, milliseconds since the Unix epoch.
    pub ts_millis: u64,
    /// Authenticated caller identity (the bearer-token CN, or `anonymous`).
    pub actor: String,
    /// Operation, `resource.verb` (e.g. `network.create`, `port.delete`).
    pub operation: String,
    /// The mutation target (id/name/vni it acted on).
    pub target: String,
    /// Outcome: `ok`, `denied`, or `error: <message>`.
    pub result: String,
}

/// Append-only audit trail: a bounded in-memory ring plus an optional
/// newline-delimited-JSON file. Every mutation (create/delete/bind/allocate/
/// associate) that reaches a handler records one [`AuditEntry`].
pub struct Audit {
    ring: Mutex<VecDeque<AuditEntry>>,
    seq: AtomicU64,
    file: Option<Mutex<std::fs::File>>,
}

impl Audit {
    /// Build an audit log, optionally mirroring records to `path` (append mode).
    pub fn new(path: Option<&PathBuf>) -> Self {
        let file = path.and_then(|p| {
            match std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(p)
            {
                Ok(f) => {
                    info!("REST audit log appending to {}", p.display());
                    Some(Mutex::new(f))
                }
                Err(e) => {
                    warn!("REST audit log {} disabled: {e}", p.display());
                    None
                }
            }
        });
        Self {
            ring: Mutex::new(VecDeque::with_capacity(AUDIT_RING_CAP)),
            seq: AtomicU64::new(0),
            file,
        }
    }

    /// Record one mutation. `result` is `ok`, `denied`, or `error: …`.
    fn record(&self, actor: &str, operation: &str, target: &str, result: &str) {
        let entry = AuditEntry {
            seq: self.seq.fetch_add(1, Ordering::SeqCst),
            ts_millis: now_millis(),
            actor: actor.to_string(),
            operation: operation.to_string(),
            target: target.to_string(),
            result: result.to_string(),
        };
        if let Some(file) = &self.file {
            // Best-effort durable mirror; a failed append must not break the API.
            if let Ok(line) = serde_json::to_string(&entry) {
                use std::io::Write;
                if let Ok(mut f) = file.lock() {
                    let _ = writeln!(f, "{line}");
                }
            }
        }
        if let Ok(mut ring) = self.ring.lock() {
            if ring.len() == AUDIT_RING_CAP {
                ring.pop_front();
            }
            ring.push_back(entry);
        }
    }

    /// The most recent `limit` records (or all retained if `None`), oldest first.
    fn recent(&self, limit: Option<usize>) -> Vec<AuditEntry> {
        let ring = self.ring.lock().expect("audit ring poisoned");
        match limit {
            Some(n) if n < ring.len() => ring.iter().skip(ring.len() - n).cloned().collect(),
            _ => ring.iter().cloned().collect(),
        }
    }
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Shared REST state
// ---------------------------------------------------------------------------

/// State threaded through every handler: the shared fabric, the authz policy,
/// the bearer-token→CN map (the mTLS-CN stand-in), and the audit log.
pub struct RestState {
    pub shared: Arc<Shared>,
    pub authz: Authz,
    /// Bearer token → caller CN. Empty ⇒ open gateway (authz disabled).
    pub tokens: HashMap<String, String>,
    pub audit: Arc<Audit>,
}

impl RestState {
    /// Resolve the caller from the request's `Authorization: Bearer <token>`
    /// header. An unknown or absent token is [`Caller::Anonymous`], which an
    /// enforced [`Authz`] denies for mutations.
    fn caller(&self, headers: &HeaderMap) -> Caller {
        let token = headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(str::trim);
        let Some(provided) = token else {
            return Caller::Anonymous;
        };
        // Compare against each configured token in constant time rather than a
        // hash lookup keyed by the secret, so a wrong token leaks no timing signal
        // about how many bytes were right. The token set is small (per-CN stand-in
        // for mTLS), so the linear scan is negligible.
        for (tok, cn) in &self.tokens {
            if ct_eq(provided.as_bytes(), tok.as_bytes()) {
                return Caller::Cert(cn.clone());
            }
        }
        Caller::Anonymous
    }
}

/// Constant-time byte-slice equality: compares every byte regardless of where the
/// first difference is, so the timing does not reveal the shared prefix length.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

fn actor_of(caller: &Caller) -> String {
    match caller {
        Caller::Cert(cn) => cn.clone(),
        Caller::Anonymous => "anonymous".to_string(),
    }
}

/// Build the versioned router. `/healthz` and `/version` are unversioned probes;
/// all fabric resources live under `/v1`.
pub fn router(state: Arc<RestState>) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/version", get(version))
        .route("/v1/audit", get(list_audit))
        .route("/v1/hosts", get(list_hosts).post(create_host))
        .route("/v1/hosts/:id", get(get_host).delete(delete_host))
        .route("/v1/networks", get(list_networks).post(create_network))
        .route("/v1/networks/:id", get(get_network).delete(delete_network))
        .route("/v1/ports", get(list_ports).post(create_port))
        .route("/v1/ports/:id", get(get_port).delete(delete_port))
        .route("/v1/subnets", get(list_subnets).post(create_subnet))
        .route("/v1/subnets/:id", get(get_subnet).delete(delete_subnet))
        .route(
            "/v1/security-groups",
            get(list_security_groups).post(create_security_group),
        )
        .route(
            "/v1/security-groups/:name",
            get(get_security_group).delete(delete_security_group),
        )
        .route(
            "/v1/floating-ips",
            get(list_floating_ips).post(allocate_floating_ip),
        )
        .route(
            "/v1/floating-ips/:id",
            get(get_floating_ip).delete(release_floating_ip),
        )
        .route(
            "/v1/floating-ips/:id/associate",
            post(associate_floating_ip),
        )
        .route(
            "/v1/floating-ips/:id/disassociate",
            post(disassociate_floating_ip),
        )
        .with_state(state)
}

// ---------------------------------------------------------------------------
// Error envelope
// ---------------------------------------------------------------------------

/// The consistent error envelope for every failed request: an HTTP status plus a
/// human-readable message, serialized as `{"status": <u16>, "message": "…"}`.
#[derive(Debug, Serialize)]
pub struct ApiError {
    #[serde(skip)]
    status: StatusCode,
    /// The numeric HTTP status, mirrored into the body for clients that only
    /// read JSON. Serialized as `status`.
    #[serde(rename = "status")]
    status_code: u16,
    message: String,
}

impl ApiError {
    fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            status_code: status.as_u16(),
            message: message.into(),
        }
    }
    fn forbidden(m: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, m)
    }
    fn not_found(m: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, m)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(self)).into_response()
    }
}

/// Map a gRPC-path [`tonic::Status`] (from `propose`) onto an HTTP error, so the
/// REST surface reports the same failure classes as the gRPC one.
fn status_to_api(s: tonic::Status) -> ApiError {
    use tonic::Code;
    let http = match s.code() {
        Code::PermissionDenied => StatusCode::FORBIDDEN,
        Code::InvalidArgument => StatusCode::BAD_REQUEST,
        Code::NotFound => StatusCode::NOT_FOUND,
        Code::FailedPrecondition | Code::AlreadyExists => StatusCode::CONFLICT,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    ApiError::new(http, s.message().to_string())
}

// ---------------------------------------------------------------------------
// JSON DTOs (response + request shapes, derived from the model)
// ---------------------------------------------------------------------------

fn action_name_str(a: ActionName) -> &'static str {
    match a {
        ActionName::Pass => "pass",
        ActionName::Drop => "drop",
        ActionName::Reject => "reject",
    }
}

fn proto_name_str(p: ProtoName) -> &'static str {
    match p {
        ProtoName::Tcp => "tcp",
        ProtoName::Udp => "udp",
        ProtoName::Icmp => "icmp",
    }
}

fn parse_action(s: &str) -> Result<Action, ApiError> {
    match s {
        "pass" => Ok(Action::Pass),
        "drop" => Ok(Action::Drop),
        other => Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            format!("unknown action {other:?} (use pass or drop)"),
        )),
    }
}

fn parse_proto(s: &str) -> Result<Proto, ApiError> {
    match s {
        "tcp" => Ok(Proto::Tcp),
        "udp" => Ok(Proto::Udp),
        "icmp" => Ok(Proto::Icmp),
        other => Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            format!("unknown proto {other:?} (use tcp/udp/icmp)"),
        )),
    }
}

fn encap_name_str(e: EncapName) -> &'static str {
    match e {
        EncapName::Vxlan => "vxlan",
        EncapName::Geneve => "geneve",
    }
}

fn parse_encap(s: &str) -> Result<Encap, ApiError> {
    match s {
        "vxlan" => Ok(Encap::Vxlan),
        "geneve" => Ok(Encap::Geneve),
        other => Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            format!("unknown encap {other:?} (use vxlan or geneve)"),
        )),
    }
}

#[derive(Debug, Serialize)]
struct HostJson {
    id: String,
    vtep: String,
    underlay_iface: String,
    underlay_mac: String,
    encap: String,
    udp_port: u16,
    underlay_mtu: u16,
}

impl From<&Host> for HostJson {
    fn from(h: &Host) -> Self {
        Self {
            id: h.id.clone(),
            vtep: h.vtep_ip.to_string(),
            underlay_iface: h.underlay_iface.clone(),
            underlay_mac: crate::fmt_mac(h.underlay_mac),
            encap: encap_name_str(h.encap).to_string(),
            udp_port: h.udp_port.unwrap_or(0),
            underlay_mtu: h.underlay_mtu.unwrap_or(0),
        }
    }
}

#[derive(Debug, Deserialize)]
struct CreateHostReq {
    id: String,
    vtep: String,
    underlay_iface: String,
    underlay_mac: String,
    #[serde(default)]
    encap: Option<String>,
    #[serde(default)]
    udp_port: u32,
    #[serde(default)]
    underlay_mtu: u32,
}

#[derive(Debug, Serialize)]
struct NetworkJson {
    vni: u32,
    name: String,
    subnet: String,
    default_action: String,
    drop_icmp: bool,
}

impl From<&Network> for NetworkJson {
    fn from(n: &Network) -> Self {
        Self {
            vni: n.vni,
            name: n.name.clone(),
            subnet: n.subnet.to_string(),
            default_action: action_name_str(n.default_action).to_string(),
            drop_icmp: n.drop_icmp,
        }
    }
}

#[derive(Debug, Deserialize)]
struct CreateNetworkReq {
    vni: u32,
    name: String,
    subnet: String,
    #[serde(default)]
    default_action: Option<String>,
    #[serde(default)]
    drop_icmp: bool,
}

#[derive(Debug, Serialize)]
struct PortJson {
    id: String,
    vni: u32,
    host: String,
    ip: String,
    mac: String,
    tap: String,
}

impl From<&Port> for PortJson {
    fn from(p: &Port) -> Self {
        let info = crate::port_to_info(p);
        Self {
            id: info.id,
            vni: info.vni,
            host: info.host,
            ip: info.ip,
            mac: info.mac,
            tap: info.tap,
        }
    }
}

impl From<velstra_raft::PortRecord> for PortJson {
    fn from(p: velstra_raft::PortRecord) -> Self {
        Self {
            id: p.id,
            vni: p.vni,
            host: p.host,
            ip: p.ip,
            mac: p.mac,
            tap: p.tap,
        }
    }
}

#[derive(Debug, Deserialize)]
struct CreatePortReq {
    /// The network VNI to place the port in.
    network: u32,
    host: String,
    tap: String,
    #[serde(default)]
    ip: Option<String>,
    #[serde(default)]
    policy: Option<u32>,
}

#[derive(Debug, Serialize)]
struct SubnetJson {
    id: String,
    vni: u32,
    cidr: String,
    gateway: String,
    pool_start: String,
    pool_end: String,
    enable_dhcp: bool,
}

impl From<&Subnet> for SubnetJson {
    fn from(s: &Subnet) -> Self {
        let (pool_start, pool_end) = match s.pool {
            Some(r) => (r.start.to_string(), r.end.to_string()),
            None => (String::new(), String::new()),
        };
        Self {
            id: s.id.clone(),
            vni: s.vni,
            cidr: crate::subnet_cidr_to_string(&s.cidr),
            gateway: s.gateway.map(|g| g.to_string()).unwrap_or_default(),
            pool_start,
            pool_end,
            enable_dhcp: s.enable_dhcp,
        }
    }
}

#[derive(Debug, Deserialize)]
struct CreateSubnetReq {
    id: String,
    vni: u32,
    cidr: String,
    #[serde(default)]
    gateway: Option<String>,
    #[serde(default)]
    pool_start: Option<String>,
    #[serde(default)]
    pool_end: Option<String>,
    #[serde(default)]
    enable_dhcp: bool,
}

#[derive(Debug, Serialize)]
struct RuleJson {
    proto: String,
    port: u16,
    action: String,
    log: bool,
    src: String,
}

#[derive(Debug, Serialize)]
struct SecurityGroupJson {
    name: String,
    policy_id: u32,
    default_action: String,
    drop_icmp: bool,
    stateful: bool,
    blocklist: Vec<String>,
    rules: Vec<RuleJson>,
}

impl From<&SecurityGroup> for SecurityGroupJson {
    fn from(g: &SecurityGroup) -> Self {
        Self {
            name: g.name.clone(),
            policy_id: g.policy_id(),
            default_action: action_name_str(g.default_action).to_string(),
            drop_icmp: g.drop_icmp,
            stateful: g.stateful,
            blocklist: g.blocklist.clone(),
            rules: g
                .rules
                .iter()
                .map(|r| RuleJson {
                    proto: proto_name_str(r.proto).to_string(),
                    port: r.port,
                    action: action_name_str(r.action).to_string(),
                    log: r.log,
                    src: r.src.clone().unwrap_or_default(),
                })
                .collect(),
        }
    }
}

#[derive(Debug, Deserialize)]
struct RuleReq {
    proto: String,
    port: u16,
    action: String,
    #[serde(default)]
    log: bool,
    #[serde(default)]
    src: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CreateSecurityGroupReq {
    name: String,
    #[serde(default)]
    default_action: Option<String>,
    #[serde(default)]
    drop_icmp: bool,
    #[serde(default)]
    stateful: bool,
    #[serde(default)]
    blocklist: Vec<String>,
    #[serde(default)]
    rules: Vec<RuleReq>,
}

#[derive(Debug, Serialize)]
struct FloatingIpJson {
    id: String,
    vni: u32,
    subnet_id: String,
    addr: String,
    assoc_port: String,
    assoc_fixed: String,
}

impl From<&FloatingIp> for FloatingIpJson {
    fn from(f: &FloatingIp) -> Self {
        Self {
            id: f.id.clone(),
            vni: f.vni,
            subnet_id: f.subnet_id.clone(),
            addr: f.addr.to_string(),
            assoc_port: f
                .association
                .as_ref()
                .map(|a| a.port_id.clone())
                .unwrap_or_default(),
            assoc_fixed: f
                .association
                .as_ref()
                .map(|a| a.fixed_addr.to_string())
                .unwrap_or_default(),
        }
    }
}

impl From<velstra_raft::FloatingIpRecord> for FloatingIpJson {
    fn from(r: velstra_raft::FloatingIpRecord) -> Self {
        Self {
            id: r.id,
            vni: r.vni,
            subnet_id: r.subnet_id,
            addr: r.addr,
            assoc_port: r.assoc_port.unwrap_or_default(),
            assoc_fixed: r.assoc_fixed.unwrap_or_default(),
        }
    }
}

#[derive(Debug, Deserialize)]
struct AllocFloatingIpReq {
    subnet_id: String,
    #[serde(default)]
    ip: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AssociateFloatingIpReq {
    port_id: String,
    fixed_addr: String,
}

/// `{"deleted": <bool>}` — the response body for a successful DELETE.
#[derive(Debug, Serialize)]
struct DeletedJson {
    deleted: bool,
}

#[derive(Debug, Deserialize)]
struct AuditQuery {
    #[serde(default)]
    limit: Option<usize>,
}

// ---------------------------------------------------------------------------
// Topology read helpers (mirror the gRPC list handlers: Raft in cluster mode,
// the local model otherwise)
// ---------------------------------------------------------------------------

macro_rules! read_collection {
    ($shared:expr, $method:ident, $ty:ty) => {{
        if let Some(raft) = &$shared.raft {
            raft.topology()
                .await
                .$method()
                .map(<$ty>::from)
                .collect::<Vec<_>>()
        } else {
            $shared
                .topology
                .read()
                .await
                .$method()
                .map(<$ty>::from)
                .collect::<Vec<_>>()
        }
    }};
}

async fn read_hosts(shared: &Shared) -> Vec<HostJson> {
    read_collection!(shared, hosts, HostJson)
}

async fn read_networks(shared: &Shared) -> Vec<NetworkJson> {
    read_collection!(shared, networks, NetworkJson)
}

async fn read_subnets(shared: &Shared) -> Vec<SubnetJson> {
    read_collection!(shared, subnets, SubnetJson)
}

async fn read_security_groups(shared: &Shared) -> Vec<SecurityGroupJson> {
    read_collection!(shared, security_groups, SecurityGroupJson)
}

async fn read_floating_ips(shared: &Shared) -> Vec<FloatingIpJson> {
    read_collection!(shared, floating_ips, FloatingIpJson)
}

async fn read_ports(shared: &Shared) -> Vec<PortJson> {
    // `ports()` returns a slice, not an iterator, so it needs its own read.
    if let Some(raft) = &shared.raft {
        raft.topology()
            .await
            .ports()
            .iter()
            .map(PortJson::from)
            .collect()
    } else {
        shared
            .topology
            .read()
            .await
            .ports()
            .iter()
            .map(PortJson::from)
            .collect()
    }
}

/// Run a mutation through the shared controller path and audit the outcome.
/// `notok` is the HTTP status used when the state machine rejects the request
/// (`resp.ok == false`) — `400` for invalid input, `409` for a precondition.
async fn propose_audited(
    state: &RestState,
    actor: &str,
    operation: &str,
    target: &str,
    req: velstra_raft::TopoRequest,
    notok: StatusCode,
) -> Result<velstra_raft::TopoResponse, ApiError> {
    match propose(&state.shared, req).await {
        Ok(resp) if resp.ok => {
            state.audit.record(actor, operation, target, "ok");
            Ok(resp)
        }
        Ok(resp) => {
            let message = resp.error.unwrap_or_else(|| "rejected".to_string());
            state
                .audit
                .record(actor, operation, target, &format!("error: {message}"));
            Err(ApiError::new(notok, message))
        }
        Err(status) => {
            let err = status_to_api(status);
            state
                .audit
                .record(actor, operation, target, &format!("error: {}", err.message));
            Err(err)
        }
    }
}

// ---------------------------------------------------------------------------
// Probe + audit handlers
// ---------------------------------------------------------------------------

async fn healthz() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "ok" }))
}

async fn version() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "name": "velstra-controller",
        "version": env!("CARGO_PKG_VERSION"),
        "api": "v1",
    }))
}

async fn list_audit(
    State(state): State<Arc<RestState>>,
    Query(q): Query<AuditQuery>,
) -> Json<Vec<AuditEntry>> {
    Json(state.audit.recent(q.limit))
}

// ---------------------------------------------------------------------------
// Hosts (VTEPs)
// ---------------------------------------------------------------------------

async fn list_hosts(State(state): State<Arc<RestState>>) -> Json<Vec<HostJson>> {
    Json(read_hosts(&state.shared).await)
}

async fn get_host(
    State(state): State<Arc<RestState>>,
    Path(id): Path<String>,
) -> Result<Json<HostJson>, ApiError> {
    read_hosts(&state.shared)
        .await
        .into_iter()
        .find(|h| h.id == id)
        .map(Json)
        .ok_or_else(|| ApiError::not_found(format!("no host with id {id:?}")))
}

async fn create_host(
    State(state): State<Arc<RestState>>,
    headers: HeaderMap,
    Json(body): Json<CreateHostReq>,
) -> Result<(StatusCode, Json<HostJson>), ApiError> {
    let caller = state.caller(&headers);
    let actor = actor_of(&caller);
    let id = body.id.clone();
    // Registering/updating a host is a write scoped to that host id (the VTEP-
    // impersonation vector), so a node may only (re)register itself — mirrors
    // the gRPC `add_host` host-scoped authz.
    if !state.authz.allow_host(&caller, &id) {
        state.audit.record(&actor, "host.create", &id, "denied");
        return Err(ApiError::forbidden(format!(
            "add/update host {id:?} (host-scoped)"
        )));
    }
    let spec = velstra_proto::HostSpec {
        id: body.id,
        vtep: body.vtep,
        underlay_iface: body.underlay_iface,
        underlay_mac: body.underlay_mac,
        encap: parse_encap(body.encap.as_deref().unwrap_or("vxlan"))? as i32,
        udp_port: body.udp_port,
        underlay_mtu: body.underlay_mtu,
    };
    propose_audited(
        &state,
        &actor,
        "host.create",
        &id,
        velstra_raft::TopoRequest::AddHost(raft_host_spec(spec)),
        StatusCode::BAD_REQUEST,
    )
    .await?;
    let created = get_host(State(state), Path(id)).await?;
    Ok((StatusCode::CREATED, created))
}

async fn delete_host(
    State(state): State<Arc<RestState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<DeletedJson>, ApiError> {
    let caller = state.caller(&headers);
    let actor = actor_of(&caller);
    if !state.authz.allow_host(&caller, &id) {
        state.audit.record(&actor, "host.delete", &id, "denied");
        return Err(ApiError::forbidden(format!(
            "remove host {id:?} (host-scoped)"
        )));
    }
    propose_audited(
        &state,
        &actor,
        "host.delete",
        &id,
        velstra_raft::TopoRequest::RemoveHost { id: id.clone() },
        StatusCode::CONFLICT,
    )
    .await?;
    Ok(Json(DeletedJson { deleted: true }))
}

// ---------------------------------------------------------------------------
// Networks
// ---------------------------------------------------------------------------

async fn list_networks(State(state): State<Arc<RestState>>) -> Json<Vec<NetworkJson>> {
    Json(read_networks(&state.shared).await)
}

async fn get_network(
    State(state): State<Arc<RestState>>,
    Path(vni): Path<u32>,
) -> Result<Json<NetworkJson>, ApiError> {
    read_networks(&state.shared)
        .await
        .into_iter()
        .find(|n| n.vni == vni)
        .map(Json)
        .ok_or_else(|| ApiError::not_found(format!("no network with vni {vni}")))
}

async fn create_network(
    State(state): State<Arc<RestState>>,
    headers: HeaderMap,
    Json(body): Json<CreateNetworkReq>,
) -> Result<(StatusCode, Json<NetworkJson>), ApiError> {
    let caller = state.caller(&headers);
    let actor = actor_of(&caller);
    let target = format!("vni={}", body.vni);
    if !state.authz.allow_admin(&caller) {
        state
            .audit
            .record(&actor, "network.create", &target, "denied");
        return Err(ApiError::forbidden("define networks (admin only)"));
    }
    let default_action = parse_action(body.default_action.as_deref().unwrap_or("pass"))? as i32;
    let spec = velstra_proto::NetworkSpec {
        vni: body.vni,
        name: body.name,
        subnet: body.subnet,
        default_action,
        drop_icmp: body.drop_icmp,
    };
    propose_audited(
        &state,
        &actor,
        "network.create",
        &target,
        velstra_raft::TopoRequest::AddNetwork(raft_network_spec(spec)),
        StatusCode::BAD_REQUEST,
    )
    .await?;
    let created = get_network(State(state), Path(body.vni)).await?;
    Ok((StatusCode::CREATED, created))
}

async fn delete_network(
    State(state): State<Arc<RestState>>,
    headers: HeaderMap,
    Path(vni): Path<u32>,
) -> Result<Json<DeletedJson>, ApiError> {
    let caller = state.caller(&headers);
    let actor = actor_of(&caller);
    let target = format!("vni={vni}");
    if !state.authz.allow_admin(&caller) {
        state
            .audit
            .record(&actor, "network.delete", &target, "denied");
        return Err(ApiError::forbidden("remove networks (admin only)"));
    }
    propose_audited(
        &state,
        &actor,
        "network.delete",
        &target,
        velstra_raft::TopoRequest::RemoveNetwork { vni },
        StatusCode::CONFLICT,
    )
    .await?;
    Ok(Json(DeletedJson { deleted: true }))
}

// ---------------------------------------------------------------------------
// Ports
// ---------------------------------------------------------------------------

async fn list_ports(State(state): State<Arc<RestState>>) -> Json<Vec<PortJson>> {
    Json(read_ports(&state.shared).await)
}

async fn get_port(
    State(state): State<Arc<RestState>>,
    Path(id): Path<String>,
) -> Result<Json<PortJson>, ApiError> {
    read_ports(&state.shared)
        .await
        .into_iter()
        .find(|p| p.id == id)
        .map(Json)
        .ok_or_else(|| ApiError::not_found(format!("no port with id {id:?}")))
}

async fn create_port(
    State(state): State<Arc<RestState>>,
    headers: HeaderMap,
    Json(body): Json<CreatePortReq>,
) -> Result<(StatusCode, Json<PortJson>), ApiError> {
    let caller = state.caller(&headers);
    let actor = actor_of(&caller);
    let target = format!("host={} vni={}", body.host, body.network);
    // Creating a port lands a tap on a host — a node may only place ports on
    // itself (mirrors the gRPC `create_port` host-scoped authz).
    if !state.authz.allow_host(&caller, &body.host) {
        state.audit.record(&actor, "port.create", &target, "denied");
        return Err(ApiError::forbidden(format!(
            "create ports on host {:?} (host-scoped)",
            body.host
        )));
    }
    let resp = propose_audited(
        &state,
        &actor,
        "port.create",
        &target,
        velstra_raft::TopoRequest::CreatePort {
            vni: body.network,
            host: body.host,
            tap: body.tap,
            ip: body.ip.filter(|s| !s.is_empty()),
            policy: body.policy,
        },
        StatusCode::BAD_REQUEST,
    )
    .await?;
    let port = resp
        .port
        .ok_or_else(|| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "no port returned"))?;
    Ok((StatusCode::CREATED, Json(PortJson::from(port))))
}

async fn delete_port(
    State(state): State<Arc<RestState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<DeletedJson>, ApiError> {
    let caller = state.caller(&headers);
    let actor = actor_of(&caller);
    // A port id doesn't name its owning host, so removal is admin-only (mirrors
    // the gRPC `remove_port`).
    if !state.authz.allow_admin(&caller) {
        state.audit.record(&actor, "port.delete", &id, "denied");
        return Err(ApiError::forbidden("remove ports (admin only)"));
    }
    let resp = propose_audited(
        &state,
        &actor,
        "port.delete",
        &id,
        velstra_raft::TopoRequest::RemovePort { id: id.clone() },
        StatusCode::CONFLICT,
    )
    .await?;
    Ok(Json(DeletedJson { deleted: resp.ok }))
}

// ---------------------------------------------------------------------------
// Subnets
// ---------------------------------------------------------------------------

async fn list_subnets(State(state): State<Arc<RestState>>) -> Json<Vec<SubnetJson>> {
    Json(read_subnets(&state.shared).await)
}

async fn get_subnet(
    State(state): State<Arc<RestState>>,
    Path(id): Path<String>,
) -> Result<Json<SubnetJson>, ApiError> {
    read_subnets(&state.shared)
        .await
        .into_iter()
        .find(|s| s.id == id)
        .map(Json)
        .ok_or_else(|| ApiError::not_found(format!("no subnet with id {id:?}")))
}

async fn create_subnet(
    State(state): State<Arc<RestState>>,
    headers: HeaderMap,
    Json(body): Json<CreateSubnetReq>,
) -> Result<(StatusCode, Json<SubnetJson>), ApiError> {
    let caller = state.caller(&headers);
    let actor = actor_of(&caller);
    let id = body.id.clone();
    if !state.authz.allow_admin(&caller) {
        state.audit.record(&actor, "subnet.create", &id, "denied");
        return Err(ApiError::forbidden("define subnets (admin only)"));
    }
    let spec = velstra_proto::SubnetSpec {
        id: body.id,
        vni: body.vni,
        cidr: body.cidr,
        gateway: body.gateway.unwrap_or_default(),
        pool_start: body.pool_start.unwrap_or_default(),
        pool_end: body.pool_end.unwrap_or_default(),
        enable_dhcp: body.enable_dhcp,
    };
    propose_audited(
        &state,
        &actor,
        "subnet.create",
        &id,
        velstra_raft::TopoRequest::AddSubnet(raft_subnet_spec(spec)),
        StatusCode::BAD_REQUEST,
    )
    .await?;
    let created = get_subnet(State(state), Path(id)).await?;
    Ok((StatusCode::CREATED, created))
}

async fn delete_subnet(
    State(state): State<Arc<RestState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<DeletedJson>, ApiError> {
    let caller = state.caller(&headers);
    let actor = actor_of(&caller);
    if !state.authz.allow_admin(&caller) {
        state.audit.record(&actor, "subnet.delete", &id, "denied");
        return Err(ApiError::forbidden("remove subnets (admin only)"));
    }
    propose_audited(
        &state,
        &actor,
        "subnet.delete",
        &id,
        velstra_raft::TopoRequest::RemoveSubnet { id: id.clone() },
        StatusCode::CONFLICT,
    )
    .await?;
    Ok(Json(DeletedJson { deleted: true }))
}

// ---------------------------------------------------------------------------
// Security groups
// ---------------------------------------------------------------------------

async fn list_security_groups(State(state): State<Arc<RestState>>) -> Json<Vec<SecurityGroupJson>> {
    Json(read_security_groups(&state.shared).await)
}

async fn get_security_group(
    State(state): State<Arc<RestState>>,
    Path(name): Path<String>,
) -> Result<Json<SecurityGroupJson>, ApiError> {
    read_security_groups(&state.shared)
        .await
        .into_iter()
        .find(|g| g.name == name)
        .map(Json)
        .ok_or_else(|| ApiError::not_found(format!("no security group named {name:?}")))
}

async fn create_security_group(
    State(state): State<Arc<RestState>>,
    headers: HeaderMap,
    Json(body): Json<CreateSecurityGroupReq>,
) -> Result<(StatusCode, Json<SecurityGroupJson>), ApiError> {
    let caller = state.caller(&headers);
    let actor = actor_of(&caller);
    let name = body.name.clone();
    if !state.authz.allow_admin(&caller) {
        state
            .audit
            .record(&actor, "security-group.create", &name, "denied");
        return Err(ApiError::forbidden("define security groups (admin only)"));
    }
    let default_action = parse_action(body.default_action.as_deref().unwrap_or("pass"))? as i32;
    let mut rules = Vec::with_capacity(body.rules.len());
    for r in &body.rules {
        rules.push(PortRule {
            proto: parse_proto(&r.proto)? as i32,
            port: r.port as u32,
            action: parse_action(&r.action)? as i32,
            log: r.log,
            src: r.src.clone().unwrap_or_default(),
        });
    }
    let spec = ProtoSgSpec {
        name: body.name,
        default_action,
        drop_icmp: body.drop_icmp,
        stateful: body.stateful,
        blocklist: body.blocklist,
        rules,
    };
    propose_audited(
        &state,
        &actor,
        "security-group.create",
        &name,
        velstra_raft::TopoRequest::AddSecurityGroup(raft_security_group_spec(spec)),
        StatusCode::BAD_REQUEST,
    )
    .await?;
    let created = get_security_group(State(state), Path(name)).await?;
    Ok((StatusCode::CREATED, created))
}

async fn delete_security_group(
    State(state): State<Arc<RestState>>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> Result<Json<DeletedJson>, ApiError> {
    let caller = state.caller(&headers);
    let actor = actor_of(&caller);
    if !state.authz.allow_admin(&caller) {
        state
            .audit
            .record(&actor, "security-group.delete", &name, "denied");
        return Err(ApiError::forbidden("remove security groups (admin only)"));
    }
    propose_audited(
        &state,
        &actor,
        "security-group.delete",
        &name,
        velstra_raft::TopoRequest::RemoveSecurityGroup { name: name.clone() },
        StatusCode::CONFLICT,
    )
    .await?;
    Ok(Json(DeletedJson { deleted: true }))
}

// ---------------------------------------------------------------------------
// Floating IPs
// ---------------------------------------------------------------------------

async fn list_floating_ips(State(state): State<Arc<RestState>>) -> Json<Vec<FloatingIpJson>> {
    Json(read_floating_ips(&state.shared).await)
}

async fn get_floating_ip(
    State(state): State<Arc<RestState>>,
    Path(id): Path<String>,
) -> Result<Json<FloatingIpJson>, ApiError> {
    read_floating_ips(&state.shared)
        .await
        .into_iter()
        .find(|f| f.id == id)
        .map(Json)
        .ok_or_else(|| ApiError::not_found(format!("no floating ip with id {id:?}")))
}

async fn allocate_floating_ip(
    State(state): State<Arc<RestState>>,
    headers: HeaderMap,
    Json(body): Json<AllocFloatingIpReq>,
) -> Result<(StatusCode, Json<FloatingIpJson>), ApiError> {
    let caller = state.caller(&headers);
    let actor = actor_of(&caller);
    let target = format!("subnet={}", body.subnet_id);
    if !state.authz.allow_admin(&caller) {
        state
            .audit
            .record(&actor, "floating-ip.allocate", &target, "denied");
        return Err(ApiError::forbidden("allocate floating ips (admin only)"));
    }
    let resp = propose_audited(
        &state,
        &actor,
        "floating-ip.allocate",
        &target,
        velstra_raft::TopoRequest::AllocateFloatingIp {
            subnet_id: body.subnet_id,
            ip: body.ip.filter(|s| !s.is_empty()),
        },
        StatusCode::BAD_REQUEST,
    )
    .await?;
    let f = resp
        .floating
        .ok_or_else(|| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "no floating ip"))?;
    Ok((StatusCode::CREATED, Json(FloatingIpJson::from(f))))
}

async fn associate_floating_ip(
    State(state): State<Arc<RestState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<AssociateFloatingIpReq>,
) -> Result<Json<FloatingIpJson>, ApiError> {
    let caller = state.caller(&headers);
    let actor = actor_of(&caller);
    if !state.authz.allow_admin(&caller) {
        state
            .audit
            .record(&actor, "floating-ip.associate", &id, "denied");
        return Err(ApiError::forbidden("associate floating ips (admin only)"));
    }
    let resp = propose_audited(
        &state,
        &actor,
        "floating-ip.associate",
        &id,
        velstra_raft::TopoRequest::AssociateFloatingIp {
            id: id.clone(),
            port_id: body.port_id,
            fixed_addr: body.fixed_addr,
        },
        StatusCode::BAD_REQUEST,
    )
    .await?;
    let f = resp
        .floating
        .ok_or_else(|| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "no floating ip"))?;
    Ok(Json(FloatingIpJson::from(f)))
}

async fn disassociate_floating_ip(
    State(state): State<Arc<RestState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<FloatingIpJson>, ApiError> {
    let caller = state.caller(&headers);
    let actor = actor_of(&caller);
    if !state.authz.allow_admin(&caller) {
        state
            .audit
            .record(&actor, "floating-ip.disassociate", &id, "denied");
        return Err(ApiError::forbidden(
            "disassociate floating ips (admin only)",
        ));
    }
    let resp = propose_audited(
        &state,
        &actor,
        "floating-ip.disassociate",
        &id,
        velstra_raft::TopoRequest::DisassociateFloatingIp { id: id.clone() },
        StatusCode::BAD_REQUEST,
    )
    .await?;
    let f = resp
        .floating
        .ok_or_else(|| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "no floating ip"))?;
    Ok(Json(FloatingIpJson::from(f)))
}

async fn release_floating_ip(
    State(state): State<Arc<RestState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<DeletedJson>, ApiError> {
    let caller = state.caller(&headers);
    let actor = actor_of(&caller);
    if !state.authz.allow_admin(&caller) {
        state
            .audit
            .record(&actor, "floating-ip.release", &id, "denied");
        return Err(ApiError::forbidden("release floating ips (admin only)"));
    }
    propose_audited(
        &state,
        &actor,
        "floating-ip.release",
        &id,
        velstra_raft::TopoRequest::ReleaseFloatingIp { id: id.clone() },
        StatusCode::CONFLICT,
    )
    .await?;
    Ok(Json(DeletedJson { deleted: true }))
}
