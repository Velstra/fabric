//! CNI (Container Network Interface) wire types: the network config the runtime
//! passes on stdin, and the result/error we print back. See the CNI spec:
//! <https://github.com/containernetworking/cni/blob/main/SPEC.md>.

use serde::{Deserialize, Serialize};

/// The CNI versions this plugin understands.
pub const SUPPORTED_VERSIONS: &[&str] = &["0.3.1", "0.4.0", "1.0.0"];

/// Network configuration passed by the runtime on stdin. Unknown fields (e.g.
/// `prevResult`, `runtimeConfig`) are ignored.
///
/// Two modes:
/// * **standalone** — no `controllers`; the plugin's own host-local IPAM
///   allocates from `subnet`.
/// * **controller-integrated** — `controllers` set; the controller (Raft leader)
///   allocates the IP/MAC via `CreatePort` and pushes the node's agent an
///   interface binding that attaches the XDP firewall/LB. `subnet` is still used
///   for the pod's prefix + default gateway.
#[derive(Debug, Deserialize)]
pub struct NetConf {
    #[serde(rename = "cniVersion")]
    pub cni_version: String,
    pub name: String,
    /// The plugin binary name; part of the CNI schema but not used at runtime.
    #[serde(rename = "type")]
    #[allow(dead_code)]
    pub plugin_type: String,

    /// Pod subnet, e.g. `"10.244.0.0/16"`. In standalone mode IPAM allocates
    /// from it; in controller mode it sets the pod's prefix + default gateway.
    pub subnet: Option<String>,
    /// Gateway address; defaults to the first usable address of `subnet`.
    pub gateway: Option<String>,

    // --- Controller-integrated mode (Velstra extensions) --------------------
    /// Orchestrator endpoints, e.g. `["https://10.0.0.1:50052"]`. Non-empty
    /// selects controller mode. Tried in order until the leader accepts.
    #[serde(default)]
    pub controllers: Vec<String>,
    /// The network (VNI) this plugin attaches pods to. Required in controller
    /// mode (the controller's network must already exist).
    pub vni: Option<u32>,
    /// This node's host id (matches the agent's `--node-id`). If unset, read
    /// from `node_file`, then the system hostname.
    pub node: Option<String>,
    /// Path to read the node id from when `node` is unset.
    #[serde(rename = "nodeFile")]
    pub node_file: Option<String>,

    /// PEM CA certificate verifying the controller (enables TLS).
    #[serde(rename = "tlsCA")]
    pub tls_ca: Option<String>,
    /// Client certificate + key for mutual TLS (both or neither).
    #[serde(rename = "tlsCert")]
    pub tls_cert: Option<String>,
    #[serde(rename = "tlsKey")]
    pub tls_key: Option<String>,
    /// Server name to validate against the controller's certificate.
    #[serde(rename = "tlsDomain")]
    pub tls_domain: Option<String>,
}

impl NetConf {
    /// TLS options for the controller channel, if a CA was supplied.
    pub fn tls_options(&self) -> Option<crate::controller::TlsOptions> {
        self.tls_ca
            .as_ref()
            .map(|ca| crate::controller::TlsOptions {
                ca: ca.into(),
                client_cert: self.tls_cert.as_ref().map(Into::into),
                client_key: self.tls_key.as_ref().map(Into::into),
                domain: self.tls_domain.clone(),
            })
    }
}

/// A successful ADD result (CNI `Result`).
#[derive(Debug, Serialize)]
pub struct CniResult {
    #[serde(rename = "cniVersion")]
    pub cni_version: String,
    pub interfaces: Vec<Interface>,
    pub ips: Vec<IpConfig>,
    pub routes: Vec<Route>,
    pub dns: Dns,
}

#[derive(Debug, Serialize)]
pub struct Interface {
    pub name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub mac: String,
    pub sandbox: String,
}

#[derive(Debug, Serialize)]
pub struct IpConfig {
    pub address: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gateway: Option<String>,
    pub interface: usize,
}

#[derive(Debug, Serialize)]
pub struct Route {
    pub dst: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gw: Option<String>,
}

#[derive(Debug, Serialize, Default)]
pub struct Dns {}

/// A CNI error object, printed to stdout with a non-zero exit on failure.
#[derive(Debug, Serialize)]
pub struct CniError {
    #[serde(rename = "cniVersion")]
    pub cni_version: String,
    pub code: u32,
    pub msg: String,
}

impl CniError {
    /// Generic plugin error (CNI error code 7 = "try again later" is reserved;
    /// 100+ are plugin-specific — we use 100).
    pub fn new(cni_version: &str, msg: impl Into<String>) -> Self {
        Self {
            cni_version: cni_version.to_string(),
            code: 100,
            msg: msg.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_netconf_ignoring_unknown_fields() {
        let json = r#"{
            "cniVersion": "1.0.0",
            "name": "velstra",
            "type": "velstra-cni",
            "subnet": "10.244.0.0/16",
            "prevResult": {"whatever": true},
            "runtimeConfig": {"x": 1}
        }"#;
        let conf: NetConf = serde_json::from_str(json).unwrap();
        assert_eq!(conf.name, "velstra");
        assert_eq!(conf.subnet.as_deref(), Some("10.244.0.0/16"));
        assert_eq!(conf.gateway, None);
        // Standalone config: no controllers, no VNI.
        assert!(conf.controllers.is_empty());
        assert_eq!(conf.vni, None);
        assert!(conf.tls_options().is_none());
    }

    #[test]
    fn parses_controller_mode_fields() {
        let json = r#"{
            "cniVersion": "1.0.0",
            "name": "blue",
            "type": "velstra-cni",
            "subnet": "192.168.100.0/24",
            "vni": 5000,
            "controllers": ["https://10.0.0.1:50052", "https://10.0.0.2:50052"],
            "node": "node-a",
            "tlsCA": "/etc/velstra/ca.pem"
        }"#;
        let conf: NetConf = serde_json::from_str(json).unwrap();
        assert_eq!(conf.vni, Some(5000));
        assert_eq!(conf.controllers.len(), 2);
        assert_eq!(conf.node.as_deref(), Some("node-a"));
        let tls = conf.tls_options().expect("tls enabled by tlsCA");
        assert_eq!(tls.ca.to_str(), Some("/etc/velstra/ca.pem"));
        assert!(tls.client_cert.is_none());
    }

    #[test]
    fn serializes_result_in_cni_shape() {
        let result = CniResult {
            cni_version: "1.0.0".into(),
            interfaces: vec![Interface {
                name: "eth0".into(),
                mac: String::new(),
                sandbox: "/var/run/netns/cni-1".into(),
            }],
            ips: vec![IpConfig {
                address: "10.244.0.5/16".into(),
                gateway: Some("10.244.0.1".into()),
                interface: 0,
            }],
            routes: vec![Route {
                dst: "0.0.0.0/0".into(),
                gw: None,
            }],
            dns: Dns::default(),
        };
        let v: serde_json::Value = serde_json::to_value(&result).unwrap();
        assert_eq!(v["cniVersion"], "1.0.0");
        assert_eq!(v["ips"][0]["address"], "10.244.0.5/16");
        assert_eq!(v["interfaces"][0]["name"], "eth0");
        // An empty MAC is omitted, not serialized as "".
        assert!(v["interfaces"][0].get("mac").is_none());
    }
}
